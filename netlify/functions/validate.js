// netlify/functions/validate.js
const crypto = require("crypto");

const TOKEN_SECRET = process.env.TOKEN_SECRET || "CAMBIA_ESTE_SECRET";

// ✅ Radio permitido (metros)
const RADIO_PERMITIDO = 200;

// ✅ Tus 5 sedes (las mismas del index.html)
const SEDES = [
  { nombre: "SEDE GAIRA KM7",     lat: 11.18957,  lng: -74.21414 },
  { nombre: "RELLENO SANITARIO", lat: 11.256635, lng: -74.157481 },
  { nombre: "REBOMBEO",          lat: 11.18702,  lng: -74.2173 },
  { nombre: "CAN CLL 22",        lat: 11.23625,  lng: -74.18786 },
  { nombre: "PTAP MAMATOCO",     lat: 11.224788, lng: -74.160243 }
];

function json(statusCode, obj) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store"
    },
    body: JSON.stringify(obj),
  };
}

function haversineMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function validateToken(token) {
  const decoded = Buffer.from(token, "base64url").toString("utf8");
  const [payload, sig] = decoded.split(".");

  const expectedSig = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(payload)
    .digest("hex");

  if (sig !== expectedSig) return { ok: false, reason: "bad_sig" };

  const exp = Number(payload);
  if (!Number.isFinite(exp)) return { ok: false, reason: "bad_payload" };
  if (Date.now() > exp) return { ok: false, reason: "expired" };

  return { ok: true, exp };
}

exports.handler = async (event) => {
  try {
    // 1) token por querystring
    const token = event.queryStringParameters?.token;
    if (!token) return json(200, { ok: false, reason: "missing_token" });

    const t = validateToken(token);
    if (!t.ok) return json(200, { ok: false, reason: t.reason });

    // 2) ubicación viene por POST body JSON
    if (event.httpMethod !== "POST") {
      return json(200, { ok: false, reason: "use_post" });
    }

    let body = {};
    try {
      body = event.body ? JSON.parse(event.body) : {};
    } catch {
      return json(200, { ok: false, reason: "bad_json" });
    }

    // aceptar varios nombres para evitar errores (lng/lon/longitude)
    const lat = Number(body.lat ?? body.latitude);
    const lng = Number(body.lng ?? body.lon ?? body.longitude);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return json(200, { ok: false, reason: "missing_coords" });
    }

    // 3) calcular sede más cercana
    let mejor = null;
    for (const sede of SEDES) {
      const d = haversineMeters(lat, lng, sede.lat, sede.lng);
      if (!mejor || d < mejor.distance_m) {
        mejor = { nombre: sede.nombre, distance_m: d };
      }
    }

    const dentro = mejor.distance_m <= RADIO_PERMITIDO;

    return json(200, {
      ok: dentro,
      sede: mejor.nombre,
      distance_m: Math.round(mejor.distance_m),
      radio_m: RADIO_PERMITIDO
    });

  } catch (e) {
    return json(200, { ok: false, reason: "server_error" });
  }
};

