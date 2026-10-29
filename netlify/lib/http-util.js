'use strict';

function json(statusCode, body, extraHeaders) {
  return {
    statusCode,
    headers: Object.assign({
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    }, extraHeaders || {}),
    body: JSON.stringify(body)
  };
}

function parseJsonBody(event, maxBytes) {
  let raw = event.body || '';
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  if (Buffer.byteLength(raw, 'utf8') > (maxBytes || 4096)) return { ok: false, error: 'Solicitud demasiado grande.' };
  try {
    const data = JSON.parse(raw || '{}');
    if (!data || typeof data !== 'object' || Array.isArray(data)) return { ok: false, error: 'Cuerpo JSON no válido.' };
    return { ok: true, data };
  } catch (e) {
    return { ok: false, error: 'Cuerpo JSON no válido.' };
  }
}

/** Bloquea usos desde otros sitios web (navegadores): el Origin debe coincidir con el host. */
function originAllowed(event) {
  const h = event.headers || {};
  const origin = h.origin || h.Origin;
  if (!origin) return true; // llamadas sin navegador (curl): limitadas igualmente por frecuencia
  const host = h['x-forwarded-host'] || h.host || h.Host;
  try {
    return new URL(origin).host === String(host).split(',')[0].trim();
  } catch (e) {
    return false;
  }
}

module.exports = { json, parseJsonBody, originAllowed };
