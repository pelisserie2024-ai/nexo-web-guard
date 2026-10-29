'use strict';
/**
 * POST /.netlify/functions/analyze-site
 * Cuerpo: { "url": "https://ejemplo.cl", "authorized": true }
 * Realiza un análisis NO intrusivo (ver netlify/lib/analysis.js).
 * No registra ni almacena las URL analizadas.
 */
const { json, parseJsonBody, originAllowed } = require('../lib/http-util');
const rateLimit = require('../lib/rate-limit');
const { validateTarget } = require('../lib/net-guard');
const { runAnalysis } = require('../lib/analysis');

const LIMIT = 6; // análisis
const WINDOW_MS = 10 * 60 * 1000; // por 10 minutos y por IP

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Método no permitido. Use POST.' }, { Allow: 'POST' });
  if (!originAllowed(event)) return json(403, { error: 'Origen no permitido.' });

  const body = parseJsonBody(event, 2048);
  if (!body.ok) return json(400, { error: body.error });
  if (body.data.authorized !== true) {
    return json(400, { error: 'Debe confirmar que es propietario del sitio o que dispone de autorización para analizarlo.' });
  }
  const v = validateTarget(body.data.url);
  if (!v.ok) return json(400, { error: v.error });

  const rl = rateLimit.check('analyze:' + rateLimit.clientIp(event), LIMIT, WINDOW_MS);
  if (!rl.ok) {
    return json(429, { error: 'Demasiados análisis seguidos. Espere unos minutos antes de volver a intentarlo.', retryAfter: rl.retryAfter }, { 'Retry-After': String(rl.retryAfter) });
  }

  try {
    const result = await runAnalysis(v.url.href);
    return json(200, result);
  } catch (e) {
    return json(500, { error: 'Error interno durante el análisis. Inténtelo de nuevo.' });
  }
};
