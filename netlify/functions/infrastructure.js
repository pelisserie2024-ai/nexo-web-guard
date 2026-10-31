'use strict';
/**
 * POST /.netlify/functions/infrastructure
 * Cuerpo: { "url": "https://ejemplo.cl" }
 * Análisis de infraestructura mediante DNS público (sin conectar al sitio).
 */
const { json, parseJsonBody, originAllowed } = require('../lib/http-util');
const rateLimit = require('../lib/rate-limit');
const { validateTarget } = require('../lib/net-guard');
const infra = require('../lib/infra');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Método no permitido. Use POST.' }, { Allow: 'POST' });
  if (!originAllowed(event)) return json(403, { error: 'Origen no permitido.' });

  const body = parseJsonBody(event, 2048);
  if (!body.ok) return json(400, { error: body.error });
  const v = validateTarget(body.data.url);
  if (!v.ok) return json(400, { error: v.error });

  const rl = rateLimit.check('infra:' + rateLimit.clientIp(event), 12, 10 * 60 * 1000);
  if (!rl.ok) return json(429, { error: 'Demasiadas solicitudes. Espere unos minutos.', retryAfter: rl.retryAfter }, { 'Retry-After': String(rl.retryAfter) });

  try {
    return json(200, await infra.run(v.host));
  } catch (e) {
    return json(500, { error: 'Error interno en el análisis de infraestructura.' });
  }
};
