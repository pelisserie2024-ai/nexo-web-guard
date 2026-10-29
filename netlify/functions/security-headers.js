'use strict';
/**
 * POST /.netlify/functions/security-headers
 * Cuerpo: { "url": "https://ejemplo.cl", "authorized": true }
 * Versión ligera: una sola solicitud GET (sin leer el cuerpo) y análisis de las cabeceras de seguridad.
 * Útil para comprobaciones rápidas o integraciones; la interfaz principal usa analyze-site.
 */
const { json, parseJsonBody, originAllowed } = require('../lib/http-util');
const rateLimit = require('../lib/rate-limit');
const { validateTarget } = require('../lib/net-guard');
const { fetchFollow } = require('../lib/safe-fetch');
const { analyzeSecurityHeaders } = require('../lib/headers-analysis');
const { describeError } = require('../lib/analysis');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Método no permitido. Use POST.' }, { Allow: 'POST' });
  if (!originAllowed(event)) return json(403, { error: 'Origen no permitido.' });

  const body = parseJsonBody(event, 2048);
  if (!body.ok) return json(400, { error: body.error });
  if (body.data.authorized !== true) return json(400, { error: 'Debe confirmar que dispone de autorización para analizar el sitio.' });
  const v = validateTarget(body.data.url);
  if (!v.ok) return json(400, { error: v.error });

  const rl = rateLimit.check('headers:' + rateLimit.clientIp(event), 12, 10 * 60 * 1000);
  if (!rl.ok) return json(429, { error: 'Demasiadas solicitudes. Espere unos minutos.', retryAfter: rl.retryAfter }, { 'Retry-After': String(rl.retryAfter) });

  const ctx = { budget: { used: 0, max: 5 }, deadline: Date.now() + 8000 };
  try {
    const r = await fetchFollow(v.url.href, ctx, { readBody: false, maxRedirects: 3, timeoutMs: 6000 });
    const isHttps = r.finalUrl.startsWith('https:');
    return json(200, {
      finalUrl: r.finalUrl,
      httpStatus: r.response.status,
      redirects: r.chain,
      headers: analyzeSecurityHeaders(r.response.headers, { isHttps }),
      checkedAt: new Date().toISOString(),
      limitations: ['Solo se analizaron las cabeceras de la respuesta de la página principal.']
    });
  } catch (e) {
    return json(502, { error: describeError(e) });
  }
};
