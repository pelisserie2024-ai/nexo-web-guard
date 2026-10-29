'use strict';
/**
 * Cliente HTTP seguro (anti-SSRF).
 *  - Valida la URL y TODAS las redirecciones.
 *  - Resuelve DNS una vez, comprueba que todas las IP son públicas y conecta a esa IP fija
 *    (anti DNS-rebinding), manteniendo el nombre de host para SNI y cabecera Host.
 *  - Límite de solicitudes por análisis, tiempo total y tamaño de respuesta.
 *  - Nunca envía cookies ni credenciales.
 */
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { validateTarget, resolvePublicHost } = require('./net-guard');

const USER_AGENT = 'NexoWebGuard/1.0 (analisis defensivo no intrusivo)';
const MAX_DECOMPRESSED = 3 * 1024 * 1024;
const RETRY_CODES = new Set(['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'ETIMEDOUT', 'EADDRNOTAVAIL', 'NWG_TIMEOUT']);

function makeError(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

function isCertError(e) {
  const c = e && e.code;
  return !!c && (String(c).startsWith('ERR_TLS_CERT') || [
    'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_NOT_YET_VALID',
    'CERT_REVOKED', 'HOSTNAME_MISMATCH', 'UNABLE_TO_GET_ISSUER_CERT', 'CERT_UNTRUSTED'
  ].includes(c));
}

function decodeBody(buf, encoding) {
  const enc = String(encoding || '').toLowerCase();
  try {
    if (enc === 'gzip' || enc === 'x-gzip') {
      return zlib.gunzipSync(buf, { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: MAX_DECOMPRESSED });
    }
    if (enc === 'deflate') {
      return zlib.inflateSync(buf, { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: MAX_DECOMPRESSED });
    }
    if (enc === 'br') {
      return zlib.brotliDecompressSync(buf, { maxOutputLength: MAX_DECOMPRESSED });
    }
    if (enc && enc !== 'identity') return Buffer.alloc(0);
    return buf;
  } catch (e) {
    return Buffer.alloc(0);
  }
}

function isTextual(contentType) {
  const ct = String(contentType || '').toLowerCase();
  return !ct || ct.startsWith('text/') || ct.includes('xml') || ct.includes('json') || ct.includes('javascript');
}

function singleRequest(o) {
  return new Promise((resolve, reject) => {
    const isHttps = o.url.protocol === 'https:';
    const lib = isHttps ? https : http;
    let settled = false;
    let tls = null;
    const finish = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(v);
    };
    const options = {
      host: o.url.hostname,
      port: o.url.port || (isHttps ? 443 : 80),
      path: (o.url.pathname || '/') + (o.url.search || ''),
      method: o.method,
      agent: false,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'es,en;q=0.8',
        Connection: 'close'
      },
      // Conexión fijada a la IP validada (evita que un segundo DNS devuelva otra dirección).
      lookup: (hostname, opts, cb) => {
        if (opts && opts.all) cb(null, [{ address: o.ip, family: o.family }]);
        else cb(null, o.ip, o.family);
      }
    };
    if (isHttps) {
      options.servername = o.url.hostname;
      options.rejectUnauthorized = o.strictTls;
    }
    const timer = setTimeout(() => {
      req.destroy(makeError('NWG_TIMEOUT', 'Tiempo de espera agotado.'));
    }, o.timeoutMs);

    const req = lib.request(options, (res) => {
      const status = res.statusCode;
      const headers = res.headers;
      const result = (body, truncated) => ({ status, headers, body, truncated: !!truncated, tls });
      const redirect = status >= 300 && status < 400;
      if (!o.readBody || redirect || o.method === 'HEAD' || !isTextual(headers['content-type'])) {
        res.destroy();
        return finish(resolve, result('', false));
      }
      const chunks = [];
      let size = 0;
      let truncated = false;
      const done = () => {
        const raw = Buffer.concat(chunks);
        const decoded = decodeBody(raw, headers['content-encoding']);
        finish(resolve, result(decoded.toString('utf8'), truncated));
      };
      res.on('data', (c) => {
        size += c.length;
        if (size > o.maxBytes) {
          truncated = true;
          chunks.push(c.subarray(0, Math.max(0, c.length - (size - o.maxBytes))));
          res.destroy();
          return done();
        }
        chunks.push(c);
      });
      res.on('end', done);
      res.on('error', () => { if (!settled) done(); });
      res.on('close', () => { if (!settled) done(); });
    });
    req.on('socket', (sock) => {
      if (isHttps) {
        sock.once('secureConnect', () => {
          try {
            const c = sock.getPeerCertificate() || {};
            tls = {
              authorized: !!sock.authorized,
              authorizationError: sock.authorizationError ? String(sock.authorizationError) : null,
              protocol: sock.getProtocol && sock.getProtocol(),
              cert: {
                subject: c.subject || null,
                issuer: c.issuer || null,
                validFrom: c.valid_from || null,
                validTo: c.valid_to || null,
                subjectAltName: c.subjectaltname || null
              }
            };
          } catch (e) { tls = null; }
        });
      }
    });
    req.on('error', (e) => finish(reject, e));
    req.end();
  });
}

/**
 * Descarga una URL con todas las protecciones.
 * ctx = { budget: { used, max }, deadline: epoch ms }
 */
async function fetchFollow(rawUrl, ctx, opts) {
  const o = opts || {};
  const method = o.method || 'GET';
  const follow = o.follow !== false;
  const maxRedirects = o.maxRedirects === undefined ? 4 : o.maxRedirects;
  const maxBytes = o.maxBytes || 600 * 1024;
  const readBody = o.readBody !== false;
  const chain = [];
  let current = rawUrl;
  let certError = null;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const v = validateTarget(current);
    if (!v.ok) throw makeError('NWG_BLOCKED', hop === 0 ? v.error : 'Redirección bloqueada: ' + v.error);
    const r = await resolvePublicHost(v.host);
    if (!r.ok) throw makeError(r.code || 'NWG_BLOCKED', r.error);

    let resp = null;
    let lastErr = null;
    for (const addr of r.addresses.slice(0, 2)) {
      const attempt = async (strict) => {
        if (ctx.budget.used >= ctx.budget.max) throw makeError('NWG_LIMIT', 'Se alcanzó el límite de solicitudes por análisis.');
        const remaining = ctx.deadline - Date.now();
        if (remaining < 400) throw makeError('NWG_TIMEOUT', 'Se agotó el tiempo máximo del análisis.');
        ctx.budget.used++;
        return singleRequest({
          url: v.url, ip: addr.address, family: addr.family, method, maxBytes, readBody,
          strictTls: strict, timeoutMs: Math.min(o.timeoutMs || 6000, remaining)
        });
      };
      try {
        try {
          resp = await attempt(true);
        } catch (e) {
          if (isCertError(e) && v.url.protocol === 'https:') {
            certError = { code: e.code, message: e.message };
            resp = await attempt(false); // solo para poder analizar el resto; no se envía nada sensible
          } else {
            throw e;
          }
        }
        lastErr = null;
        break;
      } catch (e) {
        lastErr = e;
        if (!RETRY_CODES.has(e.code) || e.code === 'NWG_LIMIT') break;
      }
    }
    if (lastErr) throw lastErr;

    chain.push({ url: v.url.href, status: resp.status });
    const loc = resp.headers.location;
    if (follow && [301, 302, 303, 307, 308].includes(resp.status) && loc) {
      try {
        current = new URL(loc, v.url).href;
      } catch (e) {
        throw makeError('NWG_BLOCKED', 'Redirección con destino no válido.');
      }
      continue;
    }
    return { finalUrl: v.url.href, chain, response: resp, certError };
  }
  throw makeError('NWG_REDIRECTS', 'Demasiadas redirecciones.');
}

module.exports = { fetchFollow, isCertError, makeError, USER_AGENT };
