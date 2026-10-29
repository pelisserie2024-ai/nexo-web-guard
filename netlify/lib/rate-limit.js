'use strict';
/**
 * Límite de frecuencia en memoria (por instancia de función).
 * Es un freno de mejor esfuerzo: en entornos serverless cada instancia tiene su propio contador.
 * Para un límite global estricto habría que usar un almacén compartido (no incluido a propósito:
 * el proyecto no usa bases de datos).
 */
const buckets = new Map();

function check(key, limit, windowMs) {
  const now = Date.now();
  const arr = (buckets.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= limit) {
    buckets.set(key, arr);
    return { ok: false, retryAfter: Math.max(1, Math.ceil((windowMs - (now - arr[0])) / 1000)) };
  }
  arr.push(now);
  buckets.set(key, arr);
  if (buckets.size > 5000) {
    for (const [k, v] of buckets) {
      if (!v.length || now - v[v.length - 1] > windowMs) buckets.delete(k);
    }
  }
  return { ok: true };
}

function clientIp(event) {
  const h = (event && event.headers) || {};
  return h['x-nf-client-connection-ip'] || h['client-ip'] ||
    String(h['x-forwarded-for'] || '').split(',')[0].trim() || 'desconocida';
}

function reset() {
  buckets.clear();
}

module.exports = { check, clientIp, reset };
