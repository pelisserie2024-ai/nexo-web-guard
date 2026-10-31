'use strict';
/**
 * Fase 2: datos públicos del dominio (RDAP), ubicación aproximada de las IP y estado de DNSSEC.
 *
 * Servicios externos (se informa al usuario en la sección de Privacidad):
 *  - RDAP vía rdap.org (redirige al RDAP oficial del registro del dominio). Recibe el dominio.
 *  - Google Public DNS (JSON API) para DNSSEC. Recibe el dominio.
 *  - ipwho.is para la ubicación aproximada. Recibe solo direcciones IP públicas.
 * Los destinos son fijos: la función no es un proxy abierto. Las redirecciones de RDAP se validan.
 * No se muestran datos personales del titular (solo registrador y fechas/estados públicos).
 */
const dns = require('dns');
const { isPublicIp, validateTarget, resolvePublicHost } = require('./net-guard');
const { registrableDomain, PRIVATE_SUFFIXES } = require('./infra');

const TIMEOUT_MS = 5500;
const MAX_BYTES = 300 * 1024;

const SOURCES = [
  { title: 'RFC 9083 - Respuestas JSON de RDAP', url: 'https://www.rfc-editor.org/rfc/rfc9083' },
  { title: 'IANA - RDAP Bootstrap', url: 'https://data.iana.org/rdap/' },
  { title: 'Google Public DNS - API JSON (DNSSEC)', url: 'https://developers.google.com/speed/public-dns/docs/doh/json' },
  { title: 'ipwho.is - geolocalización por IP', url: 'https://ipwho.is/' }
];

async function fetchJson(url, deps, opts) {
  const doFetch = (deps && deps.fetch) || fetch;
  const o = opts || {};
  let current = url;
  for (let hop = 0; hop <= (o.maxRedirects || 0); hop++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), o.timeoutMs || TIMEOUT_MS);
    let res;
    try {
      res = await doFetch(current, { headers: { Accept: o.accept || 'application/json', 'User-Agent': 'NexoWebGuard/1.1' }, redirect: 'manual', signal: ctrl.signal });
    } catch (e) {
      const err = new Error(e.name === 'AbortError' ? 'Tiempo de espera agotado.' : 'No se pudo conectar con el servicio.');
      err.code = e.name === 'AbortError' ? 'TIMEOUT' : 'NETWORK';
      throw err;
    } finally {
      clearTimeout(timer);
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers && res.headers.get && res.headers.get('location');
      if (!loc || hop >= (o.maxRedirects || 0)) { const e = new Error('Redirección no permitida.'); e.code = 'REDIRECT'; throw e; }
      let next;
      try { next = new URL(loc, current).href; } catch (e) { const er = new Error('Redirección no válida.'); er.code = 'REDIRECT'; throw er; }
      // Solo https, dominio público y sin IP/puerto raro (mismas reglas anti-SSRF del resto del proyecto).
      const v = validateTarget(next);
      if (!v.ok || v.url.protocol !== 'https:') { const e = new Error('Redirección bloqueada por seguridad.'); e.code = 'BLOCKED'; throw e; }
      const r = await resolvePublicHost(v.host, deps && deps.lookup);
      if (!r.ok) { const e = new Error('Redirección bloqueada por seguridad.'); e.code = 'BLOCKED'; throw e; }
      current = next;
      continue;
    }
    if (res.status === 404) { const e = new Error('Sin datos.'); e.code = 'NOT_FOUND'; throw e; }
    if (res.status === 429) { const e = new Error('El servicio limitó las solicitudes.'); e.code = 'RATE_LIMIT'; throw e; }
    if (!res.ok) { const e = new Error('El servicio respondió HTTP ' + res.status + '.'); e.code = 'HTTP'; throw e; }
    const text = await res.text();
    if (text.length > (o.maxBytes || MAX_BYTES)) { const e = new Error('Respuesta demasiado grande.'); e.code = 'TOO_BIG'; throw e; }
    try { return JSON.parse(text); } catch (e) { const er = new Error('Respuesta no válida.'); er.code = 'BAD_JSON'; throw er; }
  }
  const e = new Error('Demasiadas redirecciones.');
  e.code = 'REDIRECT';
  throw e;
}

/* ---------- RDAP ---------- */
function parseRdap(j) {
  const ev = {};
  (j.events || []).forEach((e) => { if (e && e.eventAction && e.eventDate) ev[String(e.eventAction).toLowerCase()] = e.eventDate; });
  let registrar = null;
  (j.entities || []).forEach((en) => {
    if (registrar || !Array.isArray(en.roles) || !en.roles.includes('registrar')) return;
    const vc = en.vcardArray && en.vcardArray[1];
    const fn = Array.isArray(vc) && vc.find((x) => x[0] === 'fn');
    registrar = (fn && String(fn[3]).slice(0, 120)) || (en.handle ? String(en.handle).slice(0, 60) : null);
  });
  return {
    registration: ev.registration || null,
    expiration: ev.expiration || null,
    lastChanged: ev['last changed'] || null,
    statuses: (j.status || []).map((x) => String(x).slice(0, 60)).slice(0, 10),
    registrar,
    nameservers: (j.nameservers || []).map((n) => String(n.ldhName || '').toLowerCase()).filter(Boolean).slice(0, 10),
    delegationSigned: j.secureDNS && typeof j.secureDNS.delegationSigned === 'boolean' ? j.secureDNS.delegationSigned : null
  };
}

async function lookupRdap(domain, deps) {
  try {
    const j = await fetchJson('https://rdap.org/domain/' + encodeURIComponent(domain), deps, { accept: 'application/rdap+json', maxRedirects: 2 });
    return Object.assign({ status: 'ok' }, parseRdap(j));
  } catch (e) {
    const msg = e.code === 'NOT_FOUND' ? 'El registro no publica datos RDAP para este dominio (o el dominio no existe).' : 'No se pudo consultar RDAP: ' + e.message;
    return { status: 'no verificable', error: msg };
  }
}

/* ---------- Geolocalización ---------- */
async function lookupGeo(ip, deps) {
  try {
    const j = await fetchJson('https://ipwho.is/' + encodeURIComponent(ip) + '?fields=success,country,country_code,region,city,latitude,longitude,connection,timezone,message', deps);
    if (!j || j.success === false) return { ip, status: 'no verificable', error: (j && j.message) || 'Sin datos de ubicación.' };
    return {
      ip, status: 'ok',
      country: j.country ? String(j.country).slice(0, 80) : null, countryCode: j.country_code ? String(j.country_code).slice(0, 2) : null,
      region: j.region ? String(j.region).slice(0, 80) : null, city: j.city ? String(j.city).slice(0, 80) : null,
      latitude: typeof j.latitude === 'number' ? Math.round(j.latitude * 10) / 10 : null,
      longitude: typeof j.longitude === 'number' ? Math.round(j.longitude * 10) / 10 : null,
      org: j.connection && (j.connection.org || j.connection.isp) ? String(j.connection.org || j.connection.isp).slice(0, 100) : null,
      asn: j.connection && j.connection.asn ? 'AS' + j.connection.asn : null,
      timezone: j.timezone && j.timezone.id ? String(j.timezone.id).slice(0, 60) : null
    };
  } catch (e) {
    return { ip, status: 'no verificable', error: 'No se pudo consultar la ubicación: ' + e.message };
  }
}

/* ---------- DNSSEC (DNS sobre HTTPS de Google) ---------- */
async function lookupDnssec(domain, deps) {
  try {
    const j = await fetchJson('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=DS&do=1', deps, { accept: 'application/dns-json' });
    if (typeof j.Status !== 'number') return { status: 'no verificable', error: 'Respuesta DNS no interpretable.' };
    if (j.Status !== 0) return { status: 'no verificable', error: 'El resolvedor devolvió el código DNS ' + j.Status + '.' };
    const ds = (j.Answer || []).filter((a) => a.type === 43);
    if (!ds.length) return { status: 'no firmado', dsRecords: 0, validated: false };
    return { status: 'firmado', dsRecords: ds.length, validated: j.AD === true };
  } catch (e) {
    return { status: 'no verificable', error: 'No se pudo consultar DNSSEC: ' + e.message };
  }
}

function mkFinding(n, f) {
  return Object.assign({
    id: 'NWG-D' + String(n).padStart(3, '0'), category: 'Dominio y DNSSEC', severity: 'Informativo', confidence: 'Media',
    evidence: [], source: 'RDAP (registro oficial del dominio)', description: '', recommendation: '', limitations: ''
  }, f);
}

const norm = (s) => String(s).toLowerCase().replace(/[^a-z]/g, '');

async function run(host, deps) {
  const d = deps || {};
  const now = d.now ? d.now() : new Date();
  const domain = registrableDomain(host);
  const onPlatform = PRIVATE_SUFFIXES.some((s) => host === s || host.endsWith('.' + s));
  const result = {
    host, domain, queriedAt: now.toISOString(), available: true, platformSubdomain: onPlatform,
    rdap: null, geo: [], dnssec: null, findings: [], limitations: [], sources: SOURCES
  };

  // IP públicas del sitio (para la ubicación). Nunca se envían IP privadas a servicios externos.
  const resolver = d.resolver || new dns.promises.Resolver({ timeout: 2500, tries: 1 });
  const ips = [];
  const [a, aaaa] = await Promise.all([resolver.resolve4(host).catch(() => []), resolver.resolve6(host).catch(() => [])]);
  [].concat(a, aaaa).forEach((ip) => { if (ips.length < 3 && isPublicIp(ip) && !ips.includes(ip)) ips.push(ip); });

  const tasks = [
    onPlatform ? Promise.resolve({ status: 'no aplica', note: host + ' es un subdominio de una plataforma (' + domain + '); el dominio base pertenece a la plataforma y no al titular del sitio.' }) : lookupRdap(domain, d),
    Promise.all(ips.map((ip) => lookupGeo(ip, d))),
    onPlatform ? Promise.resolve({ status: 'no aplica', note: 'DNSSEC lo gestiona la plataforma para su dominio base.' }) : lookupDnssec(domain, d)
  ];
  const [rdap, geo, dnssec] = await Promise.all(tasks);
  result.rdap = rdap;
  result.geo = geo;
  result.dnssec = dnssec;

  let n = 0;
  const addF = (f) => { n++; result.findings.push(mkFinding(n, f)); };

  if (rdap.status === 'ok') {
    const exp = rdap.expiration ? new Date(rdap.expiration) : null;
    if (exp && !Number.isNaN(exp.getTime())) {
      const days = Math.floor((exp.getTime() - now.getTime()) / 86400000);
      rdap.daysToExpire = days;
      if (days < 0) addF({ title: 'El dominio figura como vencido', severity: 'Alto', confidence: 'Media', evidence: ['Fecha de expiración en RDAP: ' + rdap.expiration], description: 'Un dominio vencido puede dejar de resolver o ser registrado por un tercero.', recommendation: 'Renovar el dominio de inmediato con el registrador y activar la renovación automática.', limitations: 'Algunos registros mantienen la fecha de expiración hasta completar el período de gracia.' });
      else if (days <= 30) addF({ title: 'El dominio vence en ' + days + ' días', severity: 'Bajo', confidence: 'Alta', evidence: ['Fecha de expiración en RDAP: ' + rdap.expiration], description: 'Si caduca, el sitio y el correo dejarán de funcionar.', recommendation: 'Renovar el dominio y activar la renovación automática.', limitations: 'La fecha la declara el registro; confirmar en el panel del registrador.' });
    }
    const reg = rdap.registration ? new Date(rdap.registration) : null;
    if (reg && !Number.isNaN(reg.getTime())) {
      const age = Math.floor((now.getTime() - reg.getTime()) / 86400000);
      rdap.ageDays = age;
      if (age >= 0 && age < 30) addF({ title: 'Dominio registrado hace menos de 30 días', severity: 'Informativo', confidence: 'Media', evidence: ['Fecha de registro en RDAP: ' + rdap.registration], description: 'Los dominios muy nuevos son habituales en sitios fraudulentos, pero también en proyectos legítimos recién lanzados.', recommendation: 'Si no esperabas un dominio tan reciente, verifica su titularidad con el registrador.', limitations: 'La edad por sí sola no demuestra un uso malicioso.' });
    }
    if (rdap.statuses.length && !rdap.statuses.some((s) => /transferprohibited/.test(norm(s)))) {
      addF({ title: 'El dominio no muestra bloqueo de transferencia', severity: 'Informativo', confidence: 'Baja', evidence: ['Estados RDAP: ' + rdap.statuses.join(', ')], description: 'El bloqueo de transferencia (transfer lock) dificulta el robo del dominio.', recommendation: 'Activar el bloqueo de transferencia en el panel del registrador.', limitations: 'Algunos registros de código de país no publican estos estados en RDAP, aunque el bloqueo exista.' });
    }
  }
  if (dnssec.status === 'no firmado') {
    addF({ title: 'El dominio no tiene DNSSEC activado', severity: 'Informativo', confidence: 'Media', source: 'Google Public DNS (consulta DS)', evidence: ['No hay registros DS publicados para ' + domain],
      description: 'DNSSEC firma las respuestas DNS y protege contra su manipulación. Muchos dominios aún no lo usan.', recommendation: 'Valorar activar DNSSEC si el registrador y el proveedor de DNS lo permiten.', limitations: 'Mejora de endurecimiento; su ausencia no es una vulnerabilidad por sí sola.' });
  }

  if (geo.length && geo.every((g) => g.status !== 'ok')) result.limitations.push('No se pudo obtener la ubicación aproximada de las IP.');
  if (!ips.length && !onPlatform) result.limitations.push('No se encontraron IP públicas para consultar su ubicación.');
  result.limitations.push(
    'La ubicación de la IP es aproximada (precisión de ciudad o región) y puede ser incorrecta.',
    'Los datos del dominio provienen de RDAP; los registros de algunos países no publican todos los campos, y los datos del titular no se muestran por privacidad.',
    'DNSSEC se comprueba con el servicio DNS público de Google; no se evaluó la cadena de firmas completa.'
  );
  return result;
}

module.exports = { run, parseRdap, lookupRdap, lookupGeo, lookupDnssec, fetchJson, SOURCES };
