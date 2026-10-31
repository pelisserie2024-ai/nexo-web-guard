'use strict';
/**
 * Fase 3: subdominios a partir de Certificate Transparency (registros públicos de certificados)
 * y detección de CNAME colgantes.
 *
 * Reglas de diseño (modo no intrusivo):
 *  - Los nombres vienen de servicios públicos (certspotter y crt.sh); estos reciben el dominio.
 *  - Sobre los subdominios SOLO se hacen consultas DNS (máximo MAX_RESOLVE). No hay conexiones HTTP.
 *  - No se prueban nombres por fuerza bruta: solo los que figuran en certificados públicos.
 */
const dns = require('dns');
const { fetchJson } = require('./domain-intel');
const { registrableDomain, PRIVATE_SUFFIXES } = require('./infra');
const { isPublicIp } = require('./net-guard');

const MAX_RESOLVE = 40;
const MAX_LISTED = 100;
const CT_BYTES = 4 * 1024 * 1024;
const CT_TIMEOUT = 5000;

const SOURCES = [
  { title: 'Certificate Transparency (RFC 6962)', url: 'https://datatracker.ietf.org/doc/html/rfc6962' },
  { title: 'Cert Spotter - API de emisiones', url: 'https://sslmate.com/certspotter/api' },
  { title: 'crt.sh - búsqueda de certificados', url: 'https://crt.sh/' }
];

const SENSITIVE = /^(admin|administrator|administrador|panel|cpanel|whm|webmail|dev|desarrollo|test|testing|prueba|pruebas|qa|stage|staging|uat|preprod|pre-prod|beta|demo|old|backup|bak|db|sql|mysql|phpmyadmin|pma|vpn|intranet|internal|interno|git|gitlab|jenkins|ci|grafana|kibana|jira|confluence|sso|ftp|sftp|ssh|rdp)[0-9-]*$/;

/** Servicios de terceros en los que un CNAME abandonado suele permitir "subdomain takeover". */
const TAKEOVER_PRONE = [
  [/\.herokuapp\.com\.?$|\.herokudns\.com\.?$/i, 'Heroku'], [/\.github\.io\.?$/i, 'GitHub Pages'],
  [/\.azurewebsites\.net\.?$/i, 'Azure App Service'], [/\.cloudapp\.azure\.com\.?$|\.cloudapp\.net\.?$/i, 'Azure Cloud Services'],
  [/\.trafficmanager\.net\.?$/i, 'Azure Traffic Manager'], [/\.blob\.core\.windows\.net\.?$/i, 'Azure Blob Storage'],
  [/\.s3[.-][a-z0-9.-]*amazonaws\.com\.?$/i, 'Amazon S3'], [/\.elasticbeanstalk\.com\.?$/i, 'AWS Elastic Beanstalk'],
  [/\.myshopify\.com\.?$/i, 'Shopify'], [/\.zendesk\.com\.?$/i, 'Zendesk'], [/\.surge\.sh\.?$/i, 'Surge'],
  [/\.ghost\.io\.?$/i, 'Ghost'], [/\.readme\.io\.?$/i, 'ReadMe'], [/\.helpscoutdocs\.com\.?$/i, 'Help Scout'],
  [/\.statuspage\.io\.?$/i, 'Statuspage'], [/\.pantheonsite\.io\.?$/i, 'Pantheon'], [/\.bitbucket\.io\.?$/i, 'Bitbucket'],
  [/\.unbouncepages\.com\.?$/i, 'Unbounce'], [/\.wpengine\.com\.?$/i, 'WP Engine'], [/\.netlify\.app\.?$/i, 'Netlify'],
  [/\.vercel\.app\.?$/i, 'Vercel'], [/\.cargocollective\.com\.?$/i, 'Cargo']
];

/* ---------- obtención y limpieza de nombres ---------- */
function cleanNames(rawNames, domain) {
  const out = new Set();
  let wildcard = false;
  (rawNames || []).forEach((raw) => {
    String(raw || '').split(/\r?\n/).forEach((n0) => {
      let n = n0.trim().toLowerCase().replace(/\.$/, '');
      if (!n) return;
      if (n.startsWith('*.')) {
        n = n.slice(2); // comodín: se registra el nombre base
        if (n === domain) { wildcard = true; return; }
      }
      if (!/^[a-z0-9._-]+$/.test(n) || n.length > 253) return;
      if (n === domain || !n.endsWith('.' + domain)) return;
      out.add(n);
    });
  });
  return { names: Array.from(out), wildcard };
}

function namesFromCertspotter(arr) {
  const l = [];
  (Array.isArray(arr) ? arr : []).forEach((c) => (c.dns_names || []).forEach((n) => l.push(n)));
  return l;
}
function namesFromCrtsh(arr) {
  const l = [];
  (Array.isArray(arr) ? arr : []).forEach((c) => { if (c.name_value) l.push(c.name_value); if (c.common_name) l.push(c.common_name); });
  return l;
}

async function collectNames(domain, deps) {
  const jobs = [
    fetchJson('https://api.certspotter.com/v1/issuances?domain=' + encodeURIComponent(domain) + '&include_subdomains=true&expand=dns_names', deps, { maxBytes: CT_BYTES, timeoutMs: CT_TIMEOUT })
      .then((j) => ({ service: 'certspotter', names: namesFromCertspotter(j) })),
    fetchJson('https://crt.sh/?q=' + encodeURIComponent('%.' + domain) + '&output=json', deps, { maxBytes: CT_BYTES, timeoutMs: CT_TIMEOUT })
      .then((j) => ({ service: 'crt.sh', names: namesFromCrtsh(j) }))
  ];
  const settled = await Promise.all(jobs.map((p) => p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e }))));
  const used = settled.filter((x) => x.ok).map((x) => x.v);
  const errors = settled.filter((x) => !x.ok).map((x) => x.e.message);
  return { used, errors };
}

/* ---------- resolución DNS (solo DNS) ---------- */
async function safe(fn) {
  try { return { ok: true, v: await fn() }; } catch (e) { return { ok: false, code: (e && e.code) || 'ERROR' }; }
}
const gone = (r) => !r.ok && (r.code === 'ENOTFOUND' || r.code === 'ENODATA');

async function inspect(resolver, name) {
  const [cname, a, aaaa] = await Promise.all([
    safe(() => resolver.resolveCname(name)), safe(() => resolver.resolve4(name)), safe(() => resolver.resolve6(name))
  ]);
  const cnames = cname.ok ? cname.v.slice(0, 2) : [];
  const ips = [].concat(a.ok ? a.v : [], aaaa.ok ? aaaa.v : []).slice(0, 4);
  const sensitive = name.split('.').some((l) => SENSITIVE.test(l));
  const prone = cnames.length ? (TAKEOVER_PRONE.find((p) => p[0].test(cnames[0])) || null) : null;
  let state;
  if (ips.length) state = 'resuelve';
  else if (cnames.length && gone(a) && gone(aaaa)) state = 'colgante';
  else if (gone(a) && gone(aaaa)) state = 'no resuelve';
  else state = 'no verificable';
  return {
    name, state, cnames, ips: ips.map((ip) => ({ ip, public: isPublicIp(ip) })).map((x) => x.ip + (x.public ? '' : ' (no pública)')),
    provider: prone ? prone[1] : null, takeoverProne: !!prone, sensitive
  };
}

function mkFinding(n, f) {
  return Object.assign({
    id: 'NWG-S' + String(n).padStart(3, '0'), category: 'Subdominios', severity: 'Informativo', confidence: 'Media',
    evidence: [], source: 'Certificate Transparency (certspotter / crt.sh) y consultas DNS', description: '', recommendation: '', limitations: ''
  }, f);
}

async function run(host, deps) {
  const d = deps || {};
  const now = d.now ? d.now() : new Date();
  const domain = registrableDomain(host);
  const onPlatform = PRIVATE_SUFFIXES.some((s) => host === s || host.endsWith('.' + s));
  const result = {
    host, domain, queriedAt: now.toISOString(), status: 'ok', available: true, ctSources: [], total: 0, names: [], resolved: [],
    checked: 0, truncated: false, wildcard: false, findings: [], limitations: [], sources: SOURCES
  };
  if (onPlatform) {
    result.status = 'no aplica';
    result.note = host + ' es un subdominio de una plataforma (' + domain + '); la lista de certificados del dominio de la plataforma no corresponde al titular del sitio.';
    return result;
  }

  const ct = await collectNames(domain, d);
  if (!ct.used.length) {
    result.status = 'no verificable';
    result.note = 'No se pudo consultar Certificate Transparency: ' + (ct.errors[0] || 'servicios no disponibles') + '. Repita el análisis más tarde.';
    return result;
  }
  result.ctSources = ct.used.map((u) => u.service);
  const cleaned = cleanNames([].concat.apply([], ct.used.map((u) => u.names)), domain);
  result.wildcard = cleaned.wildcard;
  const all = cleaned.names.sort();
  result.total = all.length;
  result.names = all.slice(0, MAX_LISTED);
  result.truncated = all.length > MAX_LISTED;

  // Prioridad de resolución: nombres sensibles primero, luego el resto por orden alfabético.
  const ordered = all.slice().sort((a, b) => {
    const sa = a.split('.').some((l) => SENSITIVE.test(l)) ? 0 : 1;
    const sb = b.split('.').some((l) => SENSITIVE.test(l)) ? 0 : 1;
    return sa - sb || a.localeCompare(b);
  });
  const toCheck = ordered.slice(0, MAX_RESOLVE);
  const resolver = d.resolver || new dns.promises.Resolver({ timeout: 2000, tries: 1 });
  result.resolved = await Promise.all(toCheck.map((n) => inspect(resolver, n)));
  result.checked = result.resolved.length;
  if (all.length > MAX_RESOLVE) result.limitations.push('Se resolvieron solo ' + MAX_RESOLVE + ' de ' + all.length + ' subdominios (los de nombre sensible primero) para limitar la carga.');
  if (ct.errors.length) result.limitations.push('Un servicio de certificados no respondió (' + ct.errors[0] + '); la lista puede estar incompleta.');

  // ----- hallazgos -----
  let n = 0;
  const addF = (f) => { n++; result.findings.push(mkFinding(n, f)); };
  const live = result.resolved.filter((r) => r.state === 'resuelve');
  if (result.total) {
    addF({
      title: result.total + ' subdominios aparecen en certificados públicos' + (result.checked ? ' (de ' + result.checked + ' consultados por DNS, ' + live.length + ' resuelven hoy)' : ''),
      evidence: all.slice(0, 8).map((x) => x).concat(result.wildcard ? ['Existe un certificado comodín (*.' + domain + ')'] : []),
      description: 'Los certificados TLS se registran públicamente, por lo que cualquiera puede ver qué subdominios han tenido certificado. Sirve para conocer la superficie expuesta.',
      recommendation: 'Revisar la lista y dar de baja los subdominios que ya no se usan (DNS y certificados).',
      limitations: 'Aparecer en un certificado no implica que el subdominio esté activo o accesible.'
    });
  }
  const sens = live.filter((r) => r.sensitive);
  if (sens.length) {
    addF({
      title: 'Subdominios con nombre sensible resuelven públicamente (' + sens.length + ')', severity: 'Bajo', confidence: 'Media',
      evidence: sens.slice(0, 8).map((r) => r.name + (r.ips.length ? ' -> ' + r.ips[0] : '')),
      description: 'Nombres como admin, dev, staging, backup o vpn suelen corresponder a entornos que no deberían ser públicos o que reciben menos mantenimiento.',
      recommendation: 'Confirmar que cada uno es necesario, que está protegido (autenticación, lista de IP permitidas, VPN) y actualizado; retirar los que no se usen.',
      limitations: 'Solo se comprobó el DNS: no se verificó qué contenido sirven ni si requieren autenticación. El nombre por sí solo no prueba un riesgo.'
    });
  }
  // El CNAME del propio sitio analizado ya lo evalúa el módulo de infraestructura (NWG-I): no se repite aquí.
  const proneDangling = result.resolved.filter((r) => r.state === 'colgante' && r.takeoverProne && r.name !== host);
  if (proneDangling.length) {
    addF({
      title: 'Posible "subdomain takeover": CNAME abandonado hacia servicios de terceros (' + proneDangling.length + ')', severity: 'Medio', confidence: 'Media',
      evidence: proneDangling.slice(0, 8).map((r) => r.name + ' -> ' + r.cnames[0] + ' (' + r.provider + ')'),
      description: 'El CNAME apunta a un servicio de terceros donde el destino ya no resuelve. Si el servicio permite reclamar ese nombre, un tercero podría publicar contenido bajo tu dominio.',
      recommendation: 'Eliminar los registros CNAME que ya no se usan o restablecer el servicio de destino en tu cuenta.',
      limitations: 'Solo se comprobó el DNS; no se verificó con el proveedor si el nombre puede reclamarse. Un fallo temporal puede dar el mismo resultado.'
    });
  }
  const otherDangling = result.resolved.filter((r) => r.state === 'colgante' && !r.takeoverProne && r.name !== host);
  if (otherDangling.length) {
    addF({
      title: 'CNAME hacia destinos que no resuelven (' + otherDangling.length + ')', severity: 'Bajo', confidence: 'Media',
      evidence: otherDangling.slice(0, 8).map((r) => r.name + ' -> ' + r.cnames[0]),
      description: 'Registros CNAME abandonados: además de ser desorden de configuración, pueden facilitar la toma de control si el destino vuelve a estar disponible para terceros.',
      recommendation: 'Eliminar los registros que ya no se usan.', limitations: 'Solo se comprobó el DNS; el destino podría ser un servicio interno o temporalmente caído.'
    });
  }

  result.limitations.push(
    'La lista procede de registros públicos de certificados: puede omitir subdominios sin certificado público o con certificados no registrados, e incluir nombres que ya no existen.',
    'Sobre los subdominios solo se hicieron consultas DNS; no se conectó a ninguno por HTTP, por lo que no se verificó su contenido ni su accesibilidad.',
    'No se probaron nombres por fuerza bruta ni transferencias de zona.'
  );
  return result;
}

module.exports = { run, cleanNames, namesFromCertspotter, namesFromCrtsh, inspect, MAX_RESOLVE, SENSITIVE, SOURCES };
