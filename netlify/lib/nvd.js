'use strict';
/**
 * Consulta de vulnerabilidades en la API oficial de NVD (https://nvd.nist.gov/developers/vulnerabilities).
 * Solo se envían producto y versión (nunca la URL analizada).
 * La clave opcional NVD_API_KEY se lee únicamente de variables de entorno.
 */

// Lista cerrada: la función NO es un proxy abierto hacia NVD.
const PRODUCTS = {
  php: { name: 'PHP', cpes: ['cpe:2.3:a:php:php'], match: [/^cpe:2\.3:a:php:php:/] },
  wordpress: { name: 'WordPress', cpes: ['cpe:2.3:a:wordpress:wordpress'], match: [/^cpe:2\.3:a:wordpress:wordpress:/] },
  joomla: { name: 'Joomla!', cpes: ['cpe:2.3:a:joomla:joomla\\!'], match: [/^cpe:2\.3:a:joomla:joomla\\?!:/] },
  drupal: { name: 'Drupal', cpes: ['cpe:2.3:a:drupal:drupal'], match: [/^cpe:2\.3:a:drupal:drupal:/] },
  nginx: { name: 'nginx', cpes: ['cpe:2.3:a:f5:nginx', 'cpe:2.3:a:nginx:nginx'], match: [/^cpe:2\.3:a:(f5|nginx):nginx:/] },
  apache: { name: 'Apache HTTP Server', cpes: ['cpe:2.3:a:apache:http_server'], match: [/^cpe:2\.3:a:apache:http_server:/] },
  jquery: { name: 'jQuery', cpes: ['cpe:2.3:a:jquery:jquery'], match: [/^cpe:2\.3:a:jquery:jquery:/] }
};

const VERSION_RE = /^\d{1,3}(\.\d{1,4}){1,3}$/;
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CACHE = new Map();
const CACHE_MS = 60 * 60 * 1000;
const MAX_RETURN = 25;

function pickDescription(descs) {
  const list = Array.isArray(descs) ? descs : [];
  const es = list.find((d) => d.lang === 'es');
  const en = list.find((d) => d.lang === 'en');
  const d = es || en || list[0];
  if (!d) return { text: '', lang: null };
  return { text: String(d.value || '').replace(/\s+/g, ' ').trim().slice(0, 600), lang: d.lang };
}

function pickMetric(metrics) {
  const m = metrics || {};
  const order = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
  for (const k of order) {
    const arr = m[k];
    if (Array.isArray(arr) && arr.length) {
      const primary = arr.find((x) => x.type === 'Primary') || arr[0];
      const d = primary.cvssData || {};
      return {
        score: typeof d.baseScore === 'number' ? d.baseScore : null,
        severity: String(d.baseSeverity || primary.baseSeverity || '').toUpperCase() || null,
        version: d.version || null,
        source: primary.source || null
      };
    }
  }
  return { score: null, severity: null, version: null, source: null };
}

function describeRange(m) {
  const parts = [];
  if (m.versionStartIncluding) parts.push('desde ' + m.versionStartIncluding + ' (incl.)');
  if (m.versionStartExcluding) parts.push('después de ' + m.versionStartExcluding);
  if (m.versionEndIncluding) parts.push('hasta ' + m.versionEndIncluding + ' (incl.)');
  if (m.versionEndExcluding) parts.push('anteriores a ' + m.versionEndExcluding);
  if (!parts.length) {
    const v = String(m.criteria || '').split(':')[5];
    return v && v !== '*' && v !== '-' ? 'versión ' + v : 'todas las versiones';
  }
  return parts.join(' ');
}

function collectAffected(configurations, productKey) {
  const matchers = PRODUCTS[productKey].match;
  const affected = [];
  const fixed = [];
  (configurations || []).forEach((cfg) => {
    (cfg.nodes || []).forEach((node) => {
      (node.cpeMatch || []).forEach((m) => {
        if (!m.vulnerable || !matchers.some((re) => re.test(m.criteria || ''))) return;
        const r = describeRange(m);
        if (!affected.includes(r)) affected.push(r);
        if (m.versionEndExcluding && !fixed.includes(m.versionEndExcluding)) fixed.push(m.versionEndExcluding);
      });
    });
  });
  return { affected: affected.slice(0, 8), fixed: fixed.slice(0, 8) };
}

function normalize(vuln, productKey) {
  const c = vuln.cve || {};
  const desc = pickDescription(c.descriptions);
  const metric = pickMetric(c.metrics);
  const { affected, fixed } = collectAffected(c.configurations, productKey);
  return {
    id: c.id,
    published: c.published || null,
    description: desc.text,
    descriptionLang: desc.lang,
    cvssScore: metric.score,
    cvssSeverity: metric.severity,
    cvssVersion: metric.version,
    affectedVersions: affected,
    fixedVersions: fixed,
    url: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c.id)
  };
}

async function queryOne(cpeBase, version, productKey, deps) {
  const doFetch = (deps && deps.fetch) || fetch;
  const cpe = cpeBase + ':' + version + ':*:*:*:*:*:*:*';
  const url = NVD_URL + '?virtualMatchString=' + encodeURIComponent(cpe) + '&noRejected&resultsPerPage=100';
  const headers = { Accept: 'application/json', 'User-Agent': 'NexoWebGuard/1.0' };
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 7500);
  try {
    const res = await doFetch(url, { headers, signal: ctrl.signal });
    if (res.status === 403 || res.status === 429) {
      const e = new Error('NVD limitó las solicitudes (sin clave API el límite es muy bajo). Reintente en unos segundos.');
      e.code = 'NVD_RATE_LIMIT';
      throw e;
    }
    if (!res.ok) {
      const e = new Error('NVD respondió con el estado HTTP ' + res.status + '.');
      e.code = 'NVD_HTTP';
      throw e;
    }
    const data = await res.json();
    return {
      total: typeof data.totalResults === 'number' ? data.totalResults : (data.vulnerabilities || []).length,
      vulns: (data.vulnerabilities || []).map((v) => normalize(v, productKey)).filter((v) => v.id)
    };
  } catch (e) {
    if (e.name === 'AbortError') {
      const err = new Error('NVD no respondió a tiempo.');
      err.code = 'NVD_TIMEOUT';
      throw err;
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function validateInput(product, version) {
  if (typeof product !== 'string' || !Object.prototype.hasOwnProperty.call(PRODUCTS, product)) {
    return 'Producto no admitido.';
  }
  if (typeof version !== 'string' || !VERSION_RE.test(version)) return 'Versión no válida.';
  return null;
}

async function lookup(product, version, deps) {
  const bad = validateInput(product, version);
  if (bad) {
    const e = new Error(bad);
    e.code = 'BAD_INPUT';
    throw e;
  }
  const key = product + '@' + version;
  const hit = CACHE.get(key);
  if (hit && Date.now() - hit.t < CACHE_MS) return hit.v;

  const merged = new Map();
  let total = 0;
  for (const base of PRODUCTS[product].cpes) {
    const r = await queryOne(base, version, product, deps);
    total += r.total;
    r.vulns.forEach((v) => { if (!merged.has(v.id)) merged.set(v.id, v); });
  }
  const all = Array.from(merged.values()).sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0) || String(b.published).localeCompare(String(a.published)));
  const result = {
    product,
    productName: PRODUCTS[product].name,
    version,
    totalResults: total,
    returned: Math.min(all.length, MAX_RETURN),
    truncated: total > MAX_RETURN || all.length > MAX_RETURN,
    vulnerabilities: all.slice(0, MAX_RETURN),
    source: 'NVD API 2.0 (https://nvd.nist.gov/developers/vulnerabilities)',
    queriedAt: new Date().toISOString(),
    usedApiKey: !!process.env.NVD_API_KEY
  };
  CACHE.set(key, { t: Date.now(), v: result });
  return result;
}

module.exports = { lookup, validateInput, PRODUCTS, VERSION_RE, normalize, pickMetric, collectAffected };
