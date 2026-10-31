'use strict';
/* Pruebas automáticas de NEXO WEB GUARD (sin dependencias). Ejecutar: node tests/run-tests.js */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const dns = require('dns');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');

const root = path.join(__dirname, '..');
const guard = require(path.join(root, 'netlify/lib/net-guard'));
const robots = require(path.join(root, 'netlify/lib/robots'));
const detect = require(path.join(root, 'netlify/lib/detect'));
const hdr = require(path.join(root, 'netlify/lib/headers-analysis'));
const phpSupport = require(path.join(root, 'netlify/lib/php-support'));
const nvd = require(path.join(root, 'netlify/lib/nvd'));
const { runAnalysis } = require(path.join(root, 'netlify/lib/analysis'));
const safeFetch = require(path.join(root, 'netlify/lib/safe-fetch'));
const rateLimit = require(path.join(root, 'netlify/lib/rate-limit'));
const Core = require(path.join(root, 'js/core'));
const Advisor = require(path.join(root, 'js/advisor'));
const Pdf = require(path.join(root, 'js/pdf-report'));

let passed = 0;
let failed = 0;
const queue = [];
function test(name, fn) { queue.push({ name, fn }); }

/* ---------- SSRF / validación ---------- */
test('IP privadas, loopback, link-local y mapeadas IPv6 se bloquean', () => {
  ['127.0.0.1', '10.0.0.5', '172.16.5.5', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '224.0.0.1',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1',
    '64:ff9b::7f00:1', '2002:7f00:1::1', '2001:db8::1'].forEach((ip) => assert.strictEqual(guard.isPublicIp(ip), false, ip));
});
test('IP públicas se permiten', () => {
  ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111', '::ffff:8.8.8.8'].forEach((ip) => assert.strictEqual(guard.isPublicIp(ip), true, ip));
});
test('validateTarget rechaza URL peligrosas o inválidas', () => {
  ['', 'ftp://ejemplo.cl', 'file:///etc/passwd', 'javascript:alert(1)', 'http://localhost', 'http://127.0.0.1', 'http://2130706433',
    'http://0x7f.1', 'http://[::1]/', 'https://user:pass@ejemplo.cl', 'https://ejemplo.cl:8443', 'https://servidor.local', 'https://intranet',
    'https://a.internal', 'http://169.254.169.254/latest/meta-data', 'no es una url', 'https://ejemplo.cl/\nHost: x'].forEach((u) => {
    assert.strictEqual(guard.validateTarget(u).ok, false, 'debería rechazar: ' + JSON.stringify(u));
  });
  assert.strictEqual(guard.validateTarget(12345).ok, false);
});
test('validateTarget acepta http/https con dominio público', () => {
  assert.strictEqual(guard.validateTarget('https://ejemplo.cl').ok, true);
  assert.strictEqual(guard.validateTarget('http://www.ejemplo.cl/ruta?x=1').ok, true);
  assert.strictEqual(guard.validateTarget('https://ejemplo.cl:443/').ok, true);
});
test('resolvePublicHost bloquea DNS que apunta a interno o mezcla pública+privada', async () => {
  const mk = (list) => async () => list;
  let r = await guard.resolvePublicHost('x.com', mk([{ address: '127.0.0.1', family: 4 }]));
  assert.strictEqual(r.ok, false);
  r = await guard.resolvePublicHost('x.com', mk([{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.1', family: 4 }]));
  assert.strictEqual(r.ok, false, 'una sola IP interna basta para bloquear');
  r = await guard.resolvePublicHost('x.com', mk([{ address: '2606:4700::1111', family: 6 }, { address: '8.8.8.8', family: 4 }]));
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.addresses[0].family, 4, 'IPv4 primero');
  r = await guard.resolvePublicHost('x.com', async () => { const e = new Error('x'); e.code = 'ENOTFOUND'; throw e; });
  assert.strictEqual(r.ok, false);
});

/* ---------- fetchFollow: redirecciones y fijación de IP (http.request simulado) ---------- */
function fakeHttp(routes, seen) {
  return (options, cb) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => setImmediate(() => {
      seen.push(options);
      const route = routes(options);
      const res = new PassThrough();
      res.statusCode = route.status;
      res.headers = route.headers || {};
      cb(res);
      res.end(route.body || '');
    });
    return req;
  };
}
test('fetchFollow bloquea una redirección hacia una IP interna y fija la IP validada', async () => {
  const origLookup = dns.promises.lookup;
  const origReq = http.request;
  const seen = [];
  dns.promises.lookup = async (h) => {
    if (h === 'publico.example.com') return [{ address: '93.184.216.34', family: 4 }];
    return [{ address: '8.8.4.4', family: 4 }];
  };
  http.request = fakeHttp((o) => (o.host === 'publico.example.com'
    ? { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' } }
    : { status: 200, body: 'no debería llegar' }), seen);
  try {
    const ctx = { budget: { used: 0, max: 10 }, deadline: Date.now() + 5000 };
    await assert.rejects(() => safeFetch.fetchFollow('http://publico.example.com/', ctx, {}), (e) => e.code === 'NWG_BLOCKED');
    assert.strictEqual(seen.length, 1, 'solo debe haberse hecho la primera solicitud');
    // La conexión debe usar la IP ya validada (anti DNS rebinding)
    let got;
    seen[0].lookup('publico.example.com', {}, (err, addr, fam) => { got = [addr, fam]; });
    assert.deepStrictEqual(got, ['93.184.216.34', 4]);
    let gotAll;
    seen[0].lookup('publico.example.com', { all: true }, (err, list) => { gotAll = list; });
    assert.deepStrictEqual(gotAll, [{ address: '93.184.216.34', family: 4 }]);
  } finally {
    dns.promises.lookup = origLookup;
    http.request = origReq;
  }
});
test('fetchFollow respeta el límite de solicitudes y de redirecciones', async () => {
  const origLookup = dns.promises.lookup;
  const origReq = http.request;
  dns.promises.lookup = async () => [{ address: '93.184.216.34', family: 4 }];
  http.request = fakeHttp(() => ({ status: 302, headers: { location: 'http://bucle.example.com/' } }), []);
  try {
    let ctx = { budget: { used: 0, max: 10 }, deadline: Date.now() + 5000 };
    await assert.rejects(() => safeFetch.fetchFollow('http://bucle.example.com/', ctx, { maxRedirects: 3 }), (e) => e.code === 'NWG_REDIRECTS');
    ctx = { budget: { used: 0, max: 2 }, deadline: Date.now() + 5000 };
    await assert.rejects(() => safeFetch.fetchFollow('http://bucle.example.com/', ctx, { maxRedirects: 8 }), (e) => e.code === 'NWG_LIMIT');
  } finally {
    dns.promises.lookup = origLookup;
    http.request = origReq;
  }
});
test('fetchFollow rechaza dominios que resuelven a loopback (sin conectar)', async () => {
  const origLookup = dns.promises.lookup;
  dns.promises.lookup = async () => [{ address: '127.0.0.1', family: 4 }];
  try {
    const ctx = { budget: { used: 0, max: 10 }, deadline: Date.now() + 5000 };
    await assert.rejects(() => safeFetch.fetchFollow('https://trampa.example.com/', ctx, {}), (e) => e.code === 'NWG_BLOCKED');
    assert.strictEqual(ctx.budget.used, 0);
  } finally { dns.promises.lookup = origLookup; }
});

/* ---------- robots ---------- */
test('robots.txt: respeta Disallow, Allow y grupos', () => {
  assert.strictEqual(robots.robotsAllows('User-agent: *\nDisallow: /', '/'), false);
  assert.strictEqual(robots.robotsAllows('User-agent: *\nDisallow: /privado\nAllow: /privado/publico', '/privado/publico/x'), true);
  assert.strictEqual(robots.robotsAllows('User-agent: *\nDisallow:', '/'), true);
  assert.strictEqual(robots.robotsAllows('User-agent: googlebot\nDisallow: /', '/'), true);
  assert.strictEqual(robots.robotsAllows('User-agent: NexoWebGuard\nDisallow: /', '/'), false);
  assert.strictEqual(robots.robotsAllows('', '/'), true);
});

/* ---------- detección ---------- */
const WP_HTML = '<html><head><meta name="generator" content="WordPress 6.4.2"><link rel="stylesheet" href="/wp-content/themes/x/style.css?ver=1.0">' +
  '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script><script src="/wp-includes/js/a.js?ver=6.4.2"></script>' +
  '<script src="http://cdn.inseguro.com/x.js"></script><img src="http://img.inseguro.com/a.png"></head><body></body></html>';
test('detecta WordPress con versión del generator y PHP con versión de cabecera', () => {
  const d = detect.detectTechnologies({ headers: { 'x-powered-by': 'PHP/7.4.33', server: 'nginx/1.18.0 (Ubuntu)', 'set-cookie': ['PHPSESSID=abc; path=/'] }, html: WP_HTML });
  const wp = d.technologies.find((t) => t.id === 'wordpress');
  assert.strictEqual(wp.status, 'Confirmado');
  assert.strictEqual(wp.version, '6.4.2');
  assert.strictEqual(wp.versionStatus, 'Confirmado');
  assert.strictEqual(d.php.status, 'Confirmado');
  assert.strictEqual(d.php.version, '7.4.33');
  assert.strictEqual(d.technologies.find((t) => t.id === 'server').version, '1.18.0');
  assert.strictEqual(d.technologies.find((t) => t.id === 'joomla').status, 'No detectado');
  assert.strictEqual(d.technologies.find((t) => t.id === 'jquery').version, '3.7.1');
});
test('PHP: no se infiere la versión a partir de WordPress; la presencia es solo Probable', () => {
  const d = detect.detectTechnologies({ headers: {}, html: WP_HTML });
  assert.strictEqual(d.php.version, null);
  assert.strictEqual(d.php.status, 'Probable');
  assert.ok(d.php.note.startsWith('No se ha podido confirmar la versión de PHP desde el análisis externo'));
});
test('WordPress sin generator: versión solo como Probable (indirecta) y presencia Probable/Confirmado por señales', () => {
  const html = '<script src="/wp-includes/js/a.js?ver=6.3.1"></script><script src="/wp-includes/js/b.js?ver=6.3.1"></script>';
  const d = detect.detectTechnologies({ headers: { link: '<https://x/wp-json/>; rel="https://api.w.org/"' }, html });
  const wp = d.technologies.find((t) => t.id === 'wordpress');
  assert.strictEqual(wp.status, 'Confirmado');
  assert.strictEqual(wp.version, '6.3.1');
  assert.strictEqual(wp.versionStatus, 'Probable');
});
test('Un solo indicio indirecto no se marca como Confirmado', () => {
  const d = detect.detectTechnologies({ headers: {}, html: '<link rel="stylesheet" href="/wp-content/x.css">' });
  assert.strictEqual(d.technologies.find((t) => t.id === 'wordpress').status, 'Probable');
});
test('Sin señales: No detectado y Servidor Desconocido', () => {
  const d = detect.detectTechnologies({ headers: {}, html: '<html><body>hola</body></html>' });
  ['php', 'wordpress', 'joomla', 'drupal'].forEach((id) => assert.strictEqual(d.technologies.find((t) => t.id === id).status, 'No detectado'));
  assert.strictEqual(d.technologies.find((t) => t.id === 'server').status, 'Desconocido');
});
test('Drupal solo con versión mayor no entrega versión consultable', () => {
  const d = detect.detectTechnologies({ headers: { 'x-generator': 'Drupal 10 (https://www.drupal.org)' }, html: '' });
  const dr = d.technologies.find((t) => t.id === 'drupal');
  assert.strictEqual(dr.status, 'Confirmado');
  assert.strictEqual(dr.version, null);
});
test('contenido mixto distingue activo y pasivo', () => {
  const d = detect.detectTechnologies({ headers: {}, html: WP_HTML });
  const m = detect.findMixedContent(d.assets);
  assert.strictEqual(m.active.length, 1);
  assert.strictEqual(m.passive.length, 1);
});
test('el HTML hostil no rompe la detección', () => {
  const evil = '<script>alert(1)</script><meta name="generator" content="<img src=x onerror=alert(1)>">' + '<a href="javascript:alert(1)">'.repeat(100);
  const d = detect.detectTechnologies({ headers: { server: '<script>x</script>' }, html: evil });
  assert.ok(Array.isArray(d.technologies));
});

/* ---------- cabeceras ---------- */
test('cabeceras: ausentes, correctas y contexto', () => {
  const all = hdr.analyzeSecurityHeaders({}, { isHttps: true });
  assert.strictEqual(all.length, 6);
  assert.strictEqual(all.find((x) => x.key === 'hsts').assessment, 'Ausente');
  const good = hdr.analyzeSecurityHeaders({
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()'
  }, { isHttps: true });
  good.forEach((x) => assert.strictEqual(x.assessment, 'Correcto', x.key));
  const http1 = hdr.analyzeSecurityHeaders({}, { isHttps: false });
  assert.strictEqual(http1.find((x) => x.key === 'hsts').assessment, 'No aplica');
  const weak = hdr.analyzeSecurityHeaders({ 'content-security-policy': "script-src 'unsafe-inline' *" }, { isHttps: true });
  assert.strictEqual(weak.find((x) => x.key === 'csp').assessment, 'Revisar');
});

/* ---------- PHP ---------- */
test('ciclo de soporte de PHP', () => {
  const now = new Date('2026-10-28T12:00:00Z');
  assert.strictEqual(phpSupport.phpSupportStatus('7.4.33', now).status, 'sin_soporte');
  assert.strictEqual(phpSupport.phpSupportStatus('8.0.30', now).status, 'sin_soporte');
  assert.strictEqual(phpSupport.phpSupportStatus('8.1.2', now).status, 'sin_soporte');
  assert.strictEqual(phpSupport.phpSupportStatus('8.3.10', now).status, 'soporte_seguridad');
  assert.strictEqual(phpSupport.phpSupportStatus('9.7.0', now).status, 'desconocido');
  assert.strictEqual(phpSupport.phpSupportStatus('abc', now).status, 'desconocido');
});

/* ---------- NVD (parsing con datos de ejemplo; NO es una consulta real) ---------- */
const NVD_FIXTURE = {
  totalResults: 2,
  vulnerabilities: [
    { cve: { id: 'CVE-2099-0001', published: '2099-01-01T00:00:00.000', descriptions: [{ lang: 'en', value: 'Descripcion de prueba A' }],
      metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL' } }] },
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', versionStartIncluding: '8.1.0', versionEndExcluding: '8.1.30' }] }] }] } },
    { cve: { id: 'CVE-2099-0002', published: '2099-02-01T00:00:00.000', descriptions: [{ lang: 'es', value: 'Descripción en español' }, { lang: 'en', value: 'English' }],
      metrics: {}, configurations: [] } }
  ]
};
test('nvd.lookup interpreta la respuesta, ordena por CVSS y usa descripción en español si existe', async () => {
  const calls = [];
  const res = await nvd.lookup('php', '8.1.2', { fetch: async (url, opt) => { calls.push({ url, opt }); return { ok: true, status: 200, json: async () => NVD_FIXTURE }; } });
  assert.ok(calls[0].url.startsWith('https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString='));
  assert.ok(calls[0].url.includes(encodeURIComponent('cpe:2.3:a:php:php:8.1.2')));
  assert.strictEqual(res.vulnerabilities[0].id, 'CVE-2099-0001');
  assert.strictEqual(res.vulnerabilities[0].cvssScore, 9.8);
  assert.deepStrictEqual(res.vulnerabilities[0].fixedVersions, ['8.1.30']);
  assert.strictEqual(res.vulnerabilities[1].cvssScore, null);
  assert.strictEqual(res.vulnerabilities[1].descriptionLang, 'es');
});
test('nvd: errores 429/403 se traducen a NVD_RATE_LIMIT; entradas inválidas se rechazan', async () => {
  await assert.rejects(() => nvd.lookup('php', '8.2.1', { fetch: async () => ({ ok: false, status: 403 }) }), (e) => e.code === 'NVD_RATE_LIMIT');
  await assert.rejects(() => nvd.lookup('rm -rf', '1.0', {}), (e) => e.code === 'BAD_INPUT');
  await assert.rejects(() => nvd.lookup('php', '8.1.2; DROP', {}), (e) => e.code === 'BAD_INPUT');
  assert.ok(nvd.validateInput('constructor', '1.2'), 'constructor no debe pasar como producto');
});

/* ---------- pipeline completo con respuestas simuladas ---------- */
function stubFetch(map) {
  return async (url, ctx) => {
    ctx.budget.used++;
    const u = new URL(url);
    const key = u.protocol + '//' + u.host + u.pathname;
    const r = map[key];
    if (r instanceof Error) throw r;
    if (!r) { const e = new Error('no route'); e.code = 'ECONNREFUSED'; throw e; }
    return r;
  };
}
const goodTls = { authorized: true, authorizationError: null, protocol: 'TLSv1.3', cert: { subject: { CN: 'ejemplo.cl' }, issuer: { CN: 'R3', O: 'Lets' }, validFrom: 'Jan 1 00:00:00 2026 GMT', validTo: 'Jan 1 00:00:00 2027 GMT', subjectAltName: 'DNS:ejemplo.cl, DNS:www.ejemplo.cl' } };
test('análisis completo: HTTPS válido, PHP sin soporte, WordPress, cabeceras y contenido mixto', async () => {
  const fixedNow = () => new Date('2026-10-28T12:00:00Z');
  const fetchFollow = stubFetch({
    'https://ejemplo.cl/robots.txt': { finalUrl: 'https://ejemplo.cl/robots.txt', chain: [], response: { status: 200, headers: {}, body: 'User-agent: *\nDisallow: /wp-admin/' } },
    'http://ejemplo.cl/': { finalUrl: 'http://ejemplo.cl/', chain: [], response: { status: 301, headers: { location: 'https://ejemplo.cl/' }, body: '' } },
    'https://ejemplo.cl/': {
      finalUrl: 'https://ejemplo.cl/', chain: [{ url: 'https://ejemplo.cl/', status: 200 }], certError: null,
      response: { status: 200, headers: { 'x-powered-by': 'PHP/7.4.33', server: 'Apache/2.4.41 (Ubuntu)', 'set-cookie': ['sid=1; Path=/'] }, body: WP_HTML, tls: goodTls, truncated: false }
    }
  });
  const r = await runAnalysis('https://ejemplo.cl', { fetchFollow }, { now: fixedNow });
  assert.strictEqual(r.status, 'completed');
  assert.strictEqual(r.https.available, 'Sí');
  assert.strictEqual(r.https.redirectsHttpToHttps, 'Sí');
  assert.strictEqual(r.https.certificate.daysLeft > 30, true);
  const titles = r.findings.map((f) => f.title).join(' | ');
  assert.ok(/sin soporte de seguridad/.test(titles), 'PHP 7.4 debe figurar sin soporte');
  assert.ok(/Contenido activo cargado por HTTP/.test(titles));
  assert.ok(/Cabecera ausente: Strict-Transport-Security/.test(titles));
  assert.ok(/Cookies sin atributo Secure/.test(titles));
  assert.ok(r.findings.every((f) => f.id && f.severity && f.confidence));
  const classes = r.vulnLookups.map((l) => l.product + ':' + l.classification).sort();
  assert.deepStrictEqual(classes, ['apache:B', 'jquery:C', 'php:B', 'wordpress:A']);
  assert.ok(r.requests.used <= r.requests.max);
  assert.ok(JSON.parse(JSON.stringify(r)), 'serializable');
});
test('análisis: robots.txt que prohíbe todo detiene el análisis', async () => {
  const fetchFollow = stubFetch({ 'https://ejemplo.cl/robots.txt': { finalUrl: 'x', chain: [], response: { status: 200, headers: {}, body: 'User-agent: *\nDisallow: /' } } });
  const r = await runAnalysis('https://ejemplo.cl', { fetchFollow });
  assert.strictEqual(r.status, 'stopped');
  assert.ok(r.stoppedReason);
  assert.strictEqual(r.requests.used, 1);
  assert.strictEqual(Core.computeRisk(r).incomplete, true);
});
test('análisis: HTTP 429 detiene el análisis', async () => {
  const fetchFollow = stubFetch({
    'https://ejemplo.cl/robots.txt': { finalUrl: 'x', chain: [], response: { status: 404, headers: {}, body: '' } },
    'http://ejemplo.cl/': { finalUrl: 'x', chain: [], response: { status: 200, headers: {}, body: '' } },
    'https://ejemplo.cl/': { finalUrl: 'https://ejemplo.cl/', chain: [], response: { status: 429, headers: {}, body: '' } }
  });
  const r = await runAnalysis('https://ejemplo.cl', { fetchFollow });
  assert.strictEqual(r.status, 'stopped');
});
test('análisis: fallo total devuelve estado failed con error legible (sin simular resultados)', async () => {
  const e = new Error('x'); e.code = 'ENOTFOUND';
  const fetchFollow = stubFetch({ 'https://noexiste.cl/robots.txt': e, 'https://noexiste.cl/': e, 'http://noexiste.cl/': e });
  const r = await runAnalysis('https://noexiste.cl', { fetchFollow });
  assert.strictEqual(r.status, 'failed');
  assert.ok(r.error);
  assert.strictEqual(r.technologies.length, 0);
  assert.strictEqual(r.vulnLookups.length, 0);
  assert.strictEqual(Core.computeRisk(r).message, Core.INCOMPLETE_MESSAGE);
});
test('análisis: HTTPS caído pero HTTP responde -> hallazgo Alto de HTTPS no disponible', async () => {
  const e = new Error('x'); e.code = 'ECONNREFUSED';
  const fetchFollow = stubFetch({
    'https://sinhttps.cl/robots.txt': e, 'https://sinhttps.cl/': e, 'http://sinhttps.cl/': { finalUrl: 'http://sinhttps.cl/', chain: [{ url: 'http://sinhttps.cl/', status: 200 }], response: { status: 200, headers: {}, body: '<html></html>' } }
  });
  const r = await runAnalysis('https://sinhttps.cl', { fetchFollow });
  assert.strictEqual(r.https.available, 'No');
  assert.ok(r.findings.some((f) => /HTTPS no disponible/.test(f.title) && f.severity === 'Alto'));
});
test('análisis: certificado inválido genera hallazgo Alto', async () => {
  const fetchFollow = stubFetch({
    'https://cert.cl/robots.txt': { finalUrl: 'x', chain: [], response: { status: 404, headers: {}, body: '' } },
    'http://cert.cl/': { finalUrl: 'x', chain: [], response: { status: 301, headers: { location: 'https://cert.cl/' }, body: '' } },
    'https://cert.cl/': { finalUrl: 'https://cert.cl/', chain: [], certError: { code: 'CERT_HAS_EXPIRED', message: 'expired' }, response: { status: 200, headers: {}, body: '<html></html>', tls: Object.assign({}, goodTls, { authorized: false }) } }
  });
  const r = await runAnalysis('https://cert.cl', { fetchFollow });
  assert.ok(r.findings.some((f) => /certificado TLS no superó/.test(f.title) && f.severity === 'Alto'));
  assert.strictEqual(r.https.certificate.validForClient, false);
});
test('análisis: URL inválida / interna -> failed sin tocar la red', async () => {
  let called = false;
  const r = await runAnalysis('http://127.0.0.1/', { fetchFollow: async () => { called = true; } });
  assert.strictEqual(r.status, 'failed');
  assert.strictEqual(called, false);
});

/* ---------- núcleo del cliente ---------- */
test('validateUrl del cliente', () => {
  assert.strictEqual(Core.validateUrl('https://ejemplo.cl').ok, true);
  assert.strictEqual(Core.validateUrl('ejemplo.cl').url, 'https://ejemplo.cl/');
  ['', 'ftp://a.cl', 'http://localhost', 'http://192.168.0.1', 'javascript:alert(1)'].forEach((u) => assert.strictEqual(Core.validateUrl(u).ok, false, u));
});
test('riesgo: incertidumbre limita la gravedad y separa confianza', () => {
  const base = { status: 'completed', finalUrl: 'https://x.cl/', findings: [{ id: 'F1', severity: 'Bajo', confidence: 'Alta' }], vulnerabilities: [] };
  assert.strictEqual(Core.computeRisk(base).level, 'Bajo');
  const withB = Object.assign({}, base, { vulnerabilities: [{ id: 'CVE-2099-0001', severity: 'Crítico', severityKnown: true, classification: 'B', confidence: 'Media' }] });
  assert.strictEqual(Core.computeRisk(withB).level, 'Medio', 'clase B se limita a Medio');
  const withC = Object.assign({}, base, { vulnerabilities: [{ id: 'CVE-2099-0002', severity: 'Crítico', severityKnown: true, classification: 'C', confidence: 'Baja' }] });
  assert.strictEqual(Core.computeRisk(withC).level, 'Bajo', 'clase C se limita a Bajo');
  const withA = Object.assign({}, base, { vulnerabilities: [{ id: 'CVE-2099-0003', severity: 'Crítico', severityKnown: true, classification: 'A', confidence: 'Alta' }] });
  assert.strictEqual(Core.computeRisk(withA).level, 'Crítico');
  assert.strictEqual(Core.computeRisk({ status: 'completed', finalUrl: 'https://x.cl/', findings: [], vulnerabilities: [] }).level, 'Informativo');
});
test('normalizeVulns reconstruye el enlace oficial y descarta ids inválidos', () => {
  const lk = { component: 'PHP', product: 'php', version: '8.1.2', classification: 'B' };
  const out = Core.normalizeVulns(lk, { productName: 'PHP', vulnerabilities: [
    { id: 'CVE-2099-0001', description: 'x', cvssScore: 7.5, cvssSeverity: 'HIGH', affectedVersions: [], fixedVersions: ['8.1.30'] },
    { id: '"><script>', description: 'x' }, { id: 'CVE-2099-0002', description: 'sin puntuación' }] });
  assert.strictEqual(out.length, 2);
  assert.strictEqual(out[0].url, 'https://nvd.nist.gov/vuln/detail/CVE-2099-0001');
  assert.strictEqual(out[0].severity, 'Alto');
  assert.strictEqual(out[1].severityKnown, false);
});
test('nombre del archivo PDF y JSON exportado válido', () => {
  assert.strictEqual(Core.pdfFileName(new Date(2026, 9, 28)), 'NEXO-WEB-GUARD-informe-2026-10-28.pdf');
  const j = Core.buildJsonExport({ appVersion: '1.0.0', host: 'x.cl' });
  assert.strictEqual(JSON.parse(j).report.host, 'x.cl');
});

/* ---------- PDF: maquetación con un jsPDF simulado (la librería real no está instalada en este entorno) ---------- */
function MockJsPDF() {
  const calls = { pages: 1, texts: [], links: [], rects: 0 };
  const api = {
    calls, setProperties() {}, setFont() {}, setFontSize() {}, setTextColor() {}, setFillColor() {}, setDrawColor() {}, setLineWidth() {},
    rect() { calls.rects++; }, roundedRect() {}, line() {}, lines() {}, circle() {},
    text(t) { calls.texts.push(Array.isArray(t) ? t.join(' ') : String(t)); },
    textWithLink(t, x, y, o) { calls.texts.push(t); calls.links.push(o.url); },
    getTextWidth(t) { return String(t).length * 1.6; },
    splitTextToSize(t, w) {
      const max = Math.max(5, Math.floor(w / 1.7));
      const out = [];
      String(t).split('\n').forEach((para) => {
        let line = '';
        para.split(' ').forEach((word) => {
          if ((line + ' ' + word).trim().length > max) { out.push(line); line = word; } else line = (line + ' ' + word).trim();
        });
        out.push(line);
      });
      return out;
    },
    addPage() { calls.pages++; }, getNumberOfPages() { return calls.pages; }, setPage() {}, output() { return 'blob'; }
  };
  return api;
}
test('el PDF se maqueta con paginación, incluye datos reales y no corta contenido', () => {
  const vulns = [];
  for (let i = 0; i < 25; i++) vulns.push({ id: 'CVE-2099-' + String(1000 + i), url: 'https://nvd.nist.gov/vuln/detail/CVE-2099-' + (1000 + i), product: 'PHP', detectedVersion: '7.4.33', classification: 'B', severity: 'Alto', severityKnown: true, cvssScore: 7.5, cvssVersion: '3.1', description: 'Descripción larga '.repeat(30), descriptionLang: 'en', affectedVersions: ['anteriores a 7.4.34'], fixedVersions: ['7.4.34'], published: '2099-01-01T00:00:00Z', recommendation: 'Actualizar.' });
  const result = {
    reportId: 'NWG-20261028-AAAA1111', appVersion: '1.0.0', analyzedAt: '2026-10-28T12:00:00Z', requestedUrl: 'https://ejemplo.cl/', finalUrl: 'https://ejemplo.cl/', host: 'ejemplo.cl', status: 'completed',
    https: { available: 'Sí', state: 'ok', redirectsHttpToHttps: 'Sí', tlsProtocol: 'TLSv1.3', certificate: { validForClient: true, subject: 'ejemplo.cl', issuer: 'R3', validFrom: '2026-01-01T00:00:00Z', validTo: '2027-01-01T00:00:00Z', daysLeft: 65, altNames: ['ejemplo.cl'] }, notes: [] },
    technologies: [{ name: 'PHP', status: 'Confirmado', confidence: 'Media', version: '7.4.33', versionStatus: 'Confirmado', evidence: ['X-Powered-By: PHP/7.4.33'], note: '' }],
    php: { status: 'Confirmado', confidence: 'Media', version: '7.4.33', versionSource: 'Cabecera', support: { note: 'terminó' }, evidence: ['X-Powered-By'], message: 'msg', note: '' },
    headers: [{ header: 'Content-Security-Policy', assessment: 'Ausente', present: false, function: 'f', risk: 'r', note: '', recommendation: 'rec' }],
    findings: [{ id: 'NWG-F001', category: 'PHP', title: 'PHP sin soporte — “comillas” ≥ →', severity: 'Alto', confidence: 'Media', evidence: ['e1'], source: 's', description: 'd', recommendation: 'r', limitations: 'l' }],
    vulnLookups: [{ component: 'PHP', product: 'php', version: '7.4.33', classification: 'B' }], vulnLookupSummary: { 'php@7.4.33': '25 CVE mostrados de 120' }, vulnLookupErrors: [], vulnerabilities: vulns,
    notPerformed: ['a', 'b'], limitations: ['c'], sources: [{ title: 'NVD', url: 'https://nvd.nist.gov/developers/vulnerabilities' }], requests: { used: 3, max: 10 }, robots: { checked: true }
  };
  Core.finalize(result);
  const mock = new MockJsPDF();
  const ctor = function () { return mock; };
  const doc = Pdf.build(ctor, result, Core);
  assert.strictEqual(doc, mock);
  assert.ok(mock.calls.pages >= 3, 'debe usar varias páginas: ' + mock.calls.pages);
  const all = mock.calls.texts.join('\n');
  ['NEXO WEB GUARD', 'Informe de análisis de seguridad web', 'NWG-20261028-AAAA1111', 'https://ejemplo.cl/', 'CVE-2099-1024', 'Aviso importante', 'Comprobaciones no realizadas', 'Limitaciones del análisis', 'Fuentes oficiales consultadas'].forEach((s) => assert.ok(all.includes(s), 'falta en el PDF: ' + s));
  assert.ok(!/[‘’“”≥→]/.test(all), 'caracteres fuera de Latin-1 deben normalizarse');
  assert.ok(mock.calls.links.length >= 26, 'enlaces CVE y fuentes');
});
test('el PDF de un análisis fallido explica el error y no inventa resultados', () => {
  const result = { reportId: 'NWG-X', appVersion: '1.0.0', analyzedAt: '2026-10-28T12:00:00Z', requestedUrl: 'https://noexiste.cl/', finalUrl: null, host: 'noexiste.cl', status: 'failed', error: 'No se pudo resolver el dominio (DNS).',
    https: {}, technologies: [], php: null, headers: [], findings: [], vulnLookups: [], vulnerabilities: [], vulnLookupErrors: [], notPerformed: [], limitations: [], sources: [] };
  Core.finalize(result);
  const mock = new MockJsPDF();
  Pdf.build(function () { return mock; }, result, Core);
  const all = mock.calls.texts.join('\n');
  assert.ok(all.includes('Evaluación incompleta'));
  assert.ok(all.includes('No se pudo resolver el dominio'));
  assert.ok(all.includes('No verificable con las comprobaciones disponibles'));
});

/* ---------- handlers ---------- */
const analyzeH = require(path.join(root, 'netlify/functions/analyze-site')).handler;
const vulnH = require(path.join(root, 'netlify/functions/vulnerability-lookup')).handler;
const headersH = require(path.join(root, 'netlify/functions/security-headers')).handler;
const ev = (o) => Object.assign({ httpMethod: 'POST', headers: { host: 'sitio.netlify.app', origin: 'https://sitio.netlify.app', 'x-nf-client-connection-ip': '203.0.113.9' } }, o);
test('analyze-site: método, origen, autorización, URL y límite de frecuencia', async () => {
  rateLimit.reset();
  assert.strictEqual((await analyzeH({ httpMethod: 'GET', headers: {} })).statusCode, 405);
  assert.strictEqual((await analyzeH(ev({ headers: { host: 'sitio.netlify.app', origin: 'https://otro.com' }, body: '{}' }))).statusCode, 403);
  assert.strictEqual((await analyzeH(ev({ body: 'no json' }))).statusCode, 400);
  assert.strictEqual((await analyzeH(ev({ body: JSON.stringify({ url: 'https://ejemplo.cl' }) }))).statusCode, 400, 'sin autorización');
  assert.strictEqual((await analyzeH(ev({ body: JSON.stringify({ url: 'http://169.254.169.254', authorized: true }) }))).statusCode, 400);
  assert.strictEqual((await analyzeH(ev({ body: JSON.stringify({ url: 'http://localhost', authorized: true }) }))).statusCode, 400);
  assert.strictEqual((await analyzeH(ev({ body: 'x'.repeat(5000) }))).statusCode, 400);
});
test('analyze-site: limita a 6 análisis por ventana y por IP', async () => {
  rateLimit.reset();
  const origLookup = dns.promises.lookup;
  dns.promises.lookup = async () => [{ address: '127.0.0.1', family: 4 }]; // todo bloqueado: no hay red
  try {
    const codes = [];
    for (let i = 0; i < 8; i++) codes.push((await analyzeH(ev({ body: JSON.stringify({ url: 'https://ejemplo.cl', authorized: true }) }))).statusCode);
    assert.deepStrictEqual(codes, [200, 200, 200, 200, 200, 200, 429, 429]);
    const r = JSON.parse((await analyzeH(ev({ headers: { host: 'sitio.netlify.app', origin: 'https://sitio.netlify.app', 'x-nf-client-connection-ip': '198.51.100.7' }, body: JSON.stringify({ url: 'https://ejemplo.cl', authorized: true }) }))).body);
    assert.strictEqual(r.status, 'failed', 'DNS interno bloqueado por el backend');
  } finally { dns.promises.lookup = origLookup; rateLimit.reset(); }
});
test('vulnerability-lookup y security-headers validan entradas', async () => {
  rateLimit.reset();
  assert.strictEqual((await vulnH(ev({ body: JSON.stringify({ product: 'otro', version: '1.2.3' }) }))).statusCode, 400);
  assert.strictEqual((await vulnH(ev({ body: JSON.stringify({ product: 'php', version: '../../etc' }) }))).statusCode, 400);
  assert.strictEqual((await vulnH({ httpMethod: 'GET', headers: {} })).statusCode, 405);
  assert.strictEqual((await headersH(ev({ body: JSON.stringify({ url: 'http://10.0.0.1', authorized: true }) }))).statusCode, 400);
  assert.strictEqual((await headersH(ev({ body: JSON.stringify({ url: 'https://ejemplo.cl' }) }))).statusCode, 400);
});

/* ---------- comprobaciones estáticas del proyecto ---------- */
test('las claves API no aparecen en el frontend y no se usa innerHTML', () => {
  ['index.html', 'app.js', 'js/core.js', 'js/pdf-report.js', 'styles.css'].forEach((f) => {
    const s = fs.readFileSync(path.join(root, f), 'utf8');
    assert.ok(!/NVD_API_KEY|apiKey/i.test(s), f + ' no debe contener claves ni referencias');
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/.test(s), f + ' no debe usar HTML dinámico inseguro');
  });
  const nvdSrc = fs.readFileSync(path.join(root, 'netlify/lib/nvd.js'), 'utf8');
  assert.ok(/process\.env\.NVD_API_KEY/.test(nvdSrc));
});
test('no hay firebase, base de datos ni almacenamiento local en el frontend', () => {
  ['index.html', 'app.js', 'js/core.js', 'js/pdf-report.js'].forEach((f) => {
    const s = fs.readFileSync(path.join(root, f), 'utf8');
    assert.ok(!/firebase|localStorage|sessionStorage|indexedDB/i.test(s), f);
  });
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepStrictEqual(Object.keys(pkg.dependencies), ['jspdf']);
});
test('index.html referencia solo archivos existentes y sin scripts en línea', () => {
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), 'sin scripts en línea (compatible con CSP)');
  assert.ok(!/\sstyle=/.test(html), 'sin estilos en línea');
  const refs = [...html.matchAll(/(?:src|href)="([^"#:]+)"/g)].map((m) => m[1]);
  refs.forEach((r) => {
    if (r === 'vendor/jspdf.umd.min.js') return; // se genera con "npm run build" (ver README)
    assert.ok(fs.existsSync(path.join(root, r)), 'falta el archivo referenciado: ' + r);
  });
  ['ANALIZAR SITIO WEB', 'Aviso de uso autorizado', 'Límites del análisis', 'Versión'].forEach((s) => assert.ok(html.includes(s), s));
});
test('app.js define los botones exigidos', () => {
  const s = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  ['DESCARGAR INFORME PDF', 'EXPORTAR JSON', 'VOLVER A ANALIZAR', 'LIMPIAR RESULTADOS'].forEach((t) => assert.ok(s.includes(t), t));
});

/* ---------- infraestructura y DNS ---------- */
const infra = require(path.join(root, 'netlify/lib/infra'));
const infraH = require(path.join(root, 'netlify/functions/infrastructure')).handler;
const dnsErr = (code) => { const e = new Error(code); e.code = code; return e; };
function mockResolver(map) {
  const get = (kind, name) => {
    const k = kind + ':' + name;
    if (!(k in map)) throw dnsErr('ENODATA');
    const v = map[k];
    if (v instanceof Error) throw v;
    return v;
  };
  return {
    resolve4: async (n) => get('A', n), resolve6: async (n) => get('AAAA', n), resolveCname: async (n) => get('CNAME', n),
    resolveNs: async (n) => get('NS', n), resolveMx: async (n) => get('MX', n), resolveTxt: async (n) => get('TXT', n),
    resolveCaa: async (n) => get('CAA', n), reverse: async (ip) => get('PTR', ip)
  };
}
test('registrableDomain: dominios comunes, .cl con subniveles y plataformas', () => {
  assert.strictEqual(infra.registrableDomain('www.ejemplo.cl'), 'ejemplo.cl');
  assert.strictEqual(infra.registrableDomain('ejemplo.cl'), 'ejemplo.cl');
  assert.strictEqual(infra.registrableDomain('a.b.ejemplo.com'), 'ejemplo.com');
  assert.strictEqual(infra.registrableDomain('shop.empresa.com.cl'), 'empresa.com.cl');
  assert.strictEqual(infra.registrableDomain('mi-sitio.netlify.app'), 'mi-sitio.netlify.app');
  assert.strictEqual(infra.registrableDomain('www.mi-sitio.netlify.app'), 'mi-sitio.netlify.app');
});
test('originName para Team Cymru (IPv4 e IPv6)', () => {
  assert.strictEqual(infra.originName('8.8.4.4', 4), '4.4.8.8.origin.asn.cymru.com');
  const v6 = infra.originName('2606:4700:4700::1111', 6);
  assert.ok(v6.endsWith('.origin6.asn.cymru.com'));
  assert.strictEqual(v6.split('.').length - 4, 32, '32 nibbles');
  assert.ok(v6.startsWith('1.1.1.1.'));
});
test('SPF y DMARC: evaluaciones', () => {
  assert.strictEqual(infra.analyzeSpf([]).assessment, 'Ausente');
  assert.strictEqual(infra.analyzeSpf(['v=spf1 include:_spf.google.com -all']).assessment, 'Correcto');
  assert.strictEqual(infra.analyzeSpf(['v=spf1 include:x ~all']).assessment, 'Aceptable');
  assert.strictEqual(infra.analyzeSpf(['v=spf1 +all']).assessment, 'Inseguro');
  assert.strictEqual(infra.analyzeSpf(['v=spf1 all']).assessment, 'Inseguro');
  assert.strictEqual(infra.analyzeSpf(['v=spf1 -all', 'v=spf1 ~all']).assessment, 'Revisar');
  assert.strictEqual(infra.analyzeDmarc([]).assessment, 'Ausente');
  assert.strictEqual(infra.analyzeDmarc(['v=DMARC1; p=none; rua=mailto:a@x.cl']).assessment, 'Monitoreo');
  assert.strictEqual(infra.analyzeDmarc(['v=DMARC1; p=reject; pct=50']).assessment, 'Correcto');
  assert.ok(/50%/.test(infra.analyzeDmarc(['v=DMARC1; p=reject; pct=50']).note));
});
const CF_MAP = {
  'A:www.ejemplo.cl': ['104.16.1.1'], 'NS:ejemplo.cl': ['ana.ns.cloudflare.com', 'bob.ns.cloudflare.com'],
  'MX:ejemplo.cl': [{ exchange: 'mx2.mail.com', priority: 20 }, { exchange: 'mx1.mail.com', priority: 10 }],
  'TXT:ejemplo.cl': [['v=spf1 include:mail.com ~all']],
  'PTR:104.16.1.1': ['cdn.cloudflare.com'],
  'TXT:1.1.16.104.origin.asn.cymru.com': [['13335 | 104.16.0.0/13 | US | arin | 2014-03-28']],
  'TXT:AS13335.asn.cymru.com': [['13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US']]
};
test('infra.run: IP, ASN, proveedor, correo y hallazgos (DNS simulado)', async () => {
  const r = await infra.run('www.ejemplo.cl', { resolver: mockResolver(CF_MAP), now: () => new Date('2026-10-30T12:00:00Z') });
  assert.strictEqual(r.domain, 'ejemplo.cl');
  assert.strictEqual(r.available, true);
  assert.strictEqual(r.ips[0].asn, 'AS13335');
  assert.strictEqual(r.ips[0].country, 'US');
  assert.strictEqual(r.ips[0].asName, 'CLOUDFLARENET, US');
  assert.deepStrictEqual(r.ips[0].ptr, ['cdn.cloudflare.com']);
  assert.ok(r.hosting.some((h) => h.name === 'Cloudflare' && h.role === 'CDN / protección'));
  assert.ok(r.hosting.some((h) => h.name === 'Cloudflare' && h.role === 'Proveedor de DNS'));
  assert.deepStrictEqual(r.records.MX.values, ['10 mx1.mail.com', '20 mx2.mail.com'], 'MX ordenado por prioridad');
  assert.strictEqual(r.email.receivesMail, true);
  assert.strictEqual(r.email.spf.assessment, 'Aceptable');
  const titles = r.findings.map((f) => f.title).join(' | ');
  assert.ok(/no publica DMARC/.test(titles));
  assert.ok(/no define registros CAA/.test(titles));
  assert.ok(/Infraestructura detectada: Cloudflare/.test(titles));
  assert.ok(r.findings.every((f) => /^NWG-I\d{3}$/.test(f.id) && f.severity && f.confidence));
  assert.ok(r.limitations.some((l) => /no la ubicación física|no es la ubicación física|registro del bloque IP/.test(l)));
});
test('infra.run: IP privada en DNS público no se consulta y genera hallazgo', async () => {
  const seen = [];
  const base = mockResolver({ 'A:interno.ejemplo.cl': ['10.0.0.5'], 'NS:ejemplo.cl': ['a.ns', 'b.ns'] });
  const spy = Object.assign({}, base, { reverse: async (ip) => { seen.push(ip); return []; }, resolveTxt: async (n) => { seen.push(n); throw dnsErr('ENODATA'); } });
  const r = await infra.run('interno.ejemplo.cl', { resolver: spy });
  assert.strictEqual(r.ips[0].public, false);
  assert.ok(!seen.some((x) => /10\.0\.0\.5|5\.0\.0\.10/.test(x)), 'no debe consultarse PTR/ASN de IP privadas');
  assert.ok(r.findings.some((f) => /no pública/.test(f.title)));
});
test('infra.run: CNAME colgante, un solo NS y dominio sin correo', async () => {
  const r = await infra.run('blog.ejemplo.cl', { resolver: mockResolver({
    'CNAME:blog.ejemplo.cl': ['abandonado.herokuapp.com'], 'A:blog.ejemplo.cl': [dnsErr('ENODATA')], 'NS:ejemplo.cl': ['solo.ns.com'],
    'A:abandonado.herokuapp.com': dnsErr('ENOTFOUND'), 'AAAA:abandonado.herokuapp.com': dnsErr('ENOTFOUND')
  }) });
  const titles = r.findings.map((f) => f.title).join(' | ');
  assert.ok(/subdomain takeover/.test(titles));
  assert.ok(/un solo servidor de nombres/.test(titles));
  assert.strictEqual(r.email.receivesMail, false);
  assert.ok(/Dominio sin correo y sin SPF/.test(titles));
  assert.ok(r.hosting.some((h) => h.name === 'Heroku'));
});
test('infra.run: si el DNS no responde se marca como no disponible sin inventar datos', async () => {
  const t = dnsErr('ETIMEOUT');
  const r = await infra.run('www.ejemplo.cl', { resolver: mockResolver({ 'A:www.ejemplo.cl': t, 'AAAA:www.ejemplo.cl': t, 'CNAME:www.ejemplo.cl': t, 'NS:ejemplo.cl': t }) });
  assert.strictEqual(r.available, false);
  assert.strictEqual(r.findings.length, 0);
  assert.strictEqual(r.ips.length, 0);
});
test('infra.run: dominio sin ningún registro no genera hallazgos engañosos', async () => {
  const r = await infra.run('noexiste.ejemplo.cl', { resolver: mockResolver({ 'A:noexiste.ejemplo.cl': dnsErr('ENOTFOUND'), 'AAAA:noexiste.ejemplo.cl': dnsErr('ENOTFOUND'), 'NS:ejemplo.cl': dnsErr('ENOTFOUND') }) });
  assert.strictEqual(r.noRecords, true);
  assert.strictEqual(r.findings.length, 0);
  assert.strictEqual(r.email, null);
  assert.ok(/ningún registro DNS/.test(r.limitations[0]));
});
test('infrastructure handler: valida método, origen y URL', async () => {
  rateLimit.reset();
  assert.strictEqual((await infraH({ httpMethod: 'GET', headers: {} })).statusCode, 405);
  assert.strictEqual((await infraH(ev({ headers: { host: 'sitio.netlify.app', origin: 'https://otro.com' }, body: '{}' }))).statusCode, 403);
  assert.strictEqual((await infraH(ev({ body: JSON.stringify({ url: 'http://127.0.0.1' }) }))).statusCode, 400);
  assert.strictEqual((await infraH(ev({ body: JSON.stringify({ url: 'http://localhost' }) }))).statusCode, 400);
  assert.strictEqual((await infraH(ev({ body: JSON.stringify({ url: 'ftp://ejemplo.cl' }) }))).statusCode, 400);
});
test('el PDF incluye la sección de infraestructura con datos reales', () => {
  const r = {
    reportId: 'NWG-X', appVersion: '1.1.0', analyzedAt: '2026-10-30T12:00:00Z', requestedUrl: 'https://www.ejemplo.cl/', finalUrl: 'https://www.ejemplo.cl/', host: 'www.ejemplo.cl', status: 'completed',
    https: {}, technologies: [], php: null, headers: [], findings: [], vulnLookups: [], vulnerabilities: [], vulnLookupErrors: [], notPerformed: [], limitations: [], sources: [],
    infrastructure: { host: 'www.ejemplo.cl', domain: 'ejemplo.cl', available: true,
      ips: [{ ip: '104.16.1.1', public: true, ptr: ['cdn.cloudflare.com'], asn: 'AS13335', asName: 'CLOUDFLARENET, US', prefix: '104.16.0.0/13', country: 'US', registry: 'arin' }],
      hosting: [{ name: 'Cloudflare', role: 'CDN / protección', confidence: 'Media', evidence: ['104.16.1.1 pertenece a AS13335'] }],
      records: { A: { status: 'presente', values: ['104.16.1.1'] }, MX: { status: 'presente', values: ['10 mx1.mail.com'] } },
      email: { domain: 'ejemplo.cl', receivesMail: true, spf: { assessment: 'Aceptable', note: 'ok', value: 'v=spf1 ~all' }, dmarc: { assessment: 'Ausente', note: 'No se encontró', value: null }, dkim: 'No verificable con las comprobaciones disponibles' } }
  };
  Core.finalize(r);
  const mock = new MockJsPDF();
  Pdf.build(function () { return mock; }, r, Core);
  const all = mock.calls.texts.join('\n');
  ['5. Infraestructura y DNS', 'AS13335', 'CLOUDFLARENET', 'Cloudflare', 'No verificable con las comprobaciones disponibles', '15. Aviso importante'].forEach((x) => assert.ok(all.includes(x), 'falta: ' + x));
});
test('análisis: el mensaje de PHP no se duplica cuando no se detecta', async () => {
  const fetchFollow = stubFetch({
    'https://ejemplo.cl/robots.txt': { finalUrl: 'x', chain: [], response: { status: 404, headers: {}, body: '' } },
    'http://ejemplo.cl/': { finalUrl: 'x', chain: [], response: { status: 301, headers: { location: 'https://ejemplo.cl/' }, body: '' } },
    'https://ejemplo.cl/': { finalUrl: 'https://ejemplo.cl/', chain: [{ url: 'https://ejemplo.cl/', status: 200 }], response: { status: 200, headers: {}, body: '<html></html>', tls: goodTls } }
  });
  const r = await runAnalysis('https://ejemplo.cl', { fetchFollow });
  assert.strictEqual(r.php.status, 'No detectado');
  assert.strictEqual(r.php.message, r.php.note);
});

/* ---------- Fase 2: dominio (RDAP), ubicación y DNSSEC ---------- */
const intel = require(path.join(root, 'netlify/lib/domain-intel'));
const intelH = require(path.join(root, 'netlify/functions/domain-intel')).handler;
function resp(status, body, headers) {
  return { status, ok: status >= 200 && status < 300, headers: { get: (k) => (headers || {})[String(k).toLowerCase()] || null }, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)) };
}
const RDAP_OK = {
  events: [{ eventAction: 'registration', eventDate: '2020-05-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: '2026-11-15T00:00:00Z' }, { eventAction: 'last changed', eventDate: '2026-01-10T00:00:00Z' }],
  status: ['client transfer prohibited', 'active'],
  entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'PERSONA PRIVADA']]] }, { roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Registrador Ejemplo SpA']]] }],
  nameservers: [{ ldhName: 'NS1.EJEMPLO.CL' }]
};
function fakeServices(over) {
  const calls = [];
  const o = over || {};
  const fetch = async (url) => {
    calls.push(url);
    const u = new URL(url);
    if (u.host === 'rdap.org') return o.rdap ? o.rdap(url) : resp(200, RDAP_OK);
    if (u.host === 'dns.google') return o.doh ? o.doh(url) : resp(200, { Status: 0, AD: false, Answer: [] });
    if (u.host === 'ipwho.is') return o.geo ? o.geo(url) : resp(200, { success: true, country: 'Chile', country_code: 'CL', region: 'Región Metropolitana', city: 'Santiago', latitude: -33.45, longitude: -70.66, connection: { asn: 1234, org: 'Proveedor SA' }, timezone: { id: 'America/Santiago' } });
    throw new Error('host inesperado: ' + u.host);
  };
  return { fetch, calls };
}
const pubLookup = async () => [{ address: '93.184.216.34', family: 4 }];
test('RDAP: se extraen fechas, registrador y estados sin exponer datos del titular', () => {
  const r = intel.parseRdap(RDAP_OK);
  assert.strictEqual(r.registrar, 'Registrador Ejemplo SpA');
  assert.strictEqual(r.expiration, '2026-11-15T00:00:00Z');
  assert.deepStrictEqual(r.nameservers, ['ns1.ejemplo.cl']);
  assert.ok(!JSON.stringify(r).includes('PERSONA PRIVADA'));
});
test('domain-intel: RDAP + ubicación + DNSSEC y hallazgos (servicios simulados)', async () => {
  const svc = fakeServices({ doh: () => resp(200, { Status: 0, AD: true, Answer: [{ type: 43, data: '1 13 2 abc' }] }) });
  const r = await intel.run('www.ejemplo.cl', { fetch: svc.fetch, resolver: mockResolver({ 'A:www.ejemplo.cl': ['93.184.216.34'], 'AAAA:www.ejemplo.cl': [dnsErr('ENODATA')] }), lookup: pubLookup, now: () => new Date('2026-10-30T12:00:00Z') });
  assert.strictEqual(r.rdap.status, 'ok');
  assert.strictEqual(r.rdap.daysToExpire, 15);
  assert.ok(r.findings.some((f) => /vence en 15 días/.test(f.title) && f.severity === 'Bajo'));
  assert.strictEqual(r.geo[0].country, 'Chile');
  assert.strictEqual(r.geo[0].timezone, 'America/Santiago');
  assert.strictEqual(r.dnssec.status, 'firmado');
  assert.strictEqual(r.dnssec.validated, true);
  assert.ok(!r.findings.some((f) => /DNSSEC/.test(f.title)));
  assert.ok(!r.findings.some((f) => /bloqueo de transferencia/.test(f.title)), 'tiene transfer lock');
  assert.ok(r.findings.every((f) => /^NWG-D\d{3}$/.test(f.id)));
  const hosts = svc.calls.map((u) => new URL(u).host);
  assert.ok(hosts.every((h) => ['rdap.org', 'dns.google', 'ipwho.is'].includes(h)), 'solo destinos fijos: ' + hosts);
});
test('domain-intel: dominio vencido, reciente, sin DNSSEC y sin bloqueo de transferencia', async () => {
  const svc = fakeServices({
    rdap: () => resp(200, { events: [{ eventAction: 'registration', eventDate: '2026-10-20T00:00:00Z' }, { eventAction: 'expiration', eventDate: '2026-10-01T00:00:00Z' }], status: ['active'] }),
    doh: () => resp(200, { Status: 0, Answer: [] })
  });
  const r = await intel.run('ejemplo.cl', { fetch: svc.fetch, resolver: mockResolver({}), lookup: pubLookup, now: () => new Date('2026-10-30T12:00:00Z') });
  const t = r.findings.map((f) => f.severity + ':' + f.title).join(' | ');
  assert.ok(/Alto:El dominio figura como vencido/.test(t));
  assert.ok(/registrado hace menos de 30 días/.test(t));
  assert.ok(/no tiene DNSSEC/.test(t));
  assert.ok(/no muestra bloqueo de transferencia/.test(t));
  assert.strictEqual(r.dnssec.status, 'no firmado');
});
test('domain-intel: subdominio de plataforma no consulta RDAP ni DNSSEC', async () => {
  const svc = fakeServices();
  const r = await intel.run('mi-sitio.netlify.app', { fetch: svc.fetch, resolver: mockResolver({ 'A:mi-sitio.netlify.app': ['93.184.216.34'] }), lookup: pubLookup });
  assert.strictEqual(r.rdap.status, 'no aplica');
  assert.strictEqual(r.dnssec.status, 'no aplica');
  assert.ok(!svc.calls.some((u) => /rdap\.org|dns\.google/.test(u)));
  assert.strictEqual(r.findings.length, 0);
});
test('domain-intel: IP privadas nunca se envían al servicio de ubicación', async () => {
  const svc = fakeServices();
  const r = await intel.run('interno.ejemplo.cl', { fetch: svc.fetch, resolver: mockResolver({ 'A:interno.ejemplo.cl': ['10.0.0.5', '192.168.1.9'], 'AAAA:interno.ejemplo.cl': ['::1'] }), lookup: pubLookup });
  assert.ok(!svc.calls.some((u) => /ipwho\.is/.test(u)));
  assert.strictEqual(r.geo.length, 0);
});
test('domain-intel: redirección RDAP legítima se sigue; hacia IP/interno/http se bloquea', async () => {
  let r = await intel.lookupRdap('ejemplo.cl', { lookup: pubLookup, fetch: (() => { let n = 0; return async () => (n++ === 0 ? resp(302, '', { location: 'https://rdap.nic.cl/domain/ejemplo.cl' }) : resp(200, RDAP_OK)); })() });
  assert.strictEqual(r.status, 'ok');
  for (const loc of ['http://169.254.169.254/latest/', 'https://127.0.0.1/x', 'http://rdap.nic.cl/domain/x', 'https://localhost/x']) {
    r = await intel.lookupRdap('ejemplo.cl', { lookup: pubLookup, fetch: async () => resp(302, '', { location: loc }) });
    assert.strictEqual(r.status, 'no verificable', loc);
    assert.ok(/bloqueada|no permitida|no válida/.test(r.error), loc + ' -> ' + r.error);
  }
  r = await intel.lookupRdap('ejemplo.cl', { lookup: async () => [{ address: '127.0.0.1', family: 4 }], fetch: async () => resp(302, '', { location: 'https://rdap.trampa.com/x' }) });
  assert.strictEqual(r.status, 'no verificable', 'dominio que resuelve a loopback');
});
test('domain-intel: fallos de los servicios se informan como no verificable (sin inventar)', async () => {
  const boom = async () => { throw new Error('caído'); };
  const r = await intel.run('ejemplo.cl', { fetch: boom, resolver: mockResolver({ 'A:ejemplo.cl': ['93.184.216.34'] }), lookup: pubLookup });
  assert.strictEqual(r.rdap.status, 'no verificable');
  assert.strictEqual(r.dnssec.status, 'no verificable');
  assert.strictEqual(r.geo[0].status, 'no verificable');
  assert.strictEqual(r.findings.length, 0);
  const nf = await intel.lookupRdap('ejemplo.cl', { fetch: async () => resp(404, '{}') });
  assert.ok(/no publica datos RDAP|no existe/.test(nf.error));
  const big = await intel.lookupRdap('ejemplo.cl', { fetch: async () => resp(200, 'x'.repeat(400000)) });
  assert.strictEqual(big.status, 'no verificable');
});
test('domain-intel handler valida método, origen y URL', async () => {
  rateLimit.reset();
  assert.strictEqual((await intelH({ httpMethod: 'GET', headers: {} })).statusCode, 405);
  assert.strictEqual((await intelH(ev({ headers: { host: 'sitio.netlify.app', origin: 'https://otro.com' }, body: '{}' }))).statusCode, 403);
  assert.strictEqual((await intelH(ev({ body: JSON.stringify({ url: 'http://127.0.0.1' }) }))).statusCode, 400);
  assert.strictEqual((await intelH(ev({ body: JSON.stringify({ url: 'file:///etc/passwd' }) }))).statusCode, 400);
});
test('el PDF incluye la sección de dominio, ubicación y DNSSEC', () => {
  const r = { reportId: 'NWG-X', appVersion: '1.2.0', analyzedAt: '2026-10-30T12:00:00Z', requestedUrl: 'https://ejemplo.cl/', finalUrl: 'https://ejemplo.cl/', host: 'ejemplo.cl', status: 'completed',
    https: {}, technologies: [], php: null, headers: [], findings: [], vulnLookups: [], vulnerabilities: [], vulnLookupErrors: [], notPerformed: [], limitations: [], sources: [],
    domainIntel: { host: 'ejemplo.cl', domain: 'ejemplo.cl', rdap: { status: 'ok', registrar: 'Registrador Ejemplo SpA', registration: '2020-05-01T00:00:00Z', expiration: '2026-11-15T00:00:00Z', daysToExpire: 16, statuses: ['active'], nameservers: ['ns1.ejemplo.cl'] },
      geo: [{ ip: '93.184.216.34', status: 'ok', country: 'Chile', countryCode: 'CL', region: 'RM', city: 'Santiago', org: 'Proveedor SA', asn: 'AS1234', timezone: 'America/Santiago' }], dnssec: { status: 'no firmado' } } };
  Core.finalize(r);
  const mock = new MockJsPDF();
  Pdf.build(function () { return mock; }, r, Core);
  const all = mock.calls.texts.join('\n');
  ['6. Dominio, ubicación y DNSSEC', 'Registrador Ejemplo SpA', 'Santiago', 'No firmado', '15. Aviso importante'].forEach((x) => assert.ok(all.includes(x), 'falta: ' + x));
});

/* ---------- Fase 3: subdominios (Certificate Transparency) ---------- */
const subs = require(path.join(root, 'netlify/lib/subdomains'));
const subsH = require(path.join(root, 'netlify/functions/subdomains')).handler;
function ctFetch(over) {
  const calls = [];
  const o = over || {};
  const fetch = async (url) => {
    calls.push(url);
    const u = new URL(url);
    if (u.host === 'api.certspotter.com') return o.cs ? o.cs() : resp(200, [{ dns_names: ['ejemplo.cl', '*.ejemplo.cl', 'www.ejemplo.cl', 'admin.ejemplo.cl', 'blog.ejemplo.cl', 'viejo.ejemplo.cl', 'otro.com'] }]);
    if (u.host === 'crt.sh') return o.crt ? o.crt() : resp(200, [{ name_value: 'staging.ejemplo.cl\nwww.ejemplo.cl', common_name: 'staging.ejemplo.cl' }, { name_value: 'soporte.ejemplo.cl' }]);
    throw new Error('host inesperado: ' + u.host);
  };
  return { fetch, calls };
}
const SUB_DNS = {
  'A:www.ejemplo.cl': ['93.184.216.34'], 'A:admin.ejemplo.cl': ['93.184.216.35'], 'A:staging.ejemplo.cl': ['10.0.0.9'],
  'CNAME:blog.ejemplo.cl': ['abandonado.herokuapp.com'], 'CNAME:soporte.ejemplo.cl': ['x.destino-interno.net']
};
test('subdominios: parseo de certspotter y crt.sh, comodines, dominios ajenos y duplicados', () => {
  const c = subs.cleanNames(subs.namesFromCertspotter([{ dns_names: ['*.ejemplo.cl', 'WWW.ejemplo.cl.', 'otro.com', 'x.ejemplo.cl.evil.com'] }]).concat(subs.namesFromCrtsh([{ name_value: 'www.ejemplo.cl\napi.ejemplo.cl', common_name: 'api.ejemplo.cl' }, { name_value: 'bad name.ejemplo.cl' }])), 'ejemplo.cl');
  assert.deepStrictEqual(c.names.sort(), ['api.ejemplo.cl', 'www.ejemplo.cl']);
  assert.strictEqual(c.wildcard, true);
});
test('subdominios: nombres sensibles, CNAME colgante a servicio de terceros y solo consultas DNS', async () => {
  const svc = ctFetch();
  const r = await subs.run('www.ejemplo.cl', { fetch: svc.fetch, resolver: mockResolver(Object.assign({}, SUB_DNS, {
    'A:blog.ejemplo.cl': dnsErr('ENODATA'), 'AAAA:blog.ejemplo.cl': dnsErr('ENODATA'), 'A:soporte.ejemplo.cl': dnsErr('ENOTFOUND'), 'AAAA:soporte.ejemplo.cl': dnsErr('ENOTFOUND')
  })), now: () => new Date('2026-10-30T12:00:00Z') });
  assert.strictEqual(r.status, 'ok');
  assert.deepStrictEqual(r.ctSources.sort(), ['certspotter', 'crt.sh']);
  assert.strictEqual(r.total, 6);
  assert.strictEqual(r.wildcard, true);
  const by = (n) => r.resolved.find((x) => x.name === n);
  assert.strictEqual(by('admin.ejemplo.cl').sensitive, true);
  assert.strictEqual(by('blog.ejemplo.cl').state, 'colgante');
  assert.strictEqual(by('blog.ejemplo.cl').takeoverProne, true);
  assert.strictEqual(by('blog.ejemplo.cl').provider, 'Heroku');
  assert.strictEqual(by('soporte.ejemplo.cl').takeoverProne, false);
  assert.strictEqual(by('viejo.ejemplo.cl').state, 'no resuelve');
  assert.ok(by('staging.ejemplo.cl').ips[0].includes('no pública'), 'IP privada marcada');
  const t = r.findings.map((f) => f.severity + ':' + f.title).join(' | ');
  assert.ok(/Medio:Posible "subdomain takeover"/.test(t));
  assert.ok(/Bajo:Subdominios con nombre sensible/.test(t));
  assert.ok(/Bajo:CNAME hacia destinos que no resuelven/.test(t));
  assert.ok(/Informativo:6 subdominios aparecen en certificados públicos/.test(t));
  assert.ok(r.findings.every((f) => /^NWG-S\d{3}$/.test(f.id)));
  const hosts = svc.calls.map((u) => new URL(u).host);
  assert.ok(hosts.every((h) => ['api.certspotter.com', 'crt.sh'].includes(h)), 'sin conexiones a los subdominios: ' + hosts);
});
test('subdominios: límite de 40 resoluciones, con los nombres sensibles primero', async () => {
  const many = [];
  for (let i = 0; i < 120; i++) many.push('host' + String(i).padStart(3, '0') + '.ejemplo.cl');
  many.push('zz-admin.ejemplo.cl', 'admin.ejemplo.cl');
  let resolved = 0;
  const base = mockResolver({});
  const counting = Object.assign({}, base, { resolve4: async () => { resolved++; throw dnsErr('ENOTFOUND'); } });
  const svc = ctFetch({ cs: () => resp(200, [{ dns_names: many }]), crt: () => resp(200, []) });
  const r = await subs.run('ejemplo.cl', { fetch: svc.fetch, resolver: counting });
  assert.strictEqual(r.total, 122);
  assert.strictEqual(r.checked, 40);
  assert.strictEqual(resolved, 40);
  assert.ok(r.resolved.slice(0, 1).some((x) => x.name === 'admin.ejemplo.cl'), 'sensible primero');
  assert.ok(r.limitations.some((l) => /solo 40 de 122/.test(l)));
  assert.strictEqual(r.names.length, 100);
  assert.strictEqual(r.truncated, true);
});
test('subdominios: un servicio caído se tolera; ambos caídos = no verificable; plataforma = no aplica', async () => {
  let r = await subs.run('ejemplo.cl', { fetch: ctFetch({ crt: () => { throw new Error('timeout'); } }).fetch, resolver: mockResolver({}) });
  assert.strictEqual(r.status, 'ok');
  assert.ok(r.limitations.some((l) => /no respondió/.test(l)));
  const boom = async () => { throw new Error('caído'); };
  r = await subs.run('ejemplo.cl', { fetch: boom, resolver: mockResolver({}) });
  assert.strictEqual(r.status, 'no verificable');
  assert.strictEqual(r.findings.length, 0);
  const svc = ctFetch();
  r = await subs.run('mi-sitio.netlify.app', { fetch: svc.fetch, resolver: mockResolver({}) });
  assert.strictEqual(r.status, 'no aplica');
  assert.strictEqual(svc.calls.length, 0);
});
test('subdominios: respuesta enorme se rechaza sin romper', async () => {
  const r = await subs.run('ejemplo.cl', { fetch: ctFetch({ cs: () => resp(200, 'x'.repeat(5 * 1024 * 1024)), crt: () => resp(200, 'x'.repeat(5 * 1024 * 1024)) }).fetch, resolver: mockResolver({}) });
  assert.strictEqual(r.status, 'no verificable');
});
test('subdomains handler valida método, origen y URL', async () => {
  rateLimit.reset();
  assert.strictEqual((await subsH({ httpMethod: 'GET', headers: {} })).statusCode, 405);
  assert.strictEqual((await subsH(ev({ headers: { host: 'sitio.netlify.app', origin: 'https://otro.com' }, body: '{}' }))).statusCode, 403);
  assert.strictEqual((await subsH(ev({ body: JSON.stringify({ url: 'http://169.254.169.254' }) }))).statusCode, 400);
  assert.strictEqual((await subsH(ev({ body: JSON.stringify({ url: 'ftp://ejemplo.cl' }) }))).statusCode, 400);
});
test('el PDF incluye la sección de subdominios', () => {
  const r = { reportId: 'NWG-X', appVersion: '1.3.0', analyzedAt: '2026-10-30T12:00:00Z', requestedUrl: 'https://ejemplo.cl/', finalUrl: 'https://ejemplo.cl/', host: 'ejemplo.cl', status: 'completed',
    https: {}, technologies: [], php: null, headers: [], findings: [], vulnLookups: [], vulnerabilities: [], vulnLookupErrors: [], notPerformed: [], limitations: [], sources: [],
    subdomains: { host: 'ejemplo.cl', domain: 'ejemplo.cl', status: 'ok', ctSources: ['certspotter'], total: 3, checked: 1, wildcard: false, truncated: false, names: ['admin.ejemplo.cl', 'viejo.ejemplo.cl', 'zz.ejemplo.cl'],
      resolved: [{ name: 'admin.ejemplo.cl', state: 'colgante', cnames: ['x.herokuapp.com'], ips: [], provider: 'Heroku', takeoverProne: true, sensitive: true }] } };
  Core.finalize(r);
  const mock = new MockJsPDF();
  Pdf.build(function () { return mock; }, r, Core);
  const all = mock.calls.texts.join('\n');
  ['7. Subdominios (Certificate Transparency)', 'admin.ejemplo.cl', 'takeover', '(Heroku)', 'viejo.ejemplo.cl', '15. Aviso importante'].forEach((x) => assert.ok(all.includes(x), 'falta: ' + x));
});

/* ---------- Fase 4: consistencia entre módulos, sin repeticiones ---------- */
async function fullMergedReport() {
  const now = () => new Date('2026-10-30T12:00:00Z');
  const map = Object.assign({}, CF_MAP, SUB_DNS, { 'CNAME:www.ejemplo.cl': ['destino.herokuapp.com'], 'A:blog.ejemplo.cl': dnsErr('ENODATA'), 'AAAA:blog.ejemplo.cl': dnsErr('ENODATA') });
  const i = await infra.run('www.ejemplo.cl', { resolver: mockResolver(map), now });
  const d = await intel.run('www.ejemplo.cl', { fetch: fakeServices().fetch, resolver: mockResolver(map), lookup: pubLookup, now });
  const sb = await subs.run('www.ejemplo.cl', { fetch: ctFetch().fetch, resolver: mockResolver(map), now });
  const r = { reportId: 'NWG-X', appVersion: '1.4.0', analyzedAt: '2026-10-30T12:00:00Z', requestedUrl: 'https://www.ejemplo.cl/', finalUrl: 'https://www.ejemplo.cl/', host: 'www.ejemplo.cl', status: 'completed',
    https: { available: 'Sí', certificate: { daysLeft: 60 } }, technologies: [{ name: 'PHP', status: 'Confirmado' }], php: null, headers: [], findings: [], vulnLookups: [], vulnerabilities: [], vulnLookupErrors: [], notPerformed: ['n1'], limitations: ['Base'], sources: [{ title: 'NVD', url: 'https://nvd.nist.gov/x' }] };
  Core.mergeModule(r, 'infrastructure', i, 'infra falló');
  Core.mergeModule(r, 'domainIntel', d, 'dominio falló');
  Core.mergeModule(r, 'subdomains', sb, 'subdominios falló');
  return Core.finalize(r);
}
test('mergeModule: no duplica limitaciones ni fuentes y registra un módulo fallido una sola vez', () => {
  const r = { findings: [], limitations: ['L1'], sources: [{ url: 'https://a' }] };
  Core.mergeModule(r, 'infrastructure', { host: 'x.cl', findings: [{ id: 'NWG-I001' }], limitations: ['L1', 'L2', 'L2'], sources: [{ url: 'https://a' }, { url: 'https://b' }] }, 'falló');
  assert.deepStrictEqual(r.limitations, ['L1', 'L2']);
  assert.strictEqual(r.sources.length, 2);
  assert.strictEqual(r.findings.length, 1);
  Core.mergeModule(r, 'subdomains', { error: 'timeout' }, 'El análisis de subdominios no pudo completarse');
  Core.mergeModule(r, 'subdomains', { error: 'timeout' }, 'El análisis de subdominios no pudo completarse');
  assert.strictEqual(r.subdomains, null);
  assert.strictEqual(r.limitations.filter((l) => /subdominios no pudo/.test(l)).length, 1);
});
test('auditoría: informe con todos los módulos sin IDs ni limitaciones repetidas', async () => {
  const r = await fullMergedReport();
  const ids = r.findings.map((f) => f.id);
  assert.strictEqual(new Set(ids).size, ids.length, 'IDs duplicados: ' + ids);
  assert.strictEqual(new Set(r.limitations).size, r.limitations.length, 'limitaciones repetidas');
  const urls = r.sources.map((s) => s.url);
  assert.strictEqual(new Set(urls).size, urls.length, 'fuentes repetidas');
  const titles = r.findings.map((f) => f.title);
  assert.strictEqual(new Set(titles).size, titles.length, 'títulos repetidos');
});
test('auditoría: sin limitaciones desactualizadas ni contradictorias entre módulos', async () => {
  const r = await fullMergedReport();
  const lim = r.limitations.join('\n');
  assert.ok(!/No se enumeraron subdominios/.test(lim), 'dice que no se enumeraron subdominios aunque sí se hizo');
  assert.ok(!/no se evaluó DNSSEC/.test(lim), 'dice que no se evaluó DNSSEC aunque sí se hizo');
  assert.strictEqual(r.limitations.filter((l) => /ubicación de la IP|país mostrado/.test(l)).length, 2, 'cada aviso de ubicación aporta algo distinto');
  assert.ok(!r.limitations.some((l) => /CDN, proxy o balanceador/.test(l) && /RIR/.test(l)));
});
test('auditoría: el CNAME abandonado del propio sitio se informa una sola vez (NWG-I), no también como subdominio', async () => {
  const r = await fullMergedReport();
  const take = r.findings.filter((f) => /subdomain takeover/.test(f.title));
  const own = take.filter((f) => (f.evidence || []).some((e) => /^www\.ejemplo\.cl/.test(e)));
  assert.strictEqual(own.length, 1, 'el host propio aparece en ' + own.length + ' hallazgos');
  assert.ok(/^NWG-I/.test(own[0].id));
});
test('resumen ejecutivo: máx. 3 prioridades coherentes con los hallazgos y sin datos inventados', async () => {
  const r = await fullMergedReport();
  const s = r.summary;
  assert.strictEqual(s.incomplete, false);
  assert.ok(s.priorities.length >= 1 && s.priorities.length <= 3);
  s.priorities.forEach((p, i) => assert.strictEqual(p.id, r.prioritized[i].id));
  assert.ok(s.priorities.every((p) => p.severity !== 'Informativo'));
  assert.ok(s.points.some((p) => /^Hallazgos: \d+ en total, \d+ de gravedad Baja o superior/.test(p)));
  assert.ok(s.points.some((p) => /Tecnologías confirmadas: PHP/.test(p)));
  assert.ok(!s.points.some((p) => /CVE/.test(p)), 'sin CVE no debe mencionarlos');
});
test('resumen ejecutivo: análisis incompleto o módulo caído se declara, sin porcentajes', () => {
  const f = Core.finalize({ status: 'failed', error: 'dns', findings: [], vulnerabilities: [], limitations: [] });
  assert.strictEqual(f.summary.incomplete, true);
  assert.ok(f.summary.headline.includes('Evaluación incompleta'));
  const r = Core.finalize({ status: 'completed', finalUrl: 'https://x.cl/', findings: [], vulnerabilities: [], limitations: [], infrastructure: null, subdomains: null });
  assert.ok(r.summary.points.some((p) => /infraestructura y DNS, subdominios/.test(p)));
  assert.ok(!/%/.test(JSON.stringify(r.summary)));
});
test('el PDF incluye el resumen ejecutivo y no repite la fuente de hallazgos consecutivos', async () => {
  const r = await fullMergedReport();
  const mock = new MockJsPDF();
  Pdf.build(function () { return mock; }, r, Core);
  const all = mock.calls.texts.join('\n');
  assert.ok(all.includes('Resumen ejecutivo:'));
  assert.ok(all.includes('Prioridades (detalle en la sección 10):'));
  const lines = mock.calls.texts.filter((t) => /^Fuente: /.test(t));
  lines.forEach((t, i) => { if (i) assert.notStrictEqual(t, lines[i - 1], 'fuente repetida seguida'); });
});

/* ---------- Fase 5: asesor (reportar y qué mejorar) ---------- */
test('buildReportAdvice: usa el proveedor y registrador ya detectados, sin inventar enlaces', () => {
  const r = { infrastructure: { hosting: [{ name: 'Cloudflare', role: 'CDN / protección' }, { name: 'Cloudflare', role: 'Proveedor de DNS' }, { name: 'Un Proveedor Rarísimo SA', role: 'Alojamiento' }] },
    domainIntel: { rdap: { status: 'ok', registrar: 'Registrador Ejemplo SpA' } } };
  const a = Advisor.buildReportAdvice(r);
  assert.strictEqual(a.providers.length, 2, 'no duplica Cloudflare, agrega el desconocido');
  assert.strictEqual(a.providers[0].abuseUrl, 'https://abuse.cloudflare.com/');
  assert.strictEqual(a.providers[1].abuseUrl, null, 'proveedor sin enlace fijo no inventa URL');
  assert.strictEqual(a.registrar, 'Registrador Ejemplo SpA');
  assert.ok(a.resources.length >= 3);
});
test('buildReportAdvice: sin proveedor ni RDAP, lo declara en vez de inventar', () => {
  const a = Advisor.buildReportAdvice({ infrastructure: null, domainIntel: { rdap: { status: 'no verificable' } } });
  assert.strictEqual(a.providers.length, 0);
  assert.strictEqual(a.registrar, null);
  assert.ok(/No se pudo determinar/.test(a.registrarNote));
});
test('buildImprovementPlan: mismo orden que los hallazgos priorizados, con dificultad por categoría', () => {
  const r = { findings: [
    { id: 'NWG-F001', category: 'Cabeceras', title: 'x', severity: 'Medio', confidence: 'Alta' },
    { id: 'NWG-F002', category: 'PHP', title: 'y', severity: 'Alto', confidence: 'Media' },
    { id: 'NWG-F003', category: 'Desconocida', title: 'z', severity: 'Bajo', confidence: 'Alta' },
    { id: 'NWG-F004', category: 'Cabeceras', title: 'w', severity: 'Informativo', confidence: 'Alta' }
  ] };
  const plan = Advisor.buildImprovementPlan(r, Core);
  assert.strictEqual(plan.count, 3, 'excluye Informativo');
  assert.deepStrictEqual(plan.items.map((i) => i.id), ['NWG-F002', 'NWG-F001', 'NWG-F003'], 'ordenado por gravedad efectiva');
  assert.strictEqual(plan.items[1].difficulty, 'Fácil');
  assert.strictEqual(plan.items[2].difficulty, 'Por evaluar', 'categoría sin mapeo no inventa una dificultad');
});
test('el PDF incluye "Dónde reportar" con el proveedor y sin romper la numeración', () => {
  const r = { reportId: 'NWG-X', appVersion: '1.5.0', analyzedAt: '2026-10-31T12:00:00Z', requestedUrl: 'https://ejemplo.cl/', finalUrl: 'https://ejemplo.cl/', host: 'ejemplo.cl', status: 'completed',
    https: {}, technologies: [], php: null, headers: [], findings: [{ id: 'NWG-F001', category: 'Cabeceras', title: 'Falta CSP', severity: 'Medio', confidence: 'Alta', recommendation: 'r' }],
    vulnLookups: [], vulnerabilities: [], vulnLookupErrors: [], notPerformed: [], limitations: [], sources: [] };
  Core.finalize(r);
  r.reportAdvice = Advisor.buildReportAdvice({ infrastructure: { hosting: [{ name: 'Cloudflare', role: 'CDN / protección' }] }, domainIntel: null });
  r.improvementPlan = Advisor.buildImprovementPlan(r, Core);
  const mock = new MockJsPDF();
  Pdf.build(function () { return mock; }, r, Core);
  const all = mock.calls.texts.join('\n');
  ['11. Dónde reportar un sitio sospechoso', 'Cloudflare', 'Para resolver: Fácil', '12. Comprobaciones no realizadas', '15. Aviso importante'].forEach((x) => assert.ok(all.includes(x), 'falta: ' + x));
  assert.ok(mock.calls.links.includes('https://abuse.cloudflare.com/'));
});
test('index.html carga js/advisor.js antes de app.js', () => {
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  assert.ok(/js\/advisor\.js/.test(html));
  assert.ok(html.indexOf('js/advisor.js') < html.indexOf('app.js'));
});

/* ---------- ejecución ---------- */
(async () => {
  for (const t of queue) {
    try {
      await t.fn();
      passed++;
      console.log('  OK   ' + t.name);
    } catch (e) {
      failed++;
      console.log('  FALLO ' + t.name + '\n        ' + (e && e.message ? e.message.split('\n')[0] : e));
    }
  }
  console.log('\n' + passed + ' superadas, ' + failed + ' fallidas');
  process.exit(failed ? 1 : 0);
})();
