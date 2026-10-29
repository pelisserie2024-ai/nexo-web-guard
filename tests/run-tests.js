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
