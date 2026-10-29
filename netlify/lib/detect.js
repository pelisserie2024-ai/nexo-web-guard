'use strict';
/**
 * Detección pasiva de tecnologías a partir de cabeceras HTTP y del HTML de la página principal.
 * Estados: Confirmado | Probable | No detectado | Desconocido
 * Confianza (separada del estado): Alta | Media | Baja
 */

const MAX_HTML = 1500000;

function parseAttrs(tag) {
  const attrs = {};
  const re = /([a-zA-Z_:][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
  let m;
  while ((m = re.exec(tag))) attrs[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4]);
  return attrs;
}

/** Extrae meta generator y recursos (script/link/img/iframe/form...) del HTML. */
function extractFromHtml(html) {
  const src = String(html || '').slice(0, MAX_HTML);
  const generators = [];
  const assets = [];
  const tagRe = /<(meta|script|link|img|iframe|form|source|audio|video|embed|object|a)\b[^>]*>/gi;
  let m;
  let count = 0;
  while ((m = tagRe.exec(src)) && count++ < 6000) {
    const name = m[1].toLowerCase();
    const a = parseAttrs(m[0]);
    if (name === 'meta') {
      if ((a.name || '').toLowerCase() === 'generator' && a.content) generators.push(a.content.trim().slice(0, 200));
      continue;
    }
    let url = null;
    let attr = null;
    if (name === 'link') { url = a.href; attr = 'href'; }
    else if (name === 'form') { url = a.action; attr = 'action'; }
    else if (name === 'object') { url = a.data; attr = 'data'; }
    else if (name === 'a') { url = a.href; attr = 'href'; }
    else { url = a.src; attr = 'src'; }
    if (url) assets.push({ tag: name, attr, url: url.trim().slice(0, 500), rel: (a.rel || '').toLowerCase(), raw: m[0].length > 400 ? '' : m[0] });
  }
  return { generators, assets, ngVersion: (src.match(/\bng-version\s*=\s*["']([\d.]+)["']/i) || [])[1] || null, src };
}

function tech(id, name, category, status, confidence, extra) {
  return Object.assign({
    id, name, category, status, confidence,
    version: null, versionStatus: null, versionSource: null,
    evidence: [], note: ''
  }, extra || {});
}

function cleanVersion(v) {
  const m = String(v || '').match(/\d+(?:\.\d+){1,3}/);
  return m ? m[0] : null;
}

function detectTechnologies(input) {
  const headers = input.headers || {};
  const { generators, assets, ngVersion, src: html } = extractFromHtml(input.html);
  const cookies = [].concat(headers['set-cookie'] || []);
  const cookieNames = cookies.map((c) => String(c).split('=')[0].trim());
  const techs = [];
  const infoDisclosure = [];
  const server = headers.server || '';
  const powered = [].concat(headers['x-powered-by'] || []).join(', ');
  const hrefs = assets.filter((a) => ['link', 'script', 'img'].includes(a.tag)).map((a) => a.url);
  const allUrls = assets.map((a) => a.url);

  // ---------- WordPress ----------
  {
    const ev = [];
    let direct = false;
    let version = null;
    let versionStatus = null;
    let versionSource = null;
    const gen = generators.find((g) => /^wordpress\b/i.test(g));
    if (gen) {
      direct = true;
      ev.push('Meta generator: "' + gen + '"');
      const v = cleanVersion(gen);
      if (v) { version = v; versionStatus = 'Confirmado'; versionSource = 'Meta generator declarado por el sitio'; }
    }
    const wpPaths = hrefs.filter((u) => /\/wp-(content|includes)\//i.test(u));
    if (wpPaths.length) ev.push('Recursos bajo /wp-content/ o /wp-includes/ (' + wpPaths.length + ')');
    const link = [].concat(headers.link || []).join(' ');
    const apiLink = /api\.w\.org/i.test(link) || /rel=["']https:\/\/api\.w\.org\//i.test(html);
    if (apiLink) ev.push('Enlace a la API REST de WordPress (api.w.org)');
    if (headers['x-pingback'] && /xmlrpc\.php/i.test(headers['x-pingback'])) ev.push('Cabecera X-Pingback con xmlrpc.php');
    const signals = [wpPaths.length > 0, apiLink, !!headers['x-pingback']].filter(Boolean).length;
    if (!version && wpPaths.length) {
      // Versión indirecta: parámetro ?ver= de recursos del núcleo (/wp-includes/)
      const counts = {};
      hrefs.filter((u) => /\/wp-includes\//i.test(u)).forEach((u) => {
        const vm = u.match(/[?&]ver=(\d+\.\d+(?:\.\d+)?)/);
        if (vm) counts[vm[1]] = (counts[vm[1]] || 0) + 1;
      });
      const best = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
      if (best && best[1] >= 2) {
        version = best[0];
        versionStatus = 'Probable';
        versionSource = 'Parámetro ?ver= repetido en ' + best[1] + ' recursos del núcleo (/wp-includes/); indicador indirecto';
      }
    }
    if (direct || signals >= 2) {
      techs.push(tech('wordpress', 'WordPress', 'CMS', 'Confirmado', direct ? 'Alta' : 'Media', { version, versionStatus, versionSource, evidence: ev }));
    } else if (signals === 1) {
      techs.push(tech('wordpress', 'WordPress', 'CMS', 'Probable', 'Baja', { version, versionStatus, versionSource, evidence: ev }));
    } else {
      techs.push(tech('wordpress', 'WordPress', 'CMS', 'No detectado', 'Baja', { note: 'No se observaron indicadores públicos. La ausencia de señales no demuestra que no esté presente.' }));
    }
    if (gen && version) infoDisclosure.push({ what: 'Versión de WordPress publicada en el meta generator', evidence: 'meta generator: ' + gen });
  }

  // ---------- Joomla ----------
  {
    const ev = [];
    let direct = false;
    let version = null;
    let versionStatus = null;
    let versionSource = null;
    const gen = generators.find((g) => /joomla/i.test(g));
    if (gen) { direct = true; ev.push('Meta generator: "' + gen + '"'); }
    const enc = headers['x-content-encoded-by'];
    if (enc && /joomla/i.test(enc)) {
      direct = true;
      ev.push('Cabecera X-Content-Encoded-By: ' + enc);
      const v = cleanVersion(enc);
      if (v) { version = v; versionStatus = 'Confirmado'; versionSource = 'Cabecera X-Content-Encoded-By declarada por el servidor'; }
    }
    const paths = hrefs.filter((u) => /\/(media\/(jui|system|vendor|templates)|templates\/[^/]+\/)/i.test(u) && /\/media\/(jui|system)\//i.test(u));
    if (paths.length) ev.push('Recursos bajo /media/jui/ o /media/system/ (' + paths.length + ')');
    if (direct) techs.push(tech('joomla', 'Joomla', 'CMS', 'Confirmado', 'Alta', { version, versionStatus, versionSource, evidence: ev }));
    else if (paths.length) techs.push(tech('joomla', 'Joomla', 'CMS', 'Probable', 'Baja', { evidence: ev }));
    else techs.push(tech('joomla', 'Joomla', 'CMS', 'No detectado', 'Baja', { note: 'No se observaron indicadores públicos. La ausencia de señales no demuestra que no esté presente.' }));
  }

  // ---------- Drupal ----------
  {
    const ev = [];
    let direct = false;
    let version = null;
    let versionStatus = null;
    let versionSource = null;
    const gen = generators.find((g) => /drupal/i.test(g));
    const xgen = headers['x-generator'];
    [gen && 'Meta generator: "' + gen + '"', xgen && /drupal/i.test(xgen) && 'Cabecera X-Generator: ' + xgen].filter(Boolean).forEach((e) => { ev.push(e); direct = true; });
    const dv = cleanVersion(gen || (xgen && /drupal/i.test(xgen) ? xgen : ''));
    const major = String(gen || xgen || '').match(/Drupal\s+(\d+)/i);
    if (dv && /\./.test(dv)) { version = dv; versionStatus = 'Confirmado'; versionSource = 'Declarada por el sitio'; }
    const paths = hrefs.filter((u) => /\/sites\/(default|all)\/(files|modules|themes)\//i.test(u) || /\/core\/(misc|assets|themes)\//i.test(u));
    if (paths.length) ev.push('Rutas típicas de Drupal (/sites/default/files, /core/...) (' + paths.length + ')');
    if (headers['x-drupal-cache'] || headers['x-drupal-dynamic-cache']) { ev.push('Cabeceras X-Drupal-Cache'); direct = true; }
    const note = major && !version ? 'Solo se publica la versión mayor (Drupal ' + major[1] + '); no basta para consultar vulnerabilidades por versión.' : '';
    if (direct) techs.push(tech('drupal', 'Drupal', 'CMS', 'Confirmado', 'Alta', { version, versionStatus, versionSource, evidence: ev, note }));
    else if (paths.length) techs.push(tech('drupal', 'Drupal', 'CMS', 'Probable', 'Baja', { evidence: ev }));
    else techs.push(tech('drupal', 'Drupal', 'CMS', 'No detectado', 'Baja', { note: 'No se observaron indicadores públicos. La ausencia de señales no demuestra que no esté presente.' }));
  }

  // ---------- Otros CMS / plataformas ----------
  const others = [
    { id: 'shopify', name: 'Shopify', test: () => hrefs.some((u) => /cdn\.shopify\.com/i.test(u)) || headers['x-shopid'] || /shopify/i.test(headers['x-powered-by'] || ''), ev: 'Recursos de cdn.shopify.com o cabeceras de Shopify' },
    { id: 'wix', name: 'Wix', test: () => headers['x-wix-request-id'] || hrefs.some((u) => /static\.parastorage\.com|wixstatic\.com/i.test(u)), ev: 'Recursos de Wix o cabecera X-Wix-Request-Id' },
    { id: 'squarespace', name: 'Squarespace', test: () => generators.some((g) => /squarespace/i.test(g)) || hrefs.some((u) => /static1\.squarespace\.com/i.test(u)), ev: 'Meta generator o recursos de Squarespace' },
    { id: 'magento', name: 'Magento', test: () => /Mage\.Cookies|\/static\/(version\d+|frontend)\//i.test(html) || cookieNames.includes('mage-cache-sessid'), ev: 'Rutas /static/frontend o variables Mage.Cookies' },
    { id: 'prestashop', name: 'PrestaShop', test: () => generators.some((g) => /prestashop/i.test(g)) || /prestashop/i.test(html.slice(0, 200000)) && /\/modules\/ps_/i.test(html), ev: 'Meta generator o módulos ps_*' },
    { id: 'ghost', name: 'Ghost', test: () => generators.some((g) => /^ghost/i.test(g)), ev: 'Meta generator' },
    { id: 'typo3', name: 'TYPO3', test: () => generators.some((g) => /typo3/i.test(g)) || hrefs.some((u) => /\/typo3(conf|temp)\//i.test(u)), ev: 'Meta generator o rutas /typo3conf/' },
    { id: 'laravel', name: 'Laravel (framework PHP)', test: () => cookieNames.includes('laravel_session'), ev: 'Cookie laravel_session', probable: true },
    { id: 'aspnet', name: 'ASP.NET', test: () => headers['x-aspnet-version'] || /ASP\.NET/i.test(powered), ev: 'Cabecera X-AspNet-Version / X-Powered-By' }
  ];
  others.forEach((o) => {
    if (o.test()) {
      const t = tech(o.id, o.name, 'CMS/Plataforma', o.probable ? 'Probable' : 'Confirmado', o.probable ? 'Media' : 'Media', { evidence: [o.ev] });
      if (o.id === 'aspnet' && headers['x-aspnet-version']) {
        t.version = cleanVersion(headers['x-aspnet-version']);
        t.versionStatus = 'Confirmado';
        t.versionSource = 'Cabecera X-AspNet-Version';
        infoDisclosure.push({ what: 'Versión de ASP.NET expuesta', evidence: 'X-AspNet-Version: ' + headers['x-aspnet-version'] });
      }
      techs.push(t);
    }
  });

  // ---------- PHP ----------
  const php = { status: 'No detectado', confidence: 'Baja', version: null, versionStatus: null, versionSource: null, evidence: [], distroBuild: false, note: '' };
  {
    const ev = [];
    let direct = false;
    const pm = powered.match(/PHP\/(\d+\.\d+(?:\.\d+)?)([^\s,;]*)/i);
    const sm = server.match(/PHP\/(\d+\.\d+(?:\.\d+)?)([^\s,;]*)/i);
    const hit = pm || sm;
    if (hit) {
      direct = true;
      php.version = hit[1];
      php.versionStatus = 'Confirmado';
      php.versionSource = (pm ? 'Cabecera X-Powered-By' : 'Cabecera Server') + ' declarada por el servidor (' + (pm ? powered : server) + ')';
      ev.push((pm ? 'X-Powered-By: ' : 'Server: ') + (pm ? powered : server));
      if (/ubuntu|debian|deb\d|el\d|~|\+/i.test(hit[2] || '') || /ubuntu|debian/i.test(server)) php.distroBuild = true;
      infoDisclosure.push({ what: 'Versión de PHP expuesta en cabeceras HTTP', evidence: (pm ? 'X-Powered-By: ' : 'Server: ') + (pm ? powered : server) });
    } else if (/(^|[,\s])PHP\b/i.test(powered)) {
      direct = true;
      ev.push('X-Powered-By: ' + powered);
    }
    if (cookieNames.includes('PHPSESSID')) ev.push('Cookie de sesión PHPSESSID');
    const phpLinks = allUrls.filter((u) => /\.php(\?|#|$)/i.test(u));
    if (phpLinks.length) ev.push('Enlaces/recursos que terminan en .php (' + phpLinks.length + ')');
    const cmsNeedsPhp = techs.filter((t) => ['wordpress', 'joomla', 'drupal'].includes(t.id) && t.status === 'Confirmado');
    if (direct) {
      php.status = 'Confirmado';
      php.confidence = php.version ? 'Media' : 'Media';
    } else if (cookieNames.includes('PHPSESSID') || phpLinks.length) {
      php.status = 'Probable';
      php.confidence = 'Media';
    } else if (cmsNeedsPhp.length) {
      php.status = 'Probable';
      php.confidence = 'Baja';
      ev.push(cmsNeedsPhp.map((t) => t.name).join(', ') + ' requiere PHP (inferencia indirecta; no permite conocer la versión)');
    }
    php.evidence = ev;
    if (php.status === 'No detectado') php.note = 'No se observaron indicadores públicos de PHP. La ausencia de señales no demuestra que no se utilice.';
    if (php.status !== 'No detectado' && !php.version) {
      php.note = 'No se ha podido confirmar la versión de PHP desde el análisis externo. Se necesita una comprobación autorizada del servidor para verificarla.';
    }
    if (php.version && php.distroBuild) {
      php.note = 'La versión parece de una distribución Linux; estas distribuciones suelen retroportar correcciones de seguridad sin cambiar el número de versión, por lo que los CVE listados pueden no aplicar.';
    }
    techs.push(tech('php', 'PHP', 'Lenguaje de servidor', php.status, php.confidence, {
      version: php.version, versionStatus: php.versionStatus, versionSource: php.versionSource, evidence: ev, note: php.note
    }));
  }

  // ---------- Servidor web ----------
  if (server) {
    const m = server.match(/^([A-Za-z][A-Za-z0-9 _.-]*?)(?:\/([\w.+~-]+))?(?:\s|\(|$)/);
    const name = m ? m[1].trim() : server.slice(0, 40);
    const ver = m && m[2] ? cleanVersion(m[2]) : null;
    const t = tech('server', 'Servidor web: ' + name, 'Servidor', 'Confirmado', 'Media', {
      version: ver, versionStatus: ver ? 'Confirmado' : null,
      versionSource: ver ? 'Cabecera Server declarada por el servidor' : null,
      evidence: ['Server: ' + server.slice(0, 120)],
      note: 'Valor declarado por el propio servidor; puede estar ocultado o modificado por un proxy.'
    });
    t.product = /^apache/i.test(name) ? 'apache' : (/^nginx/i.test(name) ? 'nginx' : null);
    techs.push(t);
    if (ver) infoDisclosure.push({ what: 'Versión del servidor web expuesta en la cabecera Server', evidence: 'Server: ' + server.slice(0, 120) });
  } else {
    techs.push(tech('server', 'Servidor web', 'Servidor', 'Desconocido', 'Baja', { note: 'El servidor no publica la cabecera Server (o un proxy la elimina).' }));
  }

  // ---------- Otras cabeceras técnicas ----------
  if (powered && !php.version && !/PHP/i.test(powered) && !/ASP\.NET/i.test(powered)) {
    techs.push(tech('xpoweredby', 'X-Powered-By: ' + powered.slice(0, 50), 'Cabecera técnica', 'Confirmado', 'Media', { evidence: ['X-Powered-By: ' + powered.slice(0, 120)] }));
    infoDisclosure.push({ what: 'Tecnología del servidor expuesta en X-Powered-By', evidence: 'X-Powered-By: ' + powered.slice(0, 120) });
  }

  // ---------- Frontend ----------
  {
    const jq = [];
    assets.filter((a) => a.tag === 'script').forEach((a) => {
      const u = a.url;
      let v = null;
      let m = u.match(/jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min|\.slim)*\.js/i);
      if (m) v = m[1];
      if (!v) { m = u.match(/\/jquery\/(\d+\.\d+(?:\.\d+)?)\//i); if (m) v = m[1]; }
      if (!v && /\/jquery(\.min)?\.js/i.test(u.split('?')[0])) {
        m = u.match(/[?&]ver=(\d+\.\d+(?:\.\d+)?)/);
        if (m) v = m[1];
        else v = '';
      }
      if (v !== null) jq.push({ v, u });
    });
    if (jq.length) {
      const withV = jq.find((x) => x.v);
      techs.push(tech('jquery', 'jQuery', 'Frontend', 'Confirmado', 'Media', {
        version: withV ? withV.v : null,
        versionStatus: withV ? 'Probable' : null,
        versionSource: withV ? 'Número de versión en el nombre/URL del script; no se verificó el contenido del archivo' : null,
        evidence: jq.slice(0, 3).map((x) => 'Script: ' + x.u.slice(0, 160))
      }));
    }
    if (/__NEXT_DATA__|\/_next\/static\//i.test(html) || /next\.js/i.test(powered)) techs.push(tech('nextjs', 'Next.js (React)', 'Frontend', 'Confirmado', 'Media', { evidence: ['Recursos /_next/ o __NEXT_DATA__'] }));
    else if (/data-reactroot|react(?:-dom)?(?:\.production)?(?:\.min)?\.js/i.test(html)) techs.push(tech('react', 'React', 'Frontend', 'Probable', 'Baja', { evidence: ['Indicadores de React en el HTML'] }));
    if (ngVersion) techs.push(tech('angular', 'Angular', 'Frontend', 'Confirmado', 'Alta', { version: ngVersion, versionStatus: 'Confirmado', versionSource: 'Atributo ng-version del HTML', evidence: ['ng-version="' + ngVersion + '"'] }));
    if (/\/_nuxt\//i.test(html)) techs.push(tech('nuxt', 'Nuxt (Vue)', 'Frontend', 'Confirmado', 'Media', { evidence: ['Recursos /_nuxt/'] }));
    else if (/data-v-[0-9a-f]{6,8}|vue(?:\.runtime)?(?:\.min)?\.js/i.test(html)) techs.push(tech('vue', 'Vue.js', 'Frontend', 'Probable', 'Baja', { evidence: ['Indicadores de Vue en el HTML'] }));
    if (hrefs.some((u) => /bootstrap(?:\.min)?\.(css|js)|bootstrap@/i.test(u))) techs.push(tech('bootstrap', 'Bootstrap', 'Frontend', 'Confirmado', 'Media', { evidence: ['Recurso bootstrap en enlaces/scripts'] }));
  }

  // ---------- CDN / WAF ----------
  {
    const cdn = [];
    if (headers['cf-ray'] || /cloudflare/i.test(server)) cdn.push(['Cloudflare', 'Cabecera cf-ray / Server: cloudflare']);
    if (headers['x-amz-cf-id'] || /cloudfront/i.test(headers.via || '')) cdn.push(['Amazon CloudFront', 'Cabecera x-amz-cf-id / Via']);
    if (headers['x-fastly-request-id'] || /fastly/i.test(headers['x-served-by'] || '')) cdn.push(['Fastly', 'Cabeceras de Fastly']);
    if (/akamai/i.test(server) || headers['x-akamai-transformed']) cdn.push(['Akamai', 'Cabecera Akamai']);
    if (headers['x-sucuri-id'] || /sucuri/i.test(server)) cdn.push(['Sucuri WAF', 'Cabecera x-sucuri-id']);
    if (headers['x-azure-ref']) cdn.push(['Azure Front Door', 'Cabecera x-azure-ref']);
    if (headers['x-vercel-id']) cdn.push(['Vercel', 'Cabecera x-vercel-id']);
    if (headers['x-nf-request-id']) cdn.push(['Netlify', 'Cabecera x-nf-request-id']);
    if (headers['x-cache'] && /varnish/i.test(headers.via || '')) cdn.push(['Varnish (caché)', 'Cabeceras Via/X-Cache']);
    cdn.forEach(([n, e]) => techs.push(tech('cdn-' + n.toLowerCase().replace(/\W+/g, '-'), n, 'CDN / protección', 'Confirmado', 'Media', { evidence: [e] })));
  }

  return { technologies: techs, php, infoDisclosure, assets, generators };
}

/** Contenido mixto: recursos http:// dentro de una página servida por HTTPS. */
function findMixedContent(assets) {
  const active = [];
  const passive = [];
  (assets || []).forEach((a) => {
    if (!/^http:\/\//i.test(a.url)) return;
    const isActive =
      a.tag === 'script' || a.tag === 'iframe' || a.tag === 'embed' || a.tag === 'object' ||
      (a.tag === 'form') || (a.tag === 'link' && /stylesheet|preload|modulepreload/.test(a.rel));
    const isPassive = ['img', 'audio', 'video', 'source'].includes(a.tag);
    if (isActive) active.push(a.tag + ': ' + a.url.slice(0, 120));
    else if (isPassive) passive.push(a.tag + ': ' + a.url.slice(0, 120));
  });
  return { active, passive };
}

module.exports = { detectTechnologies, extractFromHtml, findMixedContent, cleanVersion };
