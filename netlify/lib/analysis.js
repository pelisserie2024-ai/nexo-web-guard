'use strict';
/**
 * Orquestación del análisis NO intrusivo de un sitio web.
 * Solicitudes: robots.txt, página principal (con redirecciones) y una comprobación HTTP->HTTPS.
 * Nunca se prueban rutas adicionales, ni formularios, ni credenciales, ni puertos.
 */
const crypto = require('crypto');
const { validateTarget } = require('./net-guard');
const { robotsAllows } = require('./robots');
const { detectTechnologies, findMixedContent } = require('./detect');
const { analyzeSecurityHeaders } = require('./headers-analysis');
const { phpSupportStatus } = require('./php-support');

const APP_VERSION = '1.4.0';
const MAX_REQUESTS = 10;
const TOTAL_MS = 8500;
const CMS_IDS = ['wordpress', 'joomla', 'drupal'];

const SOURCES = [
  { title: 'NVD - API de vulnerabilidades (NIST)', url: 'https://nvd.nist.gov/developers/vulnerabilities' },
  { title: 'PHP - Versiones con soporte', url: 'https://www.php.net/supported-versions.php' },
  { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
  { title: 'MDN - Content-Security-Policy', url: 'https://developer.mozilla.org/docs/Web/HTTP/CSP' },
  { title: 'RFC 6797 - HTTP Strict Transport Security', url: 'https://datatracker.ietf.org/doc/html/rfc6797' },
  { title: 'WordPress - Noticias de seguridad', url: 'https://wordpress.org/news/category/security/' },
  { title: 'Joomla - Centro de seguridad', url: 'https://developer.joomla.org/security-centre.html' },
  { title: 'Drupal - Avisos de seguridad', url: 'https://www.drupal.org/security' }
];

const NOT_PERFORMED_BASE = [
  'Escaneo de puertos o servicios distintos de HTTP/HTTPS (excluido por diseño).',
  'Pruebas de explotación, fuerza bruta e intentos de inicio de sesión (excluidos por diseño).',
  'Enumeración de directorios, archivos ocultos o plugins (excluida por diseño).',
  'Verificación de versiones y parches desde el propio servidor (requiere acceso autorizado).',
  'Análisis completo de la configuración TLS (protocolos y suites soportados): no verificable con las comprobaciones disponibles.',
  'Análisis de contenido generado por JavaScript tras la carga (solo se examina el HTML recibido).',
  'Revisión de código, base de datos, permisos de archivos y configuración interna del servidor.'
];

const LIMITATIONS_BASE = [
  'El análisis es externo y pasivo: solo observa lo que el sitio publica en una solicitud a su página principal.',
  'La ausencia de una señal no significa que la tecnología no esté presente, y la presencia de una señal puede ser engañosa (cabeceras ocultadas o falsificadas, proxies, CDN).',
  'Las versiones obtenidas de cabeceras o del HTML son declaraciones del sitio y no se han verificado en el servidor.',
  'Las distribuciones de Linux pueden aplicar correcciones de seguridad sin cambiar el número de versión (retroportes).',
  'Un análisis externo no garantiza la ausencia de vulnerabilidades.'
];

function describeError(e) {
  const c = e && e.code;
  if (c === 'NWG_BLOCKED') return (e.message || 'Destino no permitido por la política de seguridad.');
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return 'No se pudo resolver el dominio (DNS).';
  if (c === 'ECONNREFUSED') return 'El servidor rechazó la conexión.';
  if (c === 'NWG_TIMEOUT' || c === 'ETIMEDOUT') return 'El servidor no respondió a tiempo.';
  if (c === 'ECONNRESET') return 'La conexión fue interrumpida por el servidor.';
  if (c === 'NWG_LIMIT') return 'Se alcanzó el límite de solicitudes por análisis.';
  if (c === 'NWG_REDIRECTS') return 'El sitio realiza demasiadas redirecciones.';
  if (c === 'ENETUNREACH' || c === 'EHOSTUNREACH') return 'No se pudo alcanzar la dirección del servidor.';
  return 'No se pudo completar la conexión con el sitio.';
}

function parseDate(s) {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

function commonName(x) {
  if (!x) return null;
  return x.CN || x.O || null;
}

function newReportId(now) {
  const d = now.toISOString().slice(0, 10).replace(/-/g, '');
  return 'NWG-' + d + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

async function runAnalysis(rawUrl, deps, opts) {
  const fetchFollow = (deps && deps.fetchFollow) || require('./safe-fetch').fetchFollow;
  const now = (opts && opts.now) ? opts.now() : new Date();
  const started = Date.now();
  const ctx = { budget: { used: 0, max: MAX_REQUESTS }, deadline: started + TOTAL_MS };

  const v = validateTarget(rawUrl);
  const result = {
    reportId: newReportId(now),
    appVersion: APP_VERSION,
    analyzedAt: now.toISOString(),
    requestedUrl: v.ok ? v.url.href : String(rawUrl || ''),
    host: v.ok ? v.host : null,
    status: 'completed', // completed | stopped | failed
    error: null,
    stoppedReason: null,
    finalUrl: null,
    httpStatus: null,
    redirects: [],
    https: { available: 'No verificable', state: 'No verificable con las comprobaciones disponibles', redirectsHttpToHttps: 'No verificable', certificate: null, tlsProtocol: null, notes: [] },
    robots: { checked: false, found: false, allowed: true },
    technologies: [],
    php: null,
    headers: [],
    cookies: [],
    findings: [],
    vulnLookups: [],
    vulnerabilities: [],
    vulnLookupErrors: [],
    notPerformed: NOT_PERFORMED_BASE.slice(),
    limitations: LIMITATIONS_BASE.slice(),
    sources: SOURCES,
    requests: { used: 0, max: MAX_REQUESTS }
  };
  if (!v.ok) {
    result.status = 'failed';
    result.error = v.error;
    return result;
  }

  let n = 0;
  const add = (f) => {
    n++;
    result.findings.push(Object.assign({
      id: 'NWG-F' + String(n).padStart(3, '0'), category: 'General', title: '', severity: 'Informativo',
      confidence: 'Media', evidence: [], source: 'Observación directa de la respuesta HTTP', description: '',
      recommendation: '', limitations: ''
    }, f));
  };
  const finish = () => {
    result.requests.used = ctx.budget.used;
    return result;
  };

  const startUrl = v.url;

  // 1) robots.txt
  try {
    const r = await fetchFollow(startUrl.origin + '/robots.txt', ctx, { maxRedirects: 2, maxBytes: 64 * 1024, timeoutMs: 3500 });
    result.robots.checked = true;
    if (r.response.status === 200) {
      result.robots.found = true;
      const path = (startUrl.pathname || '/') + (startUrl.search || '');
      if (!robotsAllows(r.response.body, path)) {
        result.robots.allowed = false;
        result.status = 'stopped';
        result.stoppedReason = 'El archivo robots.txt del sitio indica que no debe consultarse esta ruta; el análisis se detuvo por respeto a esa indicación.';
        result.limitations.push(result.stoppedReason);
        return finish();
      }
    }
  } catch (e) {
    if (e.code === 'NWG_BLOCKED') {
      result.status = 'failed';
      result.error = describeError(e);
      return finish();
    }
    result.robots.checked = false;
    result.limitations.push('No se pudo consultar robots.txt (' + describeError(e) + '); se continuó con la página principal.');
  }

  // 2) comprobación HTTP -> HTTPS en paralelo (solo si el usuario indicó https)
  let httpProbe = null;
  if (startUrl.protocol === 'https:') {
    httpProbe = fetchFollow('http://' + startUrl.hostname + '/', ctx, { follow: false, readBody: false, timeoutMs: 3500 })
      .then((r) => ({ ok: true, r }))
      .catch((e) => ({ ok: false, e }));
  }

  // 3) página principal
  let main = null;
  let httpsFailure = null;
  try {
    main = await fetchFollow(startUrl.href, ctx, { maxBytes: 600 * 1024 });
  } catch (e) {
    if (e.code === 'NWG_BLOCKED' || e.code === 'NWG_LIMIT') {
      result.status = 'failed';
      result.error = describeError(e);
      return finish();
    }
    if (startUrl.protocol === 'https:') {
      httpsFailure = describeError(e);
      try {
        main = await fetchFollow('http://' + startUrl.hostname + startUrl.pathname + startUrl.search, ctx, { maxBytes: 600 * 1024 });
      } catch (e2) {
        result.status = 'failed';
        result.https.available = 'No';
        result.https.state = 'No se pudo establecer conexión HTTPS: ' + httpsFailure;
        result.error = 'No se pudo conectar con el sitio. HTTPS: ' + httpsFailure + ' HTTP: ' + describeError(e2);
        return finish();
      }
    } else {
      result.status = 'failed';
      result.error = 'No se pudo conectar con el sitio: ' + describeError(e);
      return finish();
    }
  }

  const resp = main.response;
  const finalUrl = new URL(main.finalUrl);
  result.finalUrl = finalUrl.href;
  result.httpStatus = resp.status;
  result.redirects = main.chain;
  const isHttps = finalUrl.protocol === 'https:';

  if (resp.status === 429 || resp.status === 503) {
    result.status = 'stopped';
    result.stoppedReason = 'El sitio respondió HTTP ' + resp.status + ' (límite de solicitudes o servicio no disponible); el análisis se detuvo para no sobrecargarlo.';
    result.limitations.push(result.stoppedReason);
    return finish();
  }

  const headers = resp.headers || {};
  const html = resp.body || '';

  // ----- HTTPS y certificado -----
  if (isHttps) {
    result.https.available = 'Sí';
    result.https.state = 'La página principal se sirvió por HTTPS.';
    if (resp.tls) {
      const c = resp.tls.cert || {};
      const to = parseDate(c.validTo);
      const from = parseDate(c.validFrom);
      const daysLeft = to ? Math.floor((to.getTime() - now.getTime()) / 86400000) : null;
      const san = String(c.subjectAltName || '').split(',').map((x) => x.trim().replace(/^DNS:/, '')).filter(Boolean).slice(0, 10);
      result.https.certificate = {
        validForClient: main.certError ? false : !!resp.tls.authorized,
        validationError: main.certError ? (main.certError.code || main.certError.message) : (resp.tls.authorizationError || null),
        subject: commonName(c.subject),
        issuer: commonName(c.issuer),
        validFrom: from ? from.toISOString() : null,
        validTo: to ? to.toISOString() : null,
        daysLeft,
        altNames: san
      };
      result.https.tlsProtocol = resp.tls.protocol || null;
      result.https.notes.push('Protocolo TLS negociado: ' + (resp.tls.protocol || 'desconocido') + '. La configuración completa (suites y protocolos admitidos) no es verificable con las comprobaciones disponibles.');
    }
    if (main.certError) {
      result.https.state = 'HTTPS disponible, pero el certificado no superó la validación.';
      add({
        category: 'HTTPS y certificado', title: 'El certificado TLS no superó la validación', severity: 'Alto', confidence: 'Alta',
        evidence: ['Error de validación observado: ' + (main.certError.code || main.certError.message)],
        description: 'Los navegadores mostrarán advertencias de seguridad y los usuarios no pueden confiar plenamente en la identidad del sitio.',
        recommendation: 'Instalar un certificado válido, emitido por una autoridad reconocida, que cubra el dominio y su cadena completa.',
        limitations: 'La validación se hizo desde un único punto de red; problemas de cadena intermedia pueden variar según el cliente.'
      });
    } else if (result.https.certificate && result.https.certificate.daysLeft !== null) {
      const d = result.https.certificate.daysLeft;
      if (d < 0) {
        add({ category: 'HTTPS y certificado', title: 'Certificado caducado', severity: 'Alto', confidence: 'Alta',
          evidence: ['Fecha de expiración: ' + result.https.certificate.validTo], description: 'El certificado ya expiró.',
          recommendation: 'Renovar el certificado de inmediato y automatizar la renovación.' });
      } else if (d <= 14) {
        add({ category: 'HTTPS y certificado', title: 'El certificado caduca en ' + d + ' días', severity: 'Medio', confidence: 'Alta',
          evidence: ['Fecha de expiración: ' + result.https.certificate.validTo], description: 'La caducidad es inminente.',
          recommendation: 'Renovar el certificado y verificar la renovación automática.' });
      } else if (d <= 30) {
        add({ category: 'HTTPS y certificado', title: 'El certificado caduca en ' + d + ' días', severity: 'Bajo', confidence: 'Alta',
          evidence: ['Fecha de expiración: ' + result.https.certificate.validTo], description: 'Conviene planificar la renovación.',
          recommendation: 'Programar la renovación o confirmar que es automática.' });
      } else {
        add({ category: 'HTTPS y certificado', title: 'Certificado válido y vigente', severity: 'Informativo', confidence: 'Alta',
          evidence: ['Válido hasta ' + result.https.certificate.validTo + ' (' + d + ' días)', 'Emisor: ' + (result.https.certificate.issuer || 'desconocido')],
          description: 'El certificado superó la validación del cliente y no está próximo a caducar.', recommendation: 'Mantener la renovación automática.',
          limitations: 'Esto no demuestra que la configuración TLS completa sea segura.' });
      }
    }
  } else {
    // Final en HTTP
    const firstHop = main.chain[0] || {};
    if (httpsFailure) {
      result.https.available = 'No';
      result.https.state = 'No se pudo establecer HTTPS: ' + httpsFailure;
      add({
        category: 'HTTPS y certificado', title: 'HTTPS no disponible o con fallos de conexión', severity: 'Alto', confidence: 'Media',
        evidence: ['Fallo al conectar por HTTPS: ' + httpsFailure, 'El sitio sí respondió por HTTP'],
        description: 'La comunicación con el sitio no está cifrada; los datos podrían ser leídos o modificados en tránsito.',
        recommendation: 'Habilitar HTTPS con un certificado válido y redirigir todo el tráfico HTTP a HTTPS.',
        limitations: 'Un fallo transitorio de red también podría producir este resultado; repita el análisis para confirmarlo.'
      });
    } else if (startUrl.protocol === 'http:') {
      // el usuario indicó http: sondear https
      try {
        const p = await fetchFollow('https://' + startUrl.hostname + '/', ctx, { maxRedirects: 1, readBody: false, timeoutMs: 3500 });
        result.https.available = 'Sí';
        result.https.state = 'HTTPS responde, pero la ruta analizada terminó en HTTP.';
        if (p.certError) result.https.notes.push('El certificado no superó la validación (' + (p.certError.code || p.certError.message) + ').');
        add({
          category: 'HTTPS y certificado', title: 'El sitio termina sirviéndose por HTTP sin cifrar', severity: 'Medio', confidence: 'Alta',
          evidence: ['La solicitud inicial a ' + startUrl.href + ' finalizó en ' + finalUrl.href], description: 'El contenido llega sin cifrar aunque el sitio admite HTTPS.',
          recommendation: 'Redirigir HTTP a HTTPS de forma permanente (301/308) y activar HSTS.'
        });
      } catch (e) {
        result.https.available = 'No';
        result.https.state = 'No se pudo establecer HTTPS: ' + describeError(e);
        add({
          category: 'HTTPS y certificado', title: 'HTTPS no disponible', severity: 'Alto', confidence: 'Media',
          evidence: ['Fallo de conexión HTTPS: ' + describeError(e)], description: 'El sitio solo responde sin cifrado.',
          recommendation: 'Habilitar HTTPS con un certificado válido y redirigir todo el tráfico HTTP a HTTPS.',
          limitations: 'Un fallo transitorio de red podría producir este resultado.'
        });
      }
    }
    if (firstHop.status && !result.https.available) result.https.available = 'No verificable';
  }

  // Redirección HTTP -> HTTPS
  if (isHttps && startUrl.protocol === 'http:') {
    result.https.redirectsHttpToHttps = 'Sí';
  } else if (isHttps && httpProbe) {
    const pr = await httpProbe;
    if (pr.ok) {
      const st = pr.r.response.status;
      const loc = String(pr.r.response.headers.location || '');
      if ([301, 302, 303, 307, 308].includes(st) && /^https:\/\//i.test(loc)) {
        result.https.redirectsHttpToHttps = 'Sí';
        result.https.notes.push('http://' + startUrl.hostname + '/ redirige a HTTPS (HTTP ' + st + ').');
        if (st !== 301 && st !== 308) result.https.notes.push('La redirección es temporal (' + st + '); se recomienda una redirección permanente.');
      } else if (st >= 200 && st < 300) {
        result.https.redirectsHttpToHttps = 'No';
        add({
          category: 'HTTPS y certificado', title: 'HTTP no redirige a HTTPS', severity: 'Medio', confidence: 'Alta',
          evidence: ['GET http://' + startUrl.hostname + '/ respondió HTTP ' + st + ' sin redirigir a HTTPS'],
          description: 'Quien entre por HTTP seguirá usando una conexión sin cifrar.',
          recommendation: 'Configurar una redirección permanente de HTTP a HTTPS y activar HSTS.',
          limitations: 'Solo se comprobó la ruta raíz del dominio.'
        });
      } else {
        result.https.redirectsHttpToHttps = 'No verificable';
        result.https.notes.push('La comprobación HTTP respondió con el estado ' + st + '; no concluyente.');
      }
    } else {
      result.https.redirectsHttpToHttps = 'No verificable';
      result.https.notes.push('No se pudo comprobar el puerto 80: ' + describeError(pr.e));
    }
  }

  // Redirecciones inesperadas
  {
    const hops = main.chain;
    for (let i = 0; i < hops.length - 1; i++) {
      try {
        const a = new URL(hops[i].url);
        const b = new URL(hops[i + 1].url);
        if (a.protocol === 'https:' && b.protocol === 'http:') {
          add({ category: 'Redirecciones', title: 'Redirección de HTTPS a HTTP (degradación)', severity: 'Alto', confidence: 'Alta',
            evidence: [hops[i].url + ' -> ' + hops[i + 1].url], description: 'Una redirección saca al usuario de una conexión cifrada.',
            recommendation: 'Corregir la configuración para que las redirecciones mantengan HTTPS.' });
        }
        const strip = (h) => h.replace(/^www\./, '');
        if (strip(a.hostname) !== strip(b.hostname)) {
          add({ category: 'Redirecciones', title: 'Redirección hacia otro dominio', severity: 'Informativo', confidence: 'Alta',
            evidence: [a.hostname + ' -> ' + b.hostname], description: 'Puede ser legítima (marca, migración), pero conviene confirmar que es la esperada.',
            recommendation: 'Verificar que el dominio de destino es el previsto y que nadie ha modificado la configuración.',
            limitations: 'Una redirección a otro dominio no implica por sí sola un compromiso del sitio.' });
        }
      } catch (e) { /* ignora */ }
    }
  }

  // ----- Cabeceras de seguridad -----
  result.headers = analyzeSecurityHeaders(headers, { isHttps });
  result.headers.forEach((h) => {
    if (h.assessment === 'Ausente' || h.assessment === 'Revisar') {
      add({
        category: 'Cabeceras de seguridad', title: h.assessment === 'Ausente' ? 'Cabecera ausente: ' + h.header : 'Cabecera a revisar: ' + h.header,
        severity: h.severity, confidence: 'Alta',
        evidence: [h.present ? h.header + ': ' + h.value : 'No se observó la cabecera ' + h.header + ' en la respuesta de ' + result.finalUrl, h.note].filter(Boolean),
        source: 'Cabeceras de la respuesta HTTP; referencia: OWASP Secure Headers Project',
        description: h.risk, recommendation: h.recommendation,
        limitations: 'Evaluación contextual: la ausencia no equivale a una vulnerabilidad. Solo se analizó la respuesta de la página principal.'
      });
    }
  });

  // ----- Cookies -----
  {
    const raw = [].concat(headers['set-cookie'] || []).slice(0, 20);
    result.cookies = raw.map((c) => {
      const parts = String(c).split(';').map((x) => x.trim());
      const name = (parts[0] || '').split('=')[0];
      const lower = parts.slice(1).map((x) => x.toLowerCase());
      return {
        name: name.slice(0, 60),
        secure: lower.includes('secure'),
        httpOnly: lower.includes('httponly'),
        sameSite: ((lower.find((x) => x.startsWith('samesite=')) || '').split('=')[1]) || null
      };
    });
    const noSecure = result.cookies.filter((c) => !c.secure).map((c) => c.name);
    const noHttpOnly = result.cookies.filter((c) => !c.httpOnly).map((c) => c.name);
    if (isHttps && noSecure.length) {
      add({ category: 'Cookies', title: 'Cookies sin atributo Secure', severity: 'Bajo', confidence: 'Alta',
        evidence: ['Cookies sin Secure: ' + noSecure.join(', ') + ' (solo se muestran nombres y atributos)'],
        description: 'Una cookie sin Secure puede enviarse por conexiones HTTP sin cifrar.',
        recommendation: 'Añadir el atributo Secure (y HttpOnly/SameSite cuando corresponda) a las cookies de sesión.',
        limitations: 'Cookies de preferencias o analítica pueden no requerir estos atributos.' });
    }
    if (noHttpOnly.length) {
      add({ category: 'Cookies', title: 'Cookies sin atributo HttpOnly', severity: 'Bajo', confidence: 'Alta',
        evidence: ['Cookies sin HttpOnly: ' + noHttpOnly.join(', ')],
        description: 'Las cookies accesibles desde JavaScript pueden ser robadas si existe un fallo XSS.',
        recommendation: 'Marcar como HttpOnly las cookies de sesión y autenticación.',
        limitations: 'Algunas cookies están pensadas para ser leídas por scripts legítimos.' });
    }
  }

  // ----- Contenido mixto -----
  let htmlAssets = [];
  const det = detectTechnologies({ headers, html, finalUrl: result.finalUrl });
  htmlAssets = det.assets;
  if (isHttps && html) {
    const mixed = findMixedContent(htmlAssets);
    if (mixed.active.length) {
      add({ category: 'Contenido mixto', title: 'Contenido activo cargado por HTTP en una página HTTPS', severity: 'Medio', confidence: 'Alta',
        evidence: mixed.active.slice(0, 5), source: 'HTML de la página principal',
        description: 'Scripts, estilos, marcos o formularios cargados por HTTP pueden ser alterados en tránsito.',
        recommendation: 'Cargar todos los recursos por HTTPS (o rutas relativas) y activar la directiva CSP upgrade-insecure-requests.',
        limitations: 'Solo se analiza el HTML inicial; los recursos añadidos por JavaScript no se revisan.' });
    }
    if (mixed.passive.length) {
      add({ category: 'Contenido mixto', title: 'Contenido pasivo (imágenes/medios) cargado por HTTP', severity: 'Bajo', confidence: 'Alta',
        evidence: mixed.passive.slice(0, 5), source: 'HTML de la página principal',
        description: 'Los recursos pasivos por HTTP degradan la protección de la página.',
        recommendation: 'Servir imágenes y medios por HTTPS.', limitations: 'Solo se analiza el HTML inicial.' });
    }
  }

  // ----- Tecnologías -----
  result.technologies = det.technologies;
  result.php = Object.assign({}, det.php, { support: null, message: null });
  det.infoDisclosure.forEach((d) => {
    add({ category: 'Exposición de información técnica', title: d.what, severity: 'Bajo', confidence: 'Alta',
      evidence: [d.evidence], description: 'Publicar versiones facilita a un atacante la búsqueda de fallos conocidos; no es una vulnerabilidad por sí misma.',
      recommendation: 'Ocultar o minimizar las cabeceras y metadatos que revelan versiones (por ejemplo, expose_php=Off, ServerTokens Prod, server_tokens off).',
      limitations: 'Ocultar versiones no sustituye a mantener el software actualizado.' });
  });

  // PHP
  const phpT = det.technologies.find((t) => t.id === 'php');
  if (result.php.version) {
    const sup = phpSupportStatus(result.php.version, now);
    result.php.support = sup;
    if (sup.status === 'sin_soporte') {
      result.php.message = 'La versión de PHP declarada (' + result.php.version + ') ya no recibe soporte de seguridad oficial. ' + sup.note;
      add({ category: 'PHP', title: 'Versión de PHP declarada sin soporte de seguridad (' + result.php.version + ')', severity: 'Alto', confidence: 'Media',
        evidence: [result.php.versionSource, sup.note], source: 'Cabeceras HTTP; ciclo de vida: php.net/supported-versions.php',
        description: 'Las versiones sin soporte no reciben correcciones de seguridad oficiales.',
        recommendation: 'Actualizar a una rama de PHP con soporte activo (ver php.net/supported-versions.php) tras probar la compatibilidad.',
        limitations: 'La versión es la que el servidor declara en cabeceras; puede ser engañosa. ' + (result.php.distroBuild ? 'Parece un paquete de distribución Linux que podría tener parches retroportados. ' : '') + 'Se necesita una comprobación autorizada del servidor para confirmarla.' });
    } else if (sup.status === 'soporte_seguridad') {
      result.php.message = 'La versión de PHP declarada (' + result.php.version + ') figura con soporte de seguridad. ' + sup.note;
      add({ category: 'PHP', title: 'Versión de PHP declarada: ' + result.php.version, severity: sup.daysLeft <= 120 ? 'Bajo' : 'Informativo', confidence: 'Media',
        evidence: [result.php.versionSource, sup.note], source: 'Cabeceras HTTP; ciclo de vida: php.net/supported-versions.php',
        description: sup.daysLeft <= 120 ? 'El fin del soporte de seguridad se acerca.' : 'La rama declarada figura con soporte de seguridad en la tabla consultada.',
        recommendation: 'Mantener PHP actualizado a la última versión de parche de la rama y planificar la migración antes del fin de soporte.',
        limitations: 'Que la rama tenga soporte no implica que la versión de parche instalada esté al día.' });
    } else {
      result.php.message = 'Versión declarada ' + result.php.version + '. ' + sup.note;
    }
  } else if (result.php.status === 'No detectado') {
    result.php.message = result.php.note;
  } else {
    result.php.message = 'No se ha podido confirmar la versión de PHP desde el análisis externo. Se necesita una comprobación autorizada del servidor para verificarla.';
  }

  // CMS detectados
  det.technologies.filter((t) => CMS_IDS.includes(t.id) && t.status !== 'No detectado').forEach((t) => {
    add({ category: 'CMS', title: t.name + (t.version ? ' ' + t.version : '') + ' (' + t.status + ')', severity: 'Informativo', confidence: t.confidence,
      evidence: t.evidence.concat(t.versionSource ? ['Versión: ' + t.versionSource] : []),
      description: t.version ? 'Versión identificada: ' + t.version + (t.versionStatus === 'Probable' ? ' (indicador indirecto, no verificado).' : '.') : 'No se pudo identificar una versión verificable desde el exterior.',
      recommendation: 'Mantener el núcleo, temas y plugins actualizados y consultar los avisos de seguridad oficiales del proyecto.',
      limitations: 'No se examinan plugins ni temas (análisis no intrusivo). Para conocer versiones reales se requiere acceso autorizado al panel o al servidor.' });
  });

  // jQuery desactualizado
  {
    const jq = det.technologies.find((t) => t.id === 'jquery');
    if (jq && jq.version) {
      const p = jq.version.split('.').map(Number);
      const old = p[0] < 3 || (p[0] === 3 && p[1] < 5);
      if (old) {
        add({ category: 'Componentes', title: 'jQuery ' + jq.version + ' aparentemente desactualizado', severity: 'Bajo', confidence: 'Media',
          evidence: jq.evidence.concat(['Versión: ' + jq.versionSource]), source: 'URL del script; ver consulta NVD más abajo',
          description: 'Las versiones de jQuery anteriores a 3.5.0 son antiguas y tienen vulnerabilidades públicas registradas.',
          recommendation: 'Actualizar jQuery a la última versión estable y probar plugins dependientes.',
          limitations: 'La versión se deduce del nombre del archivo; el contenido real podría diferir. El impacto depende de cómo la aplicación use la librería.' });
      }
    }
  }

  // ----- Consultas CVE para el frontend (solo con versión completa y verificable) -----
  const lookupMap = [];
  det.technologies.forEach((t) => {
    if (!t.version || !/^\d+(\.\d+){1,3}$/.test(t.version)) return;
    let product = null;
    if (t.id === 'php') product = 'php';
    else if (CMS_IDS.includes(t.id)) product = t.id;
    else if (t.id === 'server') product = t.product;
    else if (t.id === 'jquery') product = 'jquery';
    if (!product) return;
    let classification;
    if (t.versionStatus === 'Probable') classification = 'C';
    else if (CMS_IDS.includes(t.id) && t.versionStatus === 'Confirmado') classification = 'A';
    else classification = 'B';
    lookupMap.push({ component: t.name.replace(/^Servidor web: /, ''), product, version: t.version, classification, versionStatus: t.versionStatus, versionSource: t.versionSource });
  });
  result.vulnLookups = lookupMap.slice(0, 4);
  const noVersion = det.technologies.filter((t) => ['php', 'wordpress', 'joomla', 'drupal'].includes(t.id) && t.status !== 'No detectado' && !t.version);
  noVersion.forEach((t) => {
    result.notPerformed.push('Consulta de vulnerabilidades de ' + t.name + ': no se pudo identificar una versión verificable, por lo que no se asoció ningún CVE.');
  });

  if (!html || resp.status >= 400) {
    result.limitations.push('El sitio respondió HTTP ' + resp.status + (html ? '' : ' y no se obtuvo contenido HTML') + '; puede deberse a un cortafuegos de aplicaciones (WAF), una página de error o un reto anti-bots, por lo que la detección de tecnologías puede ser incompleta.');
  }
  if (resp.truncated) result.limitations.push('La página principal superó el tamaño máximo analizado (600 KB); se examinó solo el inicio.');

  return finish();
}

module.exports = { runAnalysis, describeError, APP_VERSION, SOURCES };
