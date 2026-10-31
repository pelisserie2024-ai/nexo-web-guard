/* NEXO WEB GUARD - asesor (sin DOM): deriva "a quién reportar" y "qué mejorar" de datos ya recogidos por el análisis.
   No hace comprobaciones nuevas contra el sitio: solo reorganiza lo que infra.js, domain-intel.js, analysis.js y subdomains.js ya entregaron. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NWGAdvisor = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** Enlaces de abuso conocidos, por nombre de proveedor tal como lo entrega infra.js (detectHosting). Ninguno se inventa en tiempo de análisis: es una lista fija. */
  var ABUSE_LINKS = {
    'Cloudflare': 'https://abuse.cloudflare.com/',
    'Amazon Web Services': 'https://support.aws.amazon.com/#/contacts/report-abuse',
    'Amazon CloudFront': 'https://support.aws.amazon.com/#/contacts/report-abuse',
    'Amazon Route 53': 'https://support.aws.amazon.com/#/contacts/report-abuse',
    'Google': 'https://safebrowsing.google.com/safebrowsing/report_phish/',
    'Google Cloud DNS': 'https://safebrowsing.google.com/safebrowsing/report_phish/',
    'Microsoft Azure': 'https://www.microsoft.com/en-us/msrc/report-abuse',
    'Fastly': 'https://www.fastly.com/abuse',
    'Akamai': 'https://www.akamai.com/legal/report-abuse',
    'Netlify': 'https://www.netlify.com/abuse/',
    'DigitalOcean': 'https://www.digitalocean.com/company/contact/abuse',
    'Hetzner': 'https://www.hetzner.com/legal/report-abuse/',
    'OVH': 'https://www.ovhcloud.com/en/abuse-report/',
    'Linode (Akamai)': 'https://www.akamai.com/legal/report-abuse',
    'Imperva': 'https://www.imperva.com/abuse-report/',
    'Sucuri': 'https://sucuri.net/report-abuse/',
    'GoDaddy': 'https://www.godaddy.com/es/agreements/report-abuse',
    'Vercel': 'https://vercel.com/contact/abuse',
    'GitHub Pages': 'https://github.com/contact/report-abuse',
    'Namecheap': 'https://www.namecheap.com/abuse-report/',
    'NS1': 'https://ns1.com/legal/abuse-policy',
    'Shopify': 'https://www.shopify.com/legal/report-abuse',
    'Wix': 'https://www.wix.com/about/report-abuse'
  };

  var GENERIC_RESOURCES = [
    { title: 'Reportar sitio de phishing/engañoso a Google Safe Browsing', url: 'https://safebrowsing.google.com/safebrowsing/report_phish/' },
    { title: 'Reportar a Microsoft SmartScreen', url: 'https://report.microsoft.com/' },
    { title: 'PDI Chile - Brigada del Cibercrimen (BRICIB)', url: 'https://www.pdichile.cl/denuncia-virtual' },
    { title: 'Whois/RDAP de ICANN (para ubicar al registrador de cualquier dominio)', url: 'https://lookup.icann.org/' }
  ];

  /** result: salida ya fusionada de analysis.js + infra.js + domain-intel.js. No hace red ni DOM. */
  function buildReportAdvice(result) {
    var r = result || {};
    var providers = [];
    var seen = {};
    ((r.infrastructure && r.infrastructure.hosting) || []).forEach(function (h) {
      if (seen[h.name]) return;
      seen[h.name] = true;
      providers.push({ name: h.name, role: h.role, abuseUrl: ABUSE_LINKS[h.name] || null });
    });
    var registrar = r.domainIntel && r.domainIntel.rdap && r.domainIntel.rdap.status === 'ok' ? r.domainIntel.rdap.registrar : null;
    return {
      providers: providers,
      registrar: registrar,
      registrarNote: registrar ? 'Contacta al registrador por el canal de abuso de su propio sitio; no todos publican un enlace directo.' : 'No se pudo determinar el registrador (RDAP no disponible para este dominio).',
      resources: GENERIC_RESOURCES
    };
  }

  /** Dificultad orientativa según la categoría del hallazgo. No es un dato del análisis: es una guía general para quien administra el sitio. */
  var DIFFICULTY_BY_CATEGORY = {
    'Cabeceras': { label: 'Fácil', note: 'Se agrega en la configuración del servidor web o del CDN, sin tocar el código.' },
    'HTTPS': { label: 'Depende del proveedor', note: 'Normalmente se activa desde el panel de hosting o del CDN.' },
    'PHP': { label: 'Requiere coordinación', note: 'Actualizar PHP puede afectar al sitio; conviene probarlo antes en un entorno de prueba.' },
    'Infraestructura': { label: 'Depende del caso', note: 'Según el hallazgo: desde revisar un registro DNS hasta contactar al proveedor.' },
    'Dominio': { label: 'Administrativo', note: 'Se gestiona desde el panel del registrador del dominio.' },
    'Subdominios': { label: 'Fácil a moderado', note: 'Eliminar un registro DNS que ya no se usa es simple; confirmar que nada depende de él toma más tiempo.' },
    'Vulnerabilidad': { label: 'Requiere acceso al servidor', note: 'Actualizar el componente afectado y confirmar la versión con acceso autorizado.' }
  };

  /** Checklist priorizado a partir de los hallazgos ya calculados (no agrega comprobaciones nuevas). */
  function buildImprovementPlan(result, core) {
    var r = result || {};
    var findings = (r.findings || []).filter(function (f) { return f.severity !== 'Informativo'; });
    var ordered = core && core.sortFindings ? core.sortFindings(findings) : findings;
    var items = ordered.map(function (f) {
      var diff = DIFFICULTY_BY_CATEGORY[f.category] || { label: 'Por evaluar', note: '' };
      return {
        id: f.id, title: f.title, severity: f.severity, confidence: f.confidence, category: f.category,
        recommendation: f.recommendation || '', difficulty: diff.label, difficultyNote: diff.note
      };
    });
    return { items: items, count: items.length };
  }

  return { ABUSE_LINKS: ABUSE_LINKS, GENERIC_RESOURCES: GENERIC_RESOURCES, buildReportAdvice: buildReportAdvice, buildImprovementPlan: buildImprovementPlan };
});
