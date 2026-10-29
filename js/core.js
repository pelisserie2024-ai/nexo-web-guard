/* NEXO WEB GUARD - núcleo del cliente (sin DOM): validación, clasificación CVE y evaluación de riesgo. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NWGCore = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SEVERITIES = ['Informativo', 'Bajo', 'Medio', 'Alto', 'Crítico'];
  var INCOMPLETE_MESSAGE = 'Evaluación incompleta: no existe evidencia suficiente para determinar el nivel de seguridad del sitio';
  var CVSS_TO_SEV = { CRITICAL: 'Crítico', HIGH: 'Alto', MEDIUM: 'Medio', LOW: 'Bajo', NONE: 'Informativo' };

  function sevIndex(s) {
    var i = SEVERITIES.indexOf(s);
    return i < 0 ? 0 : i;
  }
  function capSeverity(s, max) {
    return sevIndex(s) > sevIndex(max) ? max : s;
  }

  /** Validación de URL en el navegador (el backend repite y refuerza esta validación). */
  function validateUrl(raw) {
    var s = String(raw || '').trim();
    if (!s) return { ok: false, error: 'Introduce la dirección del sitio web.' };
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
    var u;
    try { u = new URL(s); } catch (e) { return { ok: false, error: 'La dirección no tiene un formato válido. Ejemplo: https://ejemplo.cl' }; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, error: 'Solo se admiten direcciones http:// o https://.' };
    if (u.username || u.password) return { ok: false, error: 'La dirección no puede incluir usuario ni contraseña.' };
    var host = u.hostname.toLowerCase();
    if (!host.includes('.') || /^[\d.]+$/.test(host) || host.startsWith('[') || host === 'localhost') {
      return { ok: false, error: 'Introduce un nombre de dominio público (no una IP ni un nombre interno).' };
    }
    if (u.port && u.port !== '80' && u.port !== '443') return { ok: false, error: 'Solo se permiten los puertos estándar 80 y 443.' };
    return { ok: true, url: u.href };
  }

  function cveUrl(id) {
    return /^CVE-\d{4}-\d{4,7}$/.test(String(id)) ? 'https://nvd.nist.gov/vuln/detail/' + id : null;
  }

  /** Severidad efectiva para el cálculo global: la incertidumbre limita el impacto en el riesgo. */
  function effectiveSeverity(item) {
    var sev = item.severity;
    if (item.classification === 'B') sev = capSeverity(sev, 'Medio');
    else if (item.classification === 'C') sev = capSeverity(sev, 'Bajo');
    if (item.confidence === 'Baja') sev = capSeverity(sev, 'Bajo');
    return sev;
  }

  /** Convierte la respuesta de vulnerability-lookup en entradas normalizadas para el informe. */
  function normalizeVulns(lookup, resp) {
    return (resp.vulnerabilities || []).filter(function (v) { return cveUrl(v.id); }).map(function (v) {
      var sev = v.cvssSeverity && CVSS_TO_SEV[v.cvssSeverity] ? CVSS_TO_SEV[v.cvssSeverity] : null;
      return {
        id: v.id,
        url: cveUrl(v.id),
        component: lookup.component,
        product: resp.productName || lookup.product,
        detectedVersion: lookup.version,
        classification: lookup.classification,
        description: v.description || '',
        descriptionLang: v.descriptionLang || null,
        cvssScore: typeof v.cvssScore === 'number' ? v.cvssScore : null,
        cvssVersion: v.cvssVersion || null,
        publishedSeverity: v.cvssSeverity || null,
        severity: sev || 'Informativo',
        severityKnown: !!sev,
        affectedVersions: v.affectedVersions || [],
        fixedVersions: v.fixedVersions || [],
        published: v.published || null,
        confidence: lookup.classification === 'A' ? 'Alta' : (lookup.classification === 'B' ? 'Media' : 'Baja'),
        source: 'NVD (nvd.nist.gov)',
        recommendation: 'Actualizar ' + (resp.productName || lookup.component) + ' a una versión corregida' +
          ((v.fixedVersions || []).length ? ' (documentada como corregida en ' + v.fixedVersions.join(', ') + ')' : '') +
          ' o aplicar el parche del proveedor. Confirmar la versión real con acceso autorizado al servidor: las distribuciones Linux pueden incluir correcciones retroportadas.'
      };
    });
  }

  var CLASS_LABEL = {
    A: 'A - Confirmada con evidencia suficiente',
    B: 'B - Potencialmente relevante para la versión detectada',
    C: 'C - Componente o versión no confirmados'
  };

  /** Evaluación global. No produce porcentajes ni garantías. */
  function computeRisk(result) {
    var r = result || {};
    if (r.status === 'failed' || r.status === 'stopped' || !r.finalUrl) {
      return { level: null, incomplete: true, message: INCOMPLETE_MESSAGE, basis: r.error || r.stoppedReason || 'No se obtuvo una respuesta analizable del sitio.', counts: {} };
    }
    var items = (r.findings || []).map(function (f) { return { severity: f.severity, confidence: f.confidence, classification: null, ref: f.id }; })
      .concat((r.vulnerabilities || []).filter(function (v) { return v.severityKnown; }).map(function (v) {
        return { severity: v.severity, confidence: v.confidence, classification: v.classification, ref: v.id };
      }));
    var counts = {};
    SEVERITIES.forEach(function (s) { counts[s] = 0; });
    var level = 'Informativo';
    var driver = null;
    items.forEach(function (it) {
      var eff = effectiveSeverity(it);
      counts[eff]++;
      if (sevIndex(eff) > sevIndex(level)) { level = eff; driver = it.ref; }
    });
    var basis = level === 'Informativo'
      ? 'No se observaron hallazgos de gravedad en las comprobaciones realizadas. Esto no garantiza la ausencia de vulnerabilidades.'
      : 'El nivel lo determina el hallazgo ' + driver + '. Las vulnerabilidades no confirmadas (clases B y C) y las detecciones de baja confianza se ponderan a la baja.';
    return { level: level, incomplete: false, message: null, basis: basis, counts: counts };
  }

  function sortFindings(findings) {
    var conf = { Alta: 0, Media: 1, Baja: 2 };
    return (findings || []).slice().sort(function (a, b) {
      return sevIndex(effectiveSeverity(b)) - sevIndex(effectiveSeverity(a)) || (conf[a.confidence] || 3) - (conf[b.confidence] || 3);
    });
  }

  function finalize(result) {
    result.risk = computeRisk(result);
    result.prioritized = sortFindings(result.findings).filter(function (f) { return f.severity !== 'Informativo'; });
    return result;
  }

  /** Estructura del archivo JSON exportado. */
  function buildJsonExport(result) {
    return JSON.stringify({ generator: 'NEXO WEB GUARD ' + (result.appVersion || ''), exportedAt: new Date().toISOString(), report: result }, null, 2);
  }

  function pad(n) { return n < 10 ? '0' + n : String(n); }
  function dateStamp(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
  function pdfFileName(d) { return 'NEXO-WEB-GUARD-informe-' + dateStamp(d || new Date()) + '.pdf'; }

  return {
    SEVERITIES: SEVERITIES, INCOMPLETE_MESSAGE: INCOMPLETE_MESSAGE, CLASS_LABEL: CLASS_LABEL,
    validateUrl: validateUrl, cveUrl: cveUrl, effectiveSeverity: effectiveSeverity, normalizeVulns: normalizeVulns,
    computeRisk: computeRisk, sortFindings: sortFindings, finalize: finalize, buildJsonExport: buildJsonExport,
    pdfFileName: pdfFileName, sevIndex: sevIndex
  };
});
