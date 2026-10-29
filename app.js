/* NEXO WEB GUARD - interfaz. Todo el contenido dinámico se inserta con textContent (sin HTML dinámico). */
(function () {
  'use strict';

  var Core = window.NWGCore;
  var API = '/.netlify/functions/';
  var state = { result: null, running: false, lastUrl: '' };

  var $ = function (id) { return document.getElementById(id); };
  var form = $('scan-form');
  var urlInput = $('url-input');
  var authCheck = $('auth-check');
  var scanBtn = $('scan-btn');
  var errorBox = $('form-error');
  var statusPanel = $('status-panel');
  var stepsList = $('steps');
  var resultsBox = $('results');

  /* ---------- utilidades DOM ---------- */
  function h(tag, props) {
    var el = document.createElement(tag);
    Object.keys(props || {}).forEach(function (k) {
      var v = props[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v);
    });
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }
  function append(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { append(el, x); }); return; }
    el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
  function slug(s) {
    return String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z]+/g, '-').replace(/^-|-$/g, '');
  }
  function sevBadge(s) { return h('span', { class: 'badge sev-' + slug(s), text: s }); }
  function stBadge(s) { return h('span', { class: 'badge st-' + slug(s), text: s }); }
  function fmtDate(iso) {
    var d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso || 'No disponible') : d.toLocaleString('es-CL', { dateStyle: 'long', timeStyle: 'short' });
  }
  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = !msg;
  }

  /* ---------- pasos de progreso (estados reales, sin porcentajes inventados) ---------- */
  var steps = [];
  function setSteps(list) {
    steps = list.map(function (label) {
      var dot = h('span', { class: 'dot' });
      var txt = h('span', { text: label });
      var li = h('li', {}, dot, txt);
      return { li: li, txt: txt, label: label };
    });
    stepsList.textContent = '';
    steps.forEach(function (s) { stepsList.appendChild(s.li); });
    statusPanel.hidden = false;
  }
  function stepState(i, st, text) {
    var s = steps[i];
    if (!s) return;
    s.li.className = st;
    if (text) s.txt.textContent = text;
  }

  /* ---------- llamadas al backend ---------- */
  function callApi(fn, payload, timeoutMs) {
    var ctrl = new AbortController();
    var t = setTimeout(function () { ctrl.abort(); }, timeoutMs || 28000);
    return fetch(API + fn, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      signal: ctrl.signal, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer'
    }).then(function (res) {
      return res.text().then(function (txt) {
        var data = null;
        try { data = JSON.parse(txt); } catch (e) { /* respuesta no JSON */ }
        if (!res.ok) {
          var err = new Error((data && data.error) || ('El servidor respondió con el estado ' + res.status + '.'));
          err.status = res.status;
          throw err;
        }
        if (!data) throw new Error('Respuesta no válida del servidor.');
        return data;
      });
    }).catch(function (e) {
      if (e.name === 'AbortError') throw new Error('El servidor tardó demasiado en responder.');
      if (e instanceof TypeError) throw new Error('No se pudo contactar con las funciones del servidor. Si ejecuta el sitio en local, use "netlify dev".');
      throw e;
    }).then(function (d) { clearTimeout(t); return d; }, function (e) { clearTimeout(t); throw e; });
  }

  /* ---------- flujo principal ---------- */
  function run(rawUrl) {
    if (state.running) return;
    showError('');
    var v = Core.validateUrl(rawUrl);
    if (!v.ok) { showError(v.error); urlInput.focus(); return; }
    if (!authCheck.checked) { showError('Debes confirmar que eres propietario del sitio o que dispones de autorización para analizarlo.'); authCheck.focus(); return; }

    state.running = true;
    state.lastUrl = v.url;
    urlInput.value = v.url;
    scanBtn.disabled = true;
    clearResults(true);
    setSteps([
      'Validando la dirección',
      'Comprobaciones en el servidor (HTTP, HTTPS, certificado y tecnologías)',
      'Consulta de vulnerabilidades en NVD',
      'Preparando los resultados'
    ]);
    stepState(0, 'done');
    stepState(1, 'running');

    var result;
    callApi('analyze-site', { url: v.url, authorized: true }, 28000).then(function (res) {
      result = res;
      stepState(1, res.status === 'failed' ? 'error' : 'done', res.status === 'failed' ? 'Comprobaciones en el servidor: no se pudo completar' : null);
      var lookups = (res.status === 'completed' && res.vulnLookups) ? res.vulnLookups : [];
      if (!lookups.length) {
        stepState(2, 'done', res.status === 'completed' ? 'Consulta de vulnerabilidades: sin versiones verificables que consultar' : 'Consulta de vulnerabilidades: omitida');
        return;
      }
      var i = 0;
      result.vulnLookupSummary = {};
      function next() {
        if (i >= lookups.length) { stepState(2, 'done', 'Consulta de vulnerabilidades en NVD (' + lookups.length + ' de ' + lookups.length + ')'); return Promise.resolve(); }
        var lk = lookups[i];
        stepState(2, 'running', 'Consultando NVD: ' + lk.component + ' ' + lk.version + ' (' + (i + 1) + ' de ' + lookups.length + ')');
        return callApi('vulnerability-lookup', { product: lk.product, version: lk.version }, 12000).then(function (r) {
          var items = Core.normalizeVulns(lk, r);
          result.vulnerabilities = result.vulnerabilities.concat(items);
          result.vulnLookupSummary[lk.product + '@' + lk.version] = items.length + ' CVE mostrados de ' + r.totalResults + ' devueltos por NVD' + (r.truncated ? ' (ordenados por puntuación CVSS)' : '');
        }).catch(function (e) {
          result.vulnLookupErrors.push(lk.component + ' ' + lk.version + ': ' + e.message);
        }).then(function () { i++; return next(); });
      }
      return next();
    }).then(function () {
      stepState(3, 'running');
      Core.finalize(result);
      state.result = result;
      renderResults(result);
      stepState(3, 'done');
      if (result.vulnLookupErrors.length) stepState(2, 'error', 'Consulta de vulnerabilidades: algunas consultas no pudieron completarse');
    }).catch(function (e) {
      var idx = steps.findIndex(function (s) { return s.li.className === 'running'; });
      if (idx >= 0) stepState(idx, 'error');
      showError(e.message + ' Puedes repetir el análisis.');
    }).then(function () {
      state.running = false;
      scanBtn.disabled = false;
    });
  }

  /* ---------- renderizado de resultados ---------- */
  function section(title, intro) {
    var c = h('section', { class: 'card' }, h('h3', { text: title }));
    if (intro) c.appendChild(h('p', { class: 'muted small', text: intro }));
    return c;
  }
  function kv(rows) {
    var dl = h('dl', { class: 'kv' });
    rows.forEach(function (r) { dl.appendChild(h('dt', { text: r[0] })); dl.appendChild(h('dd', {}, r[1])); });
    return dl;
  }
  function list(items) {
    return h('ul', {}, (items || []).map(function (x) { return h('li', { text: x }); }));
  }
  function table(head, rows) {
    return h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', {}, h('tr', {}, head.map(function (t) { return h('th', { text: t }); }))),
      h('tbody', {}, rows.map(function (r) { return h('tr', {}, r.map(function (c) { return h('td', {}, c); })); }))));
  }

  function findingCard(f) {
    return h('article', { class: 'finding sev-' + slug(f.severity) },
      h('div', { class: 'tags' }, sevBadge(f.severity), h('span', { class: 'badge neutral', text: 'Confianza: ' + (f.confidence || 'n/d') }), h('span', { class: 'muted small', text: f.category + ' · ' + f.id })),
      h('h4', { text: f.title }),
      f.description ? h('p', { text: f.description }) : null,
      f.evidence && f.evidence.length ? [h('strong', { class: 'small', text: 'Evidencia' }), list(f.evidence)] : null,
      f.source ? h('p', { class: 'muted small', text: 'Fuente: ' + f.source }) : null,
      f.recommendation ? h('p', {}, h('strong', { text: 'Recomendación: ' }), f.recommendation) : null,
      f.limitations ? h('p', { class: 'muted small', text: 'Limitaciones: ' + f.limitations }) : null);
  }

  function vulnCard(v) {
    var sevText = v.severityKnown ? v.severity : 'Sin puntuación';
    return h('article', { class: 'finding sev-' + slug(v.severity) },
      h('div', { class: 'tags' },
        v.severityKnown ? sevBadge(v.severity) : h('span', { class: 'badge', text: sevText }),
        h('span', { class: 'badge neutral', text: 'Clase ' + v.classification }),
        h('span', { class: 'muted small', text: 'CVSS ' + (v.cvssScore !== null ? v.cvssScore + (v.cvssVersion ? ' (v' + v.cvssVersion + ')' : '') : 'no disponible') + ' · gravedad publicada por NVD: ' + (v.publishedSeverity || 'no disponible') })),
      h('h4', {}, h('a', { href: v.url, target: '_blank', rel: 'noopener noreferrer', text: v.id }), ' · ' + v.product + ' ' + v.detectedVersion),
      h('p', { text: v.description + (v.descriptionLang === 'en' ? ' (descripción original en inglés, fuente NVD)' : '') }),
      h('p', { class: 'small', text: 'Versiones afectadas: ' + (v.affectedVersions.join('; ') || 'no detalladas') }),
      h('p', { class: 'small', text: 'Versiones corregidas: ' + (v.fixedVersions.join(', ') || 'no documentadas en la fuente') + ' · Publicada: ' + (v.published ? fmtDate(v.published) : 'no disponible') }),
      h('p', { class: 'muted small', text: 'Recomendación: ' + v.recommendation }));
  }

  function renderResults(r) {
    resultsBox.textContent = '';
    resultsBox.hidden = false;
    var risk = r.risk;

    // Cabecera
    var badge = risk.incomplete
      ? h('div', { class: 'risk-badge incomplete' }, h('small', { text: 'Nivel de riesgo' }), h('strong', { text: 'Evaluación incompleta' }))
      : h('div', { class: 'risk-badge sev-' + slug(risk.level) }, h('small', { text: 'Riesgo observado' }), h('strong', { text: risk.level }));
    var head = h('section', { class: 'card' },
      h('div', { class: 'res-head' },
        h('div', {}, h('h2', { text: r.host || 'Análisis' }),
          h('div', { class: 'meta', text: fmtDate(r.analyzedAt) + ' · ' + r.reportId + ' · ' + (r.finalUrl || r.requestedUrl) })),
        badge));
    if (risk.incomplete) head.appendChild(h('p', { class: 'banner', text: Core.INCOMPLETE_MESSAGE + '. ' + (risk.basis || '') }));
    else head.appendChild(h('p', { class: 'muted', text: risk.basis }));
    if (r.error) head.appendChild(h('p', { class: 'banner', text: 'Error: ' + r.error }));
    if (r.stoppedReason) head.appendChild(h('p', { class: 'banner', text: r.stoppedReason }));
    if (!risk.incomplete) {
      var counts = h('div', { class: 'counts' });
      Core.SEVERITIES.slice().reverse().forEach(function (s) {
        counts.appendChild(h('span', { class: 'badge sev-' + slug(s), text: s + ': ' + (risk.counts[s] || 0) }));
      });
      head.appendChild(counts);
    }
    head.appendChild(h('p', { class: 'muted small', text: 'La gravedad técnica y la confianza se muestran por separado. Este nivel no es una puntuación de seguridad ni garantiza la ausencia de vulnerabilidades.' }));
    var actions = h('div', { class: 'actions' },
      h('button', { class: 'btn primary', type: 'button', id: 'btn-pdf', text: 'DESCARGAR INFORME PDF' }),
      h('button', { class: 'btn', type: 'button', id: 'btn-json', text: 'EXPORTAR JSON' }),
      h('button', { class: 'btn', type: 'button', id: 'btn-again', text: 'VOLVER A ANALIZAR' }),
      h('button', { class: 'btn danger', type: 'button', id: 'btn-clear', text: 'LIMPIAR RESULTADOS' }));
    head.appendChild(actions);
    resultsBox.appendChild(head);

    // HTTPS
    var hs = r.https || {};
    var cert = hs.certificate;
    var sHttps = section('HTTPS y certificado');
    sHttps.appendChild(kv([
      ['HTTPS disponible', hs.available || 'No verificable con las comprobaciones disponibles'],
      ['Estado', hs.state || 'No verificable con las comprobaciones disponibles'],
      ['Redirección HTTP a HTTPS', hs.redirectsHttpToHttps || 'No verificable con las comprobaciones disponibles'],
      ['Protocolo TLS negociado', hs.tlsProtocol || 'No verificable con las comprobaciones disponibles'],
      ['Certificado', cert ? (cert.validForClient ? 'Válido para el cliente de análisis' : 'No válido: ' + (cert.validationError || 'error')) : 'No verificable con las comprobaciones disponibles'],
      ['Titular / emisor', cert ? (cert.subject || 'n/d') + ' / ' + (cert.issuer || 'n/d') : 'No disponible'],
      ['Validez', cert && cert.validTo ? fmtDate(cert.validFrom) + ' → ' + fmtDate(cert.validTo) + (typeof cert.daysLeft === 'number' ? ' (' + cert.daysLeft + ' días restantes)' : '') : 'No disponible']
    ]));
    (hs.notes || []).forEach(function (n) { sHttps.appendChild(h('p', { class: 'muted small', text: n })); });
    resultsBox.appendChild(sHttps);

    // Tecnologías
    var sTech = section('Tecnologías detectadas', 'Confirmado = evidencia directa · Probable = indicios indirectos · No detectado = sin señales (no prueba ausencia) · Desconocido = sin información.');
    if ((r.technologies || []).length) {
      sTech.appendChild(table(['Tecnología', 'Estado', 'Versión', 'Evidencia y notas'], r.technologies.map(function (t) {
        return [t.name, h('span', {}, stBadge(t.status), ' ', h('span', { class: 'muted small', text: 'confianza ' + (t.confidence || 'n/d') })),
          t.version ? t.version + (t.versionStatus ? ' (' + t.versionStatus + ')' : '') : '—',
          (t.evidence || []).concat(t.versionSource ? ['Versión: ' + t.versionSource] : []).concat(t.note ? [t.note] : []).join(' · ') || '—'];
      })));
    } else {
      sTech.appendChild(h('p', { class: 'muted', text: 'No disponible: no se obtuvo respuesta analizable del sitio.' }));
    }
    resultsBox.appendChild(sTech);

    // PHP
    var sPhp = section('PHP Security Analyzer');
    if (r.php) {
      sPhp.appendChild(kv([
        ['Estado de PHP', h('span', {}, stBadge(r.php.status), ' ', h('span', { class: 'muted small', text: 'confianza ' + (r.php.confidence || 'n/d') }))],
        ['Versión', r.php.version ? r.php.version + ' (declarada por el servidor; no verificada en el servidor)' : 'No confirmada'],
        ['Ciclo de soporte', r.php.support && r.php.support.note ? r.php.support.note : 'No evaluable sin una versión verificable'],
        ['Evidencia', (r.php.evidence || []).join(' · ') || 'Sin evidencia directa']
      ]));
      sPhp.appendChild(h('p', { text: r.php.message || '' }));
      if (r.php.note && r.php.note !== r.php.message) sPhp.appendChild(h('p', { class: 'muted small', text: r.php.note }));
      sPhp.appendChild(h('p', { class: 'muted small', text: 'Usar PHP no implica que el sitio sea vulnerable. Las vulnerabilidades solo se asocian a versiones identificadas con evidencia.' }));
    } else {
      sPhp.appendChild(h('p', { class: 'muted', text: 'No disponible: no se obtuvo respuesta analizable del sitio.' }));
    }
    resultsBox.appendChild(sPhp);

    // Cabeceras
    var sHead = section('Cabeceras de seguridad', 'La ausencia de una cabecera no equivale automáticamente a una vulnerabilidad: depende del contexto.');
    if ((r.headers || []).length) {
      sHead.appendChild(table(['Cabecera', 'Estado', 'Función y riesgo', 'Recomendación'], r.headers.map(function (x) {
        var col = x.assessment === 'Correcto' ? 'st-confirmado' : (x.assessment === 'No aplica' ? 'st-desconocido' : 'st-probable');
        return [x.header, h('span', { class: 'badge ' + col, text: x.assessment }),
          h('span', {}, x.function, ' ', h('span', { class: 'muted', text: 'Riesgo: ' + x.risk + (x.note ? ' ' + x.note : '') })), x.recommendation];
      })));
    } else {
      sHead.appendChild(h('p', { class: 'muted', text: 'No disponible: no se obtuvo una respuesta HTTP analizable.' }));
    }
    resultsBox.appendChild(sHead);

    // CVE
    var sVuln = section('Vulnerabilidades conocidas (NVD/CVE)');
    sVuln.appendChild(h('div', { class: 'legend' },
      h('span', { text: 'A · Confirmada con evidencia suficiente (componente y versión verificados).' }),
      h('span', { text: 'B · Potencialmente relevante para la versión detectada (versión declarada, sin verificar en el servidor).' }),
      h('span', { text: 'C · Componente o versión no confirmados (indicador indirecto).' }),
      h('span', { text: 'Que exista un CVE para una tecnología no demuestra que este sitio sea vulnerable.' })));
    (r.vulnLookups || []).forEach(function (lk) {
      var s = (r.vulnLookupSummary || {})[lk.product + '@' + lk.version];
      sVuln.appendChild(h('p', { class: 'small', text: 'Consulta: ' + lk.component + ' ' + lk.version + ' (clase ' + lk.classification + ')' + (s ? ' — ' + s : '') }));
    });
    (r.vulnLookupErrors || []).forEach(function (e) { sVuln.appendChild(h('p', { class: 'banner', text: 'No se pudo completar la consulta: ' + e })); });
    if (!(r.vulnerabilities || []).length) {
      sVuln.appendChild(h('p', { class: 'muted', text: (r.vulnLookups || []).length
        ? 'La consulta no devolvió CVE para las versiones identificadas o no pudo completarse. Esto no garantiza la ausencia de vulnerabilidades.'
        : 'No se consultaron CVE: no se identificó ninguna versión de componente verificable desde el exterior. Esto es «no verificado», no «sin vulnerabilidades».' }));
    }
    (r.vulnerabilities || []).forEach(function (v) { sVuln.appendChild(vulnCard(v)); });
    resultsBox.appendChild(sVuln);

    // Recomendaciones priorizadas
    var sRec = section('Recomendaciones priorizadas', 'Ordenadas por gravedad efectiva y confianza.');
    if ((r.prioritized || []).length) r.prioritized.forEach(function (f) { sRec.appendChild(findingCard(f)); });
    else sRec.appendChild(h('p', { class: 'muted', text: 'No se registraron hallazgos de gravedad superior a «Informativo» en las comprobaciones realizadas.' }));
    var info = (r.findings || []).filter(function (f) { return f.severity === 'Informativo'; });
    if (info.length) {
      var d = h('details', {}, h('summary', { text: 'Observaciones informativas (' + info.length + ')' }));
      info.forEach(function (f) { d.appendChild(findingCard(f)); });
      sRec.appendChild(d);
    }
    resultsBox.appendChild(sRec);

    // Limitaciones
    var sLim = section('Limitaciones y comprobaciones no realizadas');
    sLim.appendChild(h('strong', { class: 'small', text: 'Limitaciones' }));
    sLim.appendChild(list(r.limitations));
    sLim.appendChild(h('strong', { class: 'small', text: 'No realizado' }));
    sLim.appendChild(list(r.notPerformed));
    sLim.appendChild(h('p', { class: 'muted small', text: 'Solicitudes al sitio: ' + (r.requests ? r.requests.used + ' de un máximo de ' + r.requests.max : 'n/d') + '.' }));
    sLim.appendChild(h('strong', { class: 'small', text: 'Fuentes oficiales' }));
    var ul = h('ul');
    (r.sources || []).forEach(function (s) {
      if (/^https:\/\//.test(s.url)) ul.appendChild(h('li', {}, h('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer', text: s.title })));
    });
    sLim.appendChild(ul);
    resultsBox.appendChild(sLim);

    $('btn-pdf').addEventListener('click', downloadPdf);
    $('btn-json').addEventListener('click', downloadJson);
    $('btn-again').addEventListener('click', function () { run(state.lastUrl || urlInput.value); });
    $('btn-clear').addEventListener('click', function () { clearResults(false); });
    resultsBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function clearResults(keepStatus) {
    state.result = null;
    resultsBox.textContent = '';
    resultsBox.hidden = true;
    if (!keepStatus) { statusPanel.hidden = true; stepsList.textContent = ''; showError(''); }
  }

  /* ---------- descargas (en el dispositivo del usuario) ---------- */
  function saveBlob(blob, name) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = name; a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1500);
  }
  function downloadPdf() {
    if (!state.result) return;
    var ctor = window.jspdf && window.jspdf.jsPDF;
    if (!ctor) { showError('No se pudo cargar la biblioteca de PDF (vendor/jspdf.umd.min.js). Ejecute "npm install" y "npm run build", o vuelva a desplegar el sitio.'); window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
    try {
      var doc = window.NWGPdf.build(ctor, state.result, Core);
      saveBlob(doc.output('blob'), Core.pdfFileName(new Date()));
    } catch (e) {
      showError('No se pudo generar el PDF: ' + e.message);
    }
  }
  function downloadJson() {
    if (!state.result) return;
    var name = Core.pdfFileName(new Date()).replace(/\.pdf$/, '.json');
    saveBlob(new Blob([Core.buildJsonExport(state.result)], { type: 'application/json' }), name);
  }

  form.addEventListener('submit', function (ev) { ev.preventDefault(); run(urlInput.value); });
})();
