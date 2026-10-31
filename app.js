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
      'Infraestructura y DNS (IP, proveedor, correo)',
      'Dominio, ubicación aproximada y DNSSEC',
      'Subdominios (certificados públicos) y CNAME colgantes',
      'Consulta de vulnerabilidades en NVD',
      'Preparando los resultados'
    ]);
    stepState(0, 'done');
    stepState(1, 'running');
    stepState(2, 'running');
    stepState(3, 'running');
    stepState(4, 'running');

    // El análisis de infraestructura (solo DNS) corre en paralelo con el del servidor.
    var infraP = callApi('infrastructure', { url: v.url }, 15000).then(function (r) {
      stepState(2, r.available === false ? 'error' : 'done', r.available === false ? 'Infraestructura y DNS: no se pudo completar' : null);
      return r;
    }).catch(function (e) {
      stepState(2, 'error', 'Infraestructura y DNS: ' + e.message);
      return { error: e.message };
    });

    var domainP = callApi('domain-intel', { url: v.url }, 20000).then(function (r) {
      stepState(3, 'done');
      return r;
    }).catch(function (e) {
      stepState(3, 'error', 'Dominio, ubicación y DNSSEC: ' + e.message);
      return { error: e.message };
    });

    var subsP = callApi('subdomains', { url: v.url }, 20000).then(function (r) {
      stepState(4, r.status === 'no verificable' ? 'error' : 'done', r.status === 'no verificable' ? 'Subdominios: no verificable (servicio de certificados no disponible)' : null);
      return r;
    }).catch(function (e) {
      stepState(4, 'error', 'Subdominios: ' + e.message);
      return { error: e.message };
    });

    var result;
    callApi('analyze-site', { url: v.url, authorized: true }, 28000).then(function (res) {
      result = res;
      stepState(1, res.status === 'failed' ? 'error' : 'done', res.status === 'failed' ? 'Comprobaciones en el servidor: no se pudo completar' : null);
      var lookups = (res.status === 'completed' && res.vulnLookups) ? res.vulnLookups : [];
      if (!lookups.length) {
        stepState(5, 'done', res.status === 'completed' ? 'Consulta de vulnerabilidades: sin versiones verificables que consultar' : 'Consulta de vulnerabilidades: omitida');
        return;
      }
      var i = 0;
      result.vulnLookupSummary = {};
      function next() {
        if (i >= lookups.length) { stepState(5, 'done', 'Consulta de vulnerabilidades en NVD (' + lookups.length + ' de ' + lookups.length + ')'); return Promise.resolve(); }
        var lk = lookups[i];
        stepState(5, 'running', 'Consultando NVD: ' + lk.component + ' ' + lk.version + ' (' + (i + 1) + ' de ' + lookups.length + ')');
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
      return Promise.all([infraP, domainP, subsP]);
    }).then(function (both) {
      stepState(6, 'running');
      mergeInfra(result, both[0]);
      mergeDomain(result, both[1]);
      mergeSubs(result, both[2]);
      Core.finalize(result);
      state.result = result;
      renderResults(result);
      stepState(6, 'done');
      if (result.vulnLookupErrors.length) stepState(5, 'error', 'Consulta de vulnerabilidades: algunas consultas no pudieron completarse');
    }).catch(function (e) {
      var idx = steps.findIndex(function (s) { return s.li.className === 'running'; });
      if (idx >= 0) stepState(idx, 'error');
      showError(e.message + ' Puedes repetir el análisis.');
    }).then(function () {
      state.running = false;
      scanBtn.disabled = false;
    });
  }

  /* Fusiona los módulos adicionales con una única función (Core.mergeModule): sin duplicar limitaciones ni fuentes. */
  function mergeInfra(result, d) { Core.mergeModule(result, 'infrastructure', d, 'El análisis de infraestructura y DNS no pudo completarse'); }
  function mergeDomain(result, d) { Core.mergeModule(result, 'domainIntel', d, 'El análisis de dominio, ubicación y DNSSEC no pudo completarse'); }
  function mergeSubs(result, d) { Core.mergeModule(result, 'subdomains', d, 'El análisis de subdominios no pudo completarse'); }

  function subdomainsSection(sd) {
    var s = section('Subdominios (Certificate Transparency)', 'Subdominios que figuran en certificados públicos. Solo se hicieron consultas DNS; no se conectó a ninguno por HTTP.');
    if (!sd) { s.appendChild(h('p', { class: 'muted', text: 'No disponible: este análisis no pudo completarse. Repite el análisis.' })); return s; }
    if (sd.status !== 'ok') {
      s.appendChild(h('p', { class: sd.status === 'no verificable' ? 'banner' : 'muted', text: sd.note || 'No verificable con las comprobaciones disponibles.' }));
      return s;
    }
    s.appendChild(kv([
      ['Dominio base (estimado)', sd.domain],
      ['Fuentes consultadas', (sd.ctSources || []).join(', ') || 'n/d'],
      ['Subdominios encontrados', String(sd.total) + (sd.wildcard ? ' (existe un certificado comodín *.' + sd.domain + ')' : '')],
      ['Resueltos por DNS', sd.checked + ' de ' + sd.total]
    ]));
    if ((sd.resolved || []).length) {
      s.appendChild(table(['Subdominio', 'Estado', 'Destino', 'Notas'], sd.resolved.map(function (r) {
        var notes = [];
        if (r.sensitive) notes.push('nombre sensible');
        if (r.takeoverProne && r.state === 'colgante') notes.push('posible takeover (' + r.provider + ')');
        else if (r.provider) notes.push(r.provider);
        var badgeCls = r.state === 'resuelve' ? 'st-confirmado' : (r.state === 'colgante' ? 'sev-medio' : 'st-desconocido');
        return [r.name, h('span', { class: 'badge ' + badgeCls, text: r.state }),
          (r.cnames.length ? 'CNAME ' + r.cnames[0] + (r.ips.length ? ' → ' : '') : '') + (r.ips.slice(0, 2).join(', ') || (r.cnames.length ? '' : '—')),
          notes.join(' · ') || '—'];
      })));
    }
    var rest = (sd.names || []).filter(function (n) { return !(sd.resolved || []).some(function (r) { return r.name === n; }); });
    if (rest.length) {
      var d = h('details', {}, h('summary', { text: 'Otros subdominios sin resolver (' + rest.length + (sd.truncated ? '+' : '') + ')' }), list(rest.slice(0, 100)));
      s.appendChild(d);
    }
    s.appendChild(h('p', { class: 'muted small', text: 'La lista procede de registros públicos de certificados: puede ser incompleta o incluir nombres que ya no existen.' }));
    return s;
  }

  function fmtDay(iso) {
    var d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso || 'No disponible') : d.toLocaleDateString('es-CL', { dateStyle: 'long', timeZone: 'UTC' });
  }

  function domainSection(di) {
    var s = section('Dominio, ubicación y DNSSEC', 'Datos públicos del dominio (RDAP), ubicación aproximada de las IP y estado de DNSSEC. No se muestran datos personales del titular.');
    if (!di) { s.appendChild(h('p', { class: 'muted', text: 'No disponible: este análisis no pudo completarse. Repite el análisis.' })); return s; }

    s.appendChild(h('h4', { text: 'Datos del dominio (RDAP)' }));
    var rd = di.rdap || {};
    if (rd.status === 'ok') {
      s.appendChild(kv([
        ['Dominio', di.domain],
        ['Registrador', rd.registrar || 'No publicado'],
        ['Fecha de registro', rd.registration ? fmtDay(rd.registration) + (typeof rd.ageDays === 'number' ? ' (hace ' + rd.ageDays + ' días)' : '') : 'No publicada'],
        ['Fecha de expiración', rd.expiration ? fmtDay(rd.expiration) + (typeof rd.daysToExpire === 'number' ? ' (' + (rd.daysToExpire >= 0 ? 'en ' + rd.daysToExpire + ' días' : 'vencido') + ')' : '') : 'No publicada'],
        ['Última modificación', rd.lastChanged ? fmtDay(rd.lastChanged) : 'No publicada'],
        ['Estados', (rd.statuses || []).join(', ') || 'No publicados'],
        ['Servidores de nombres (RDAP)', (rd.nameservers || []).join(', ') || 'No publicados']
      ]));
    } else {
      s.appendChild(h('p', { class: 'muted', text: rd.note || rd.error || 'No verificable con las comprobaciones disponibles.' }));
    }

    s.appendChild(h('h4', { text: 'Ubicación aproximada de las IP' }));
    var okGeo = (di.geo || []).filter(function (g) { return g.status === 'ok'; });
    if (okGeo.length) {
      s.appendChild(table(['IP', 'País', 'Región / ciudad', 'Organización', 'Zona horaria'], okGeo.map(function (g) {
        return [g.ip, (g.country || 'n/d') + (g.countryCode ? ' (' + g.countryCode + ')' : ''), [g.region, g.city].filter(Boolean).join(' / ') || 'n/d', (g.org || 'n/d') + (g.asn ? ' · ' + g.asn : ''), g.timezone || 'n/d'];
      })));
    } else {
      s.appendChild(h('p', { class: 'muted', text: (di.geo || []).length ? 'No verificable con las comprobaciones disponibles.' : 'No hay IP públicas que consultar.' }));
    }
    s.appendChild(h('p', { class: 'muted small', text: 'Ubicación aproximada: puede ser incorrecta. Con un CDN o proxy corresponde al proveedor, no al servidor de origen.' }));

    s.appendChild(h('h4', { text: 'DNSSEC' }));
    var dk = di.dnssec || {};
    var dkText = dk.status === 'firmado' ? 'Firmado (' + dk.dsRecords + ' registro(s) DS)' + (dk.validated ? ' y validado por el resolvedor.' : '; el resolvedor no confirmó la validación.')
      : (dk.status === 'no firmado' ? 'No firmado: no hay registros DS publicados.' : (dk.note || dk.error || 'No verificable con las comprobaciones disponibles.'));
    s.appendChild(h('p', { text: dkText }));
    return s;
  }

  function assessBadge(text) {
    var cls = 'st-probable';
    if (text === 'Correcto' || text === 'Aceptable') cls = 'st-confirmado';
    else if (text === 'Inseguro') cls = 'sev-medio';
    return h('span', { class: 'badge ' + cls, text: text });
  }

  function infraSection(inf) {
    var s = section('Infraestructura y DNS', 'Datos obtenidos de DNS público, sin conectarse al sitio. Cada dato indica sus límites.');
    if (!inf) { s.appendChild(h('p', { class: 'muted', text: 'No disponible: el análisis de infraestructura no pudo completarse. Repite el análisis.' })); return s; }
    s.appendChild(kv([['Dominio analizado', inf.host], ['Dominio base (estimado)', inf.domain]]));
    if (inf.available === false || inf.noRecords) {
      s.appendChild(h('p', { class: 'banner', text: (inf.limitations && inf.limitations[0]) || 'No se pudo completar la consulta DNS.' }));
      return s;
    }

    s.appendChild(h('h4', { text: 'Direcciones IP y red' }));
    if ((inf.ips || []).length) {
      s.appendChild(table(['IP', 'DNS inverso', 'Red (ASN)', 'País de registro'], inf.ips.map(function (i) {
        return [i.ip + (i.public ? '' : ' (no pública)'), (i.ptr || []).join(', ') || '—',
          i.asn ? i.asn + (i.asName ? ' · ' + i.asName : '') + (i.prefix ? ' · ' + i.prefix : '') : 'No verificable',
          i.country ? i.country + (i.registry ? ' (' + i.registry.toUpperCase() + ')' : '') : 'No verificable'];
      })));
      s.appendChild(h('p', { class: 'muted small', text: 'El país es el de registro del bloque IP, no la ubicación física del servidor. Con un CDN o proxy, la IP no es la del servidor de origen.' }));
    } else {
      s.appendChild(h('p', { class: 'muted', text: 'No se obtuvieron direcciones IP para este nombre.' }));
    }

    s.appendChild(h('h4', { text: 'Proveedores detectados' }));
    if ((inf.hosting || []).length) {
      s.appendChild(table(['Proveedor', 'Función', 'Confianza', 'Evidencia'], inf.hosting.map(function (x) {
        return [x.name, x.role, x.confidence, x.evidence.join(' · ')];
      })));
    } else {
      s.appendChild(h('p', { class: 'muted', text: 'Sin proveedor identificable con los datos DNS (no significa que no exista uno).' }));
    }

    s.appendChild(h('h4', { text: 'Registros DNS' }));
    var order = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'CAA'];
    s.appendChild(table(['Tipo', 'Estado', 'Valores'], order.map(function (k) {
      var r = inf.records[k] || { status: 'no verificable', values: [] };
      var shown = r.values.length ? r.values.map(function (v) { return String(v).slice(0, 200); }).join(' · ') : '—';
      return [k, r.status, shown];
    })));

    s.appendChild(h('h4', { text: 'Seguridad del correo (SPF, DMARC)' }));
    var em = inf.email;
    if (em) {
      s.appendChild(kv([
        ['Dominio evaluado', em.domain],
        ['Recibe correo (MX)', em.receivesMail === null ? 'No verificable con las comprobaciones disponibles' : (em.receivesMail ? 'Sí' : 'No')],
        ['SPF', em.spf ? h('span', {}, assessBadge(em.spf.assessment), ' ', em.spf.note, em.spf.value ? h('div', { class: 'muted small', text: em.spf.value }) : null) : 'No verificable con las comprobaciones disponibles'],
        ['DMARC', em.dmarc ? h('span', {}, assessBadge(em.dmarc.assessment), ' ', em.dmarc.note, em.dmarc.value ? h('div', { class: 'muted small', text: em.dmarc.value }) : null) : 'No verificable con las comprobaciones disponibles'],
        ['DKIM', em.dkim]
      ]));
    }
    return s;
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

    // Resumen ejecutivo (solo datos ya presentes en el resultado)
    if (r.summary && !r.summary.incomplete) {
      var sSum = section('Resumen ejecutivo');
      sSum.appendChild(list(r.summary.points));
      if (r.summary.priorities.length) {
        sSum.appendChild(h('h4', { text: 'Prioridades (detalle y recomendaciones más abajo)' }));
        sSum.appendChild(h('ol', {}, r.summary.priorities.map(function (p) {
          return h('li', {}, sevBadge(p.severity), ' ' + p.title + ' ', h('span', { class: 'muted small', text: '(' + p.id + ')' }));
        })));
      } else {
        sSum.appendChild(h('p', { class: 'muted', text: 'No hay hallazgos de gravedad Baja o superior en las comprobaciones realizadas.' }));
      }
      resultsBox.appendChild(sSum);
    }

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

    resultsBox.appendChild(infraSection(r.infrastructure));
    resultsBox.appendChild(domainSection(r.domainIntel));
    resultsBox.appendChild(subdomainsSection(r.subdomains));

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
