/* NEXO WEB GUARD - generador del informe PDF (jsPDF). Se ejecuta en el navegador del usuario. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NWGPdf = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var PAGE_W = 210, PAGE_H = 297, M = 15, CW = PAGE_W - 2 * M, BOTTOM = PAGE_H - 18;
  var C = {
    navy: [10, 22, 40], teal: [20, 184, 166], blue: [59, 130, 246], text: [30, 41, 59],
    muted: [100, 116, 139], line: [203, 213, 225], zebra: [244, 247, 251], head: [226, 232, 240]
  };
  var SEV_COLOR = {
    'Informativo': [100, 116, 139], 'Bajo': [37, 99, 235], 'Medio': [217, 119, 6], 'Alto': [234, 88, 12], 'Crítico': [185, 28, 28]
  };
  var MAP = { '‘': "'", '’': "'", '“': '"', '”': '"', '–': '-', '—': '-', '…': '...', '•': '-', '→': '->', '≥': '>=', '≤': '<=', ' ': ' ', '✓': 'OK' };

  /** jsPDF con fuentes estándar solo admite Latin-1: se normaliza el texto para evitar caracteres corruptos. */
  function clean(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/[‘’“”–—…•→≥≤ ✓]/g, function (c) { return MAP[c]; })
      .replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '')
      .replace(/[^\n -ÿ]/g, '?');
  }

  function fmtDate(iso) {
    if (!iso) return 'No disponible';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toLocaleString('es-CL', { dateStyle: 'long', timeStyle: 'short' });
  }
  /* Fechas del registro del dominio: en UTC, como las publica el registro. */
  function fmtDayUtc(iso) {
    if (!iso) return 'No disponible';
    var d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso) : d.toLocaleDateString('es-CL', { dateStyle: 'long', timeZone: 'UTC' });
  }
  function fmtDay(iso) {
    if (!iso) return 'No disponible';
    var d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso) : d.toLocaleDateString('es-CL', { dateStyle: 'long' });
  }

  function Layout(doc) {
    this.doc = doc;
    this.y = M;
  }
  Layout.prototype.lh = function (size) { return size * 0.46; };
  Layout.prototype.ensure = function (h) {
    if (this.y + h > BOTTOM) { this.doc.addPage(); this.y = M + 4; return true; }
    return false;
  };
  Layout.prototype.setText = function (size, bold, color) {
    this.doc.setFont('helvetica', bold ? 'bold' : 'normal');
    this.doc.setFontSize(size);
    var c = color || C.text;
    this.doc.setTextColor(c[0], c[1], c[2]);
  };
  Layout.prototype.h1 = function (text) {
    this.ensure(14);
    this.y += 3;
    this.doc.setFillColor(C.teal[0], C.teal[1], C.teal[2]);
    this.doc.rect(M, this.y - 4.5, 1.6, 7, 'F');
    this.setText(13, true, C.navy);
    this.doc.text(clean(text), M + 4, this.y);
    this.y += 6;
  };
  Layout.prototype.h2 = function (text) {
    this.ensure(9);
    this.setText(10.5, true, C.navy);
    this.doc.text(clean(text), M, this.y);
    this.y += 5.5;
  };
  Layout.prototype.para = function (text, o) {
    o = o || {};
    var size = o.size || 9;
    var x = M + (o.indent || 0);
    this.setText(size, o.bold, o.color);
    var lines = this.doc.splitTextToSize(clean(text), CW - (o.indent || 0));
    for (var i = 0; i < lines.length; i++) {
      this.ensure(this.lh(size) + 1);
      this.setText(size, o.bold, o.color);
      this.doc.text(lines[i], x, this.y);
      this.y += this.lh(size);
    }
    this.y += o.gap === undefined ? 1.5 : o.gap;
  };
  Layout.prototype.link = function (label, url, indent) {
    var size = 8.5;
    this.ensure(5);
    this.setText(size, false, C.blue);
    var lines = this.doc.splitTextToSize(clean(label), CW - (indent || 0));
    var self = this;
    lines.forEach(function (ln, i) {
      self.ensure(self.lh(size) + 1);
      self.setText(size, false, C.blue);
      if (i === 0 && url && self.doc.textWithLink) self.doc.textWithLink(ln, M + (indent || 0), self.y, { url: url });
      else self.doc.text(ln, M + (indent || 0), self.y);
      self.y += self.lh(size);
    });
    this.y += 1;
  };
  Layout.prototype.badge = function (text, color, x, y) {
    var t = clean(text);
    this.setText(8, true, [255, 255, 255]);
    var w = this.doc.getTextWidth(t) + 5;
    this.doc.setFillColor(color[0], color[1], color[2]);
    this.doc.roundedRect(x, y - 3.6, w, 5.2, 1.2, 1.2, 'F');
    this.doc.text(t, x + 2.5, y);
    return w;
  };
  Layout.prototype.kv = function (rows) {
    var self = this;
    rows.forEach(function (r) {
      var size = 9;
      self.setText(size, false, C.text);
      var lines = self.doc.splitTextToSize(clean(r[1]), CW - 48);
      var h = Math.max(1, lines.length) * self.lh(size) + 1.5;
      self.ensure(h);
      self.setText(size, true, C.muted);
      self.doc.text(clean(r[0]), M, self.y);
      self.setText(size, false, C.text);
      lines.forEach(function (ln, i) { self.doc.text(ln, M + 46, self.y + i * self.lh(size)); });
      self.y += h;
    });
    this.y += 1;
  };
  /** Tabla con saltos de página y cabecera repetida. cols: [{title, w}] (w en mm, suma = CW) */
  Layout.prototype.table = function (cols, rows) {
    var self = this;
    var size = 8, pad = 1.6, lh = this.lh(size);
    function header() {
      self.ensure(9);
      self.doc.setFillColor(C.head[0], C.head[1], C.head[2]);
      self.doc.rect(M, self.y - 3.8, CW, 6.4, 'F');
      self.setText(size, true, C.navy);
      var x = M;
      cols.forEach(function (c) { self.doc.text(clean(c.title), x + pad, self.y); x += c.w; });
      self.y += 5;
    }
    header();
    rows.forEach(function (row, ri) {
      var cells = row.map(function (cell, ci) {
        var lines = self.doc.splitTextToSize(clean(cell), cols[ci].w - 2 * pad);
        return lines.length > 30 ? lines.slice(0, 30).concat(['...']) : lines;
      });
      var h = Math.max.apply(null, cells.map(function (l) { return l.length; })) * lh + 2 * pad - 0.6;
      if (self.y + h > BOTTOM) { self.doc.addPage(); self.y = M + 4; header(); }
      if (ri % 2 === 0) {
        self.doc.setFillColor(C.zebra[0], C.zebra[1], C.zebra[2]);
        self.doc.rect(M, self.y - 3.6, CW, h, 'F');
      }
      var x = M;
      cells.forEach(function (lines, ci) {
        self.setText(size, ci === 0, ci === 0 ? C.navy : C.text);
        lines.forEach(function (ln, li) { self.doc.text(ln, x + pad, self.y + li * lh); });
        x += cols[ci].w;
      });
      self.y += h;
    });
    this.y += 3;
  };
  Layout.prototype.hr = function () {
    this.doc.setDrawColor(C.line[0], C.line[1], C.line[2]);
    this.doc.line(M, this.y, PAGE_W - M, this.y);
    this.y += 3;
  };

  function drawLogo(doc, x, y, s) {
    // Escudo con red de nodos (vectorial, original)
    doc.setDrawColor(C.teal[0], C.teal[1], C.teal[2]);
    doc.setLineWidth(0.7);
    doc.setFillColor(C.navy[0], C.navy[1], C.navy[2]);
    var p = function (a, b) { return [a * s / 64, b * s / 64]; };
    var pts = [p(32, 3), p(56, 12), p(56, 30), p(46, 50), p(32, 61), p(18, 50), p(8, 30), p(8, 12)];
    var segs = [];
    for (var i = 1; i < pts.length; i++) segs.push([pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]]);
    segs.push([pts[0][0] - pts[pts.length - 1][0], pts[0][1] - pts[pts.length - 1][1]]);
    doc.lines(segs, x + pts[0][0], y + pts[0][1], [1, 1], 'FD', true);
    var n = [p(32, 18), p(21, 30), p(43, 30), p(32, 44)];
    doc.setLineWidth(0.5);
    [[0, 1], [0, 2], [1, 3], [2, 3], [1, 2]].forEach(function (e) {
      doc.line(x + n[e[0]][0], y + n[e[0]][1], x + n[e[1]][0], y + n[e[1]][1]);
    });
    doc.setFillColor(C.teal[0], C.teal[1], C.teal[2]);
    n.forEach(function (q, i) {
      if (i === 3) doc.setFillColor(C.blue[0], C.blue[1], C.blue[2]);
      doc.circle(x + q[0], y + q[1], 1.5, 'F');
    });
  }

  function findingBlock(L, f, prevSource) {
    var doc = L.doc;
    L.ensure(24);
    var col = SEV_COLOR[f.severity] || SEV_COLOR['Informativo'];
    var x0 = M;
    var w = L.badge(f.severity, col, x0, L.y);
    L.setText(8, false, C.muted);
    doc.text('Confianza: ' + clean(f.confidence || 'No indicada') + (f.category ? '   |   ' + clean(f.category) : '') + (f.id ? '   |   ' + clean(f.id) : ''), x0 + w + 3, L.y);
    L.y += 5;
    L.para(f.title, { size: 10, bold: true, color: C.navy, gap: 1 });
    if (f.description) L.para(f.description, { size: 8.5 });
    if (f.evidence && f.evidence.length) {
      L.para('Evidencia:', { size: 8.5, bold: true, color: C.muted, gap: 0.5 });
      f.evidence.forEach(function (e) { L.para('- ' + e, { size: 8.5, indent: 3, gap: 0.5 }); });
    }
    if (f.source && f.source !== prevSource) L.para('Fuente: ' + f.source, { size: 8, color: C.muted, gap: 0.8 });
    if (f.recommendation) {
      L.para('Recomendación:', { size: 8.5, bold: true, color: C.muted, gap: 0.5 });
      L.para(f.recommendation, { size: 8.5, indent: 3, gap: 0.8 });
    }
    if (f.limitations) L.para('Limitaciones: ' + f.limitations, { size: 8, color: C.muted, gap: 1 });
    L.hr();
  }

  /**
   * @param {Function} JsPDF constructor jsPDF
   * @param {object} r resultado final del análisis (con r.risk)
   * @param {object} core NWGCore (para etiquetas)
   */
  function build(JsPDF, r, core) {
    var doc = new JsPDF({ unit: 'mm', format: 'a4', compress: true });
    doc.setProperties({ title: 'Informe de análisis de seguridad web - ' + clean(r.host || ''), subject: 'NEXO WEB GUARD', creator: 'NEXO WEB GUARD ' + clean(r.appVersion || '') });
    var L = new Layout(doc);

    // Portada / cabecera
    doc.setFillColor(C.navy[0], C.navy[1], C.navy[2]);
    doc.rect(0, 0, PAGE_W, 44, 'F');
    doc.setFillColor(C.teal[0], C.teal[1], C.teal[2]);
    doc.rect(0, 44, PAGE_W, 1.2, 'F');
    drawLogo(doc, M, 8, 26);
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(20);
    doc.text('NEXO WEB GUARD', M + 32, 21);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(11);
    doc.setTextColor(165, 243, 252);
    doc.text('Informe de análisis de seguridad web', M + 32, 29);
    doc.setFontSize(8.5);
    doc.setTextColor(200, 215, 235);
    doc.text('Análisis defensivo y no intrusivo', M + 32, 35);
    L.y = 54;

    L.kv([
      ['URL analizada', r.requestedUrl || 'No disponible'],
      ['URL final', r.finalUrl || 'No disponible'],
      ['Fecha y hora', fmtDate(r.analyzedAt)],
      ['Identificador', r.reportId || 'No disponible'],
      ['Versión de la herramienta', r.appVersion || 'No disponible'],
      ['Estado del análisis', r.status === 'completed' ? 'Completado' : (r.status === 'stopped' ? 'Detenido' : 'Fallido')]
    ]);

    // Resumen y riesgo
    L.h1('1. Resumen y nivel de riesgo');
    var risk = r.risk || { incomplete: true, message: core.INCOMPLETE_MESSAGE };
    if (risk.incomplete) {
      L.para(risk.message + '.', { size: 10, bold: true, color: SEV_COLOR['Medio'] });
      if (risk.basis) L.para('Motivo: ' + risk.basis, { size: 9 });
      if (r.error) L.para('Error registrado: ' + r.error, { size: 9 });
      if (r.stoppedReason) L.para(r.stoppedReason, { size: 9 });
      L.para('Se recomienda repetir el análisis o realizar una comprobación autorizada directamente en el servidor.', { size: 9 });
    } else {
      L.ensure(10);
      var bw = L.badge('Riesgo observado: ' + risk.level, SEV_COLOR[risk.level] || SEV_COLOR['Informativo'], M, L.y);
      L.y += 6;
      L.para(risk.basis, { size: 9 });
      var cts = core.SEVERITIES.slice().reverse().map(function (s) { return s + ': ' + ((risk.counts || {})[s] || 0); }).join('   |   ');
      L.para('Hallazgos por gravedad efectiva (incluye CVE): ' + cts, { size: 8.5, color: C.muted });
      L.para('La gravedad técnica y la confianza de cada resultado se indican por separado. Este nivel no es una puntuación de seguridad ni garantiza la ausencia de vulnerabilidades.', { size: 8.5, color: C.muted });
      var sm = r.summary;
      if (sm) {
        L.para('Resumen ejecutivo:', { size: 9.5, bold: true, color: C.navy, gap: 0.8 });
        (sm.points || []).forEach(function (t) { L.para('- ' + t, { size: 8.5, indent: 3, gap: 0.5 }); });
        if ((sm.priorities || []).length) {
          L.para('Prioridades (detalle en la sección 10):', { size: 9, bold: true, color: C.navy, gap: 0.8 });
          sm.priorities.forEach(function (p, i) { L.para((i + 1) + '. [' + p.severity + '] ' + p.title + ' (' + p.id + ')', { size: 8.5, indent: 3, gap: 0.5 }); });
        } else {
          L.para('No hay hallazgos de gravedad Baja o superior en las comprobaciones realizadas.', { size: 8.5, indent: 3 });
        }
      }
    }

    // HTTPS
    L.h1('2. HTTPS y certificado');
    var h = r.https || {};
    var cert = h.certificate;
    L.kv([
      ['HTTPS disponible', h.available || 'No verificable con las comprobaciones disponibles'],
      ['Estado', h.state || 'No verificable con las comprobaciones disponibles'],
      ['Redirección HTTP a HTTPS', h.redirectsHttpToHttps || 'No verificable con las comprobaciones disponibles'],
      ['Protocolo TLS negociado', h.tlsProtocol || 'No verificable con las comprobaciones disponibles'],
      ['Certificado válido', cert ? (cert.validForClient ? 'Sí (superó la validación del cliente)' : 'No: ' + (cert.validationError || 'error de validación')) : 'No verificable con las comprobaciones disponibles'],
      ['Titular (CN)', cert && cert.subject ? cert.subject : 'No disponible'],
      ['Emisor', cert && cert.issuer ? cert.issuer : 'No disponible'],
      ['Válido desde', cert ? fmtDay(cert.validFrom) : 'No disponible'],
      ['Válido hasta', cert ? fmtDay(cert.validTo) + (typeof cert.daysLeft === 'number' ? ' (' + cert.daysLeft + ' días restantes)' : '') : 'No disponible'],
      ['Nombres alternativos', cert && cert.altNames && cert.altNames.length ? cert.altNames.join(', ') : 'No disponible']
    ]);
    (h.notes || []).forEach(function (n) { L.para(n, { size: 8.5, color: C.muted }); });

    // Tecnologías
    L.h1('3. Tecnologías detectadas');
    L.para('Estados: Confirmado (evidencia directa), Probable (indicios indirectos), No detectado (sin señales; no prueba ausencia), Desconocido (sin información).', { size: 8.5, color: C.muted });
    var techRows = (r.technologies || []).map(function (t) {
      return [t.name, t.status + ' (confianza ' + (t.confidence || 'n/d') + ')', t.version ? t.version + (t.versionStatus ? ' (' + t.versionStatus + ')' : '') : '-', (t.evidence || []).concat(t.note ? [t.note] : []).join(' | ') || '-'];
    });
    if (techRows.length) L.table([{ title: 'Tecnología', w: 40 }, { title: 'Estado', w: 36 }, { title: 'Versión', w: 28 }, { title: 'Evidencia / notas', w: 76 }], techRows);
    else L.para('No hay datos de tecnologías disponibles.', { size: 9 });

    // PHP
    L.h1('4. PHP Security Analyzer');
    var p = r.php;
    if (p) {
      L.kv([
        ['Estado de PHP', p.status + ' (confianza ' + (p.confidence || 'n/d') + ')'],
        ['Versión', p.version ? p.version + ' - declarada por el servidor, no verificada en el servidor' : 'No confirmada'],
        ['Origen de la versión', p.versionSource || 'No disponible'],
        ['Ciclo de soporte', p.support && p.support.note ? p.support.note : 'No evaluable sin una versión'],
        ['Evidencia', (p.evidence || []).join(' | ') || 'Sin evidencia directa']
      ]);
      L.para(p.message || '', { size: 9 });
      if (p.note && p.note !== p.message) L.para(p.note, { size: 8.5, color: C.muted });
      L.para('PHP no se considera vulnerable por el solo hecho de estar presente. Las vulnerabilidades se asocian únicamente a versiones identificadas con evidencia.', { size: 8.5, color: C.muted });
    } else {
      L.para('No hay datos de PHP disponibles porque el análisis no obtuvo respuesta del sitio.', { size: 9 });
    }

    // Infraestructura y DNS
    L.h1('5. Infraestructura y DNS');
    var inf = r.infrastructure;
    if (!inf) {
      L.para('No disponible: el análisis de infraestructura no pudo completarse. Repita el análisis.', { size: 9 });
    } else if (inf.available === false || inf.noRecords) {
      L.para((inf.limitations && inf.limitations[0]) || 'No se pudo completar la consulta DNS.', { size: 9 });
    } else {
      L.para('Datos obtenidos de DNS público, sin conectarse al sitio. Dominio: ' + inf.host + ' (dominio base estimado: ' + inf.domain + ').', { size: 8.5, color: C.muted });
      L.h2('Direcciones IP y red');
      if ((inf.ips || []).length) {
        L.table([{ title: 'IP', w: 40 }, { title: 'DNS inverso', w: 44 }, { title: 'Red (ASN)', w: 58 }, { title: 'País de registro', w: 38 }],
          inf.ips.map(function (i) {
            return [i.ip + (i.public ? '' : ' (no pública)'), (i.ptr || []).join(', ') || '-',
              i.asn ? i.asn + (i.asName ? ' - ' + i.asName : '') + (i.prefix ? ' - ' + i.prefix : '') : 'No verificable',
              i.country ? i.country + (i.registry ? ' (' + String(i.registry).toUpperCase() + ')' : '') : 'No verificable'];
          }));
        L.para('El país es el de registro del bloque IP, no la ubicación física del servidor. Con un CDN o proxy, la IP no es la del servidor de origen.', { size: 8.5, color: C.muted });
      } else {
        L.para('No se obtuvieron direcciones IP para este nombre.', { size: 9 });
      }
      L.h2('Proveedores detectados');
      if ((inf.hosting || []).length) {
        L.table([{ title: 'Proveedor', w: 40 }, { title: 'Función', w: 32 }, { title: 'Confianza', w: 20 }, { title: 'Evidencia', w: 88 }],
          inf.hosting.map(function (x) { return [x.name, x.role, x.confidence, x.evidence.join(' | ')]; }));
      } else {
        L.para('Sin proveedor identificable con los datos DNS (no significa que no exista uno).', { size: 9 });
      }
      L.h2('Registros DNS');
      L.table([{ title: 'Tipo', w: 16 }, { title: 'Estado', w: 28 }, { title: 'Valores', w: 136 }],
        ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'CAA'].map(function (k) {
          var rec = (inf.records || {})[k] || { status: 'no verificable', values: [] };
          return [k, rec.status, rec.values.length ? rec.values.map(function (v) { return String(v).slice(0, 200); }).join(' | ') : '-'];
        }));
      L.h2('Seguridad del correo (SPF, DMARC)');
      var em = inf.email;
      if (em) {
        L.kv([
          ['Dominio evaluado', em.domain],
          ['Recibe correo (MX)', em.receivesMail === null ? 'No verificable con las comprobaciones disponibles' : (em.receivesMail ? 'Sí' : 'No')],
          ['SPF', em.spf ? em.spf.assessment + ' - ' + em.spf.note + (em.spf.value ? ' [' + em.spf.value + ']' : '') : 'No verificable con las comprobaciones disponibles'],
          ['DMARC', em.dmarc ? em.dmarc.assessment + ' - ' + em.dmarc.note + (em.dmarc.value ? ' [' + em.dmarc.value + ']' : '') : 'No verificable con las comprobaciones disponibles'],
          ['DKIM', em.dkim]
        ]);
      }
    }

    // Dominio, ubicación y DNSSEC
    L.h1('6. Dominio, ubicación y DNSSEC');
    var di = r.domainIntel;
    if (!di) {
      L.para('No disponible: este análisis no pudo completarse. Repita el análisis.', { size: 9 });
    } else {
      L.h2('Datos del dominio (RDAP)');
      var rd = di.rdap || {};
      if (rd.status === 'ok') {
        L.kv([
          ['Dominio', di.domain],
          ['Registrador', rd.registrar || 'No publicado'],
          ['Fecha de registro', rd.registration ? fmtDayUtc(rd.registration) + (typeof rd.ageDays === 'number' ? ' (hace ' + rd.ageDays + ' días)' : '') : 'No publicada'],
          ['Fecha de expiración', rd.expiration ? fmtDayUtc(rd.expiration) + (typeof rd.daysToExpire === 'number' ? (rd.daysToExpire >= 0 ? ' (en ' + rd.daysToExpire + ' días)' : ' (vencido)') : '') : 'No publicada'],
          ['Última modificación', rd.lastChanged ? fmtDayUtc(rd.lastChanged) : 'No publicada'],
          ['Estados', (rd.statuses || []).join(', ') || 'No publicados'],
          ['Servidores de nombres', (rd.nameservers || []).join(', ') || 'No publicados']
        ]);
      } else {
        L.para(rd.note || rd.error || 'No verificable con las comprobaciones disponibles.', { size: 9 });
      }
      L.h2('Ubicación aproximada de las IP');
      var okGeo = (di.geo || []).filter(function (g) { return g.status === 'ok'; });
      if (okGeo.length) {
        L.table([{ title: 'IP', w: 38 }, { title: 'País', w: 34 }, { title: 'Región / ciudad', w: 42 }, { title: 'Organización', w: 46 }, { title: 'Zona horaria', w: 20 }],
          okGeo.map(function (g) {
            return [g.ip, (g.country || 'n/d') + (g.countryCode ? ' (' + g.countryCode + ')' : ''), [g.region, g.city].filter(Boolean).join(' / ') || 'n/d', (g.org || 'n/d') + (g.asn ? ' - ' + g.asn : ''), g.timezone || 'n/d'];
          }));
      } else {
        L.para((di.geo || []).length ? 'No verificable con las comprobaciones disponibles.' : 'No hay IP públicas que consultar.', { size: 9 });
      }
      L.para('Ubicación aproximada: puede ser incorrecta. Con un CDN o proxy corresponde al proveedor, no al servidor de origen.', { size: 8.5, color: C.muted });
      L.h2('DNSSEC');
      var dk = di.dnssec || {};
      L.para(dk.status === 'firmado' ? 'Firmado (' + dk.dsRecords + ' registro(s) DS)' + (dk.validated ? ' y validado por el resolvedor.' : '; el resolvedor no confirmó la validación.')
        : (dk.status === 'no firmado' ? 'No firmado: no hay registros DS publicados.' : (dk.note || dk.error || 'No verificable con las comprobaciones disponibles.')), { size: 9 });
    }

    // Subdominios
    L.h1('7. Subdominios (Certificate Transparency)');
    var sd = r.subdomains;
    if (!sd) {
      L.para('No disponible: este análisis no pudo completarse. Repita el análisis.', { size: 9 });
    } else if (sd.status !== 'ok') {
      L.para(sd.note || 'No verificable con las comprobaciones disponibles.', { size: 9 });
    } else {
      L.kv([
        ['Dominio base (estimado)', sd.domain],
        ['Fuentes consultadas', (sd.ctSources || []).join(', ') || 'n/d'],
        ['Subdominios encontrados', String(sd.total) + (sd.wildcard ? ' (existe un certificado comodín)' : '')],
        ['Resueltos por DNS', sd.checked + ' de ' + sd.total]
      ]);
      if ((sd.resolved || []).length) {
        L.table([{ title: 'Subdominio', w: 56 }, { title: 'Estado', w: 22 }, { title: 'Destino', w: 62 }, { title: 'Notas', w: 40 }],
          sd.resolved.map(function (x) {
            var notes = [];
            if (x.sensitive) notes.push('nombre sensible');
            if (x.takeoverProne && x.state === 'colgante') notes.push('posible takeover (' + x.provider + ')');
            else if (x.provider) notes.push(x.provider);
            return [x.name, x.state, (x.cnames.length ? 'CNAME ' + x.cnames[0] + (x.ips.length ? ' -> ' : '') : '') + (x.ips.slice(0, 2).join(', ') || (x.cnames.length ? '' : '-')), notes.join(' | ') || '-'];
          }));
      }
      var restPdf = (sd.names || []).filter(function (nm) { return !(sd.resolved || []).some(function (x) { return x.name === nm; }); });
      if (restPdf.length) L.para('Otros subdominios sin resolver (' + restPdf.length + (sd.truncated ? '+' : '') + '): ' + restPdf.slice(0, 60).join(', ') + (restPdf.length > 60 ? ' ...' : ''), { size: 8.5, color: C.muted });
      L.para('La lista procede de registros públicos de certificados: puede ser incompleta. Solo se hicieron consultas DNS; no se conectó a ningún subdominio por HTTP.', { size: 8.5, color: C.muted });
    }

    // Cabeceras
    L.h1('8. Cabeceras de seguridad');
    if ((r.headers || []).length) {
      L.table([{ title: 'Cabecera', w: 38 }, { title: 'Estado', w: 22 }, { title: 'Función y riesgo', w: 70 }, { title: 'Recomendación', w: 50 }],
        r.headers.map(function (x) {
          return [x.header, x.assessment + (x.present ? ' (presente)' : ''), x.function + ' Riesgo: ' + x.risk + (x.note ? ' Nota: ' + x.note : ''), x.recommendation];
        }));
      L.para('La ausencia de una cabecera no implica automáticamente una vulnerabilidad: depende del contexto del sitio.', { size: 8.5, color: C.muted });
    } else {
      L.para('No disponible: no se obtuvo una respuesta HTTP analizable.', { size: 9 });
    }

    // CVE
    L.h1('9. Vulnerabilidades conocidas (CVE)');
    L.para('Fuente: API oficial de NVD. Clases: A = confirmada con evidencia suficiente; B = potencialmente relevante para la versión detectada; C = componente o versión no confirmados. Una vulnerabilidad existente en un componente no demuestra que este sitio sea vulnerable.', { size: 8.5, color: C.muted });
    (r.vulnLookups || []).forEach(function (lk) {
      var res = (r.vulnLookupSummary || {})[lk.product + '@' + lk.version];
      L.para('Consulta: ' + lk.component + ' ' + lk.version + ' (clase ' + lk.classification + ')' + (res ? ' - ' + res : ''), { size: 8.5, bold: true, color: C.navy, gap: 0.8 });
    });
    (r.vulnLookupErrors || []).forEach(function (e) { L.para('No se pudo completar la consulta: ' + e, { size: 8.5, color: SEV_COLOR['Medio'] }); });
    if (!(r.vulnerabilities || []).length) {
      L.para((r.vulnLookups || []).length ? 'La consulta no devolvió CVE para las versiones identificadas, o no pudo completarse (ver arriba). Esto no garantiza la ausencia de vulnerabilidades.' : 'No se consultaron CVE: no se identificó ninguna versión de componente verificable desde el exterior.', { size: 9 });
    }
    (r.vulnerabilities || []).forEach(function (v) {
      L.ensure(28);
      var col = SEV_COLOR[v.severity] || SEV_COLOR['Informativo'];
      var w = L.badge(v.severityKnown ? v.severity : 'Sin puntuación', col, M, L.y);
      L.setText(8, true, C.navy);
      doc.text('Clase ' + v.classification + '  |  CVSS ' + (v.cvssScore !== null ? v.cvssScore + (v.cvssVersion ? ' (v' + v.cvssVersion + ')' : '') : 'no disponible'), M + w + 3, L.y);
      L.y += 5;
      L.link(v.id + '  -  ' + v.url, v.url);
      L.para(v.product + ' (versión detectada: ' + v.detectedVersion + ') - Publicada: ' + (v.published ? fmtDay(v.published) : 'no disponible'), { size: 8.5, bold: true, gap: 0.8 });
      L.para(v.description + (v.descriptionLang === 'en' ? ' (descripción original en inglés, fuente NVD)' : ''), { size: 8.5 });
      L.para('Versiones afectadas: ' + ((v.affectedVersions || []).join('; ') || 'no detalladas'), { size: 8.5, gap: 0.5 });
      L.para('Versiones corregidas: ' + ((v.fixedVersions || []).join(', ') || 'no documentadas en la fuente'), { size: 8.5, gap: 0.5 });
      L.para('Recomendación: ' + v.recommendation, { size: 8.5, color: C.muted, gap: 1 });
      L.hr();
    });

    // Hallazgos
    L.h1('10. Hallazgos, evidencias y recomendaciones');
    var all = (r.findings || []);
    if (!all.length) L.para('No hay hallazgos registrados.', { size: 9 });
    var ordered = core.sortFindings(all);
    var prevSource = null;
    ordered.forEach(function (f) { findingBlock(L, f, prevSource); prevSource = f.source || null; });

    // Comprobaciones no realizadas / limitaciones
    L.h1('11. Comprobaciones no realizadas');
    (r.notPerformed || []).forEach(function (t) { L.para('- ' + t, { size: 8.5, gap: 0.8 }); });
    L.h1('12. Limitaciones del análisis');
    (r.limitations || []).forEach(function (t) { L.para('- ' + t, { size: 8.5, gap: 0.8 }); });
    if (r.requests) L.para('Solicitudes realizadas al sitio: ' + r.requests.used + ' (máximo permitido: ' + r.requests.max + '). robots.txt consultado: ' + (r.robots && r.robots.checked ? 'sí' : 'no') + '.', { size: 8.5, color: C.muted });

    // Fuentes
    L.h1('13. Fuentes oficiales consultadas');
    (r.sources || []).forEach(function (s) {
      L.link(s.title + ' - ' + s.url, s.url);
    });

    // Aviso
    L.h1('14. Aviso importante');
    L.para('Este informe procede de un análisis externo, pasivo y no intrusivo, basado en lo que el sitio publica en solicitudes de bajo impacto. No sustituye a una auditoría de seguridad autorizada ni garantiza la ausencia de vulnerabilidades. Las versiones indicadas son declaraciones del sitio y deben confirmarse con acceso autorizado al servidor. Los resultados no se han almacenado en ningún servidor.', { size: 9 });

    // Pie de página en todas las páginas
    var total = doc.getNumberOfPages();
    for (var i = 1; i <= total; i++) {
      doc.setPage(i);
      doc.setDrawColor(C.line[0], C.line[1], C.line[2]);
      doc.line(M, PAGE_H - 12, PAGE_W - M, PAGE_H - 12);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(C.muted[0], C.muted[1], C.muted[2]);
      doc.text(clean('NEXO WEB GUARD v' + (r.appVersion || '') + '  |  ' + (r.reportId || '') + '  |  ' + (r.host || '')), M, PAGE_H - 7.5);
      doc.text('Página ' + i + ' de ' + total, PAGE_W - M, PAGE_H - 7.5, { align: 'right' });
    }
    return doc;
  }

  return { build: build, clean: clean };
});
