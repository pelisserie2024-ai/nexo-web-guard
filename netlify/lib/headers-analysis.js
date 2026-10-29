'use strict';
/** Análisis contextual de cabeceras de seguridad HTTP. */

function parseCsp(value) {
  const d = {};
  String(value || '').split(';').forEach((part) => {
    const t = part.trim().split(/\s+/);
    if (t[0]) d[t[0].toLowerCase()] = t.slice(1);
  });
  return d;
}

function item(key, label, present, value, assessment, severity, fn, risk, rec, note) {
  return {
    header: label, key, present, value: value ? String(value).slice(0, 300) : null,
    assessment, severity, function: fn, risk, recommendation: rec, note: note || ''
  };
}

/**
 * @param {object} headers cabeceras en minúsculas
 * @param {{isHttps:boolean}} ctx
 */
function analyzeSecurityHeaders(headers, ctx) {
  const h = headers || {};
  const isHttps = !!(ctx && ctx.isHttps);
  const out = [];

  // Content-Security-Policy
  {
    const v = h['content-security-policy'];
    const fn = 'Indica al navegador desde qué orígenes puede cargar scripts, estilos, imágenes y marcos; reduce el impacto de ataques XSS e inyección de contenido.';
    const risk = 'Sin CSP, un fallo de inyección de scripts (XSS) tendría más margen de explotación. La ausencia no es una vulnerabilidad por sí sola.';
    const rec = 'Definir una CSP progresiva (empezando con Content-Security-Policy-Report-Only) que limite script-src, object-src y frame-ancestors, evitando \'unsafe-inline\' y comodines.';
    if (!v) {
      const ro = h['content-security-policy-report-only'];
      out.push(item('csp', 'Content-Security-Policy', false, null, ro ? 'Revisar' : 'Ausente', 'Bajo', fn, risk, rec,
        ro ? 'Existe una política en modo solo informe (Report-Only): no bloquea nada todavía.' : 'Más relevante en sitios con formularios, sesiones o contenido de terceros.'));
    } else {
      const d = parseCsp(v);
      const script = d['script-src'] || d['default-src'] || [];
      const weak = [];
      if (script.includes("'unsafe-inline'") && !script.some((x) => x.startsWith("'nonce-") || x === "'strict-dynamic'")) weak.push("'unsafe-inline'");
      if (script.includes("'unsafe-eval'")) weak.push("'unsafe-eval'");
      if (script.includes('*') || script.includes('http:') || script.includes('data:')) weak.push('comodín/origen amplio');
      out.push(item('csp', 'Content-Security-Policy', true, v, weak.length ? 'Revisar' : 'Correcto', weak.length ? 'Bajo' : 'Informativo', fn, risk, rec,
        weak.length ? 'La política contiene elementos que debilitan su protección: ' + weak.join(', ') + '.' : 'Política presente; su eficacia real depende de su contenido completo.'));
    }
  }

  // Strict-Transport-Security
  {
    const v = h['strict-transport-security'];
    const fn = 'Obliga al navegador a usar siempre HTTPS con el dominio durante el tiempo indicado, evitando degradaciones a HTTP.';
    const risk = 'Sin HSTS, el primer acceso por HTTP puede ser interceptado o redirigido por un atacante en la red (ataque de degradación).';
    const rec = 'Enviar Strict-Transport-Security: max-age=31536000; includeSubDomains (y valorar "preload" cuando todo el dominio funcione con HTTPS).';
    if (!isHttps) {
      out.push(item('hsts', 'Strict-Transport-Security', !!v, v, 'No aplica', 'Informativo', fn, risk, rec, 'La respuesta analizada no se sirvió por HTTPS; HSTS solo se procesa sobre HTTPS.'));
    } else if (!v) {
      out.push(item('hsts', 'Strict-Transport-Security', false, null, 'Ausente', 'Medio', fn, risk, rec, 'El sitio sirve HTTPS pero no declara HSTS.'));
    } else {
      const m = String(v).match(/max-age\s*=\s*(\d+)/i);
      const age = m ? parseInt(m[1], 10) : 0;
      const low = age < 15552000;
      out.push(item('hsts', 'Strict-Transport-Security', true, v, low ? 'Revisar' : 'Correcto', low ? 'Bajo' : 'Informativo', fn, risk, rec,
        low ? 'max-age (' + age + ' s) inferior a 180 días; se recomienda al menos 1 año.' : 'Duración adecuada' + (/includesubdomains/i.test(v) ? ' e incluye subdominios.' : '.')));
    }
  }

  // X-Content-Type-Options
  {
    const v = h['x-content-type-options'];
    const fn = 'Impide que el navegador "adivine" el tipo de contenido (MIME sniffing) y trate un archivo como script.';
    const risk = 'Sin esta cabecera, ciertos archivos subidos o servidos con tipo incorrecto podrían interpretarse como ejecutables por el navegador.';
    const rec = 'Enviar X-Content-Type-Options: nosniff en todas las respuestas.';
    const ok = v && /nosniff/i.test(v);
    out.push(item('xcto', 'X-Content-Type-Options', !!v, v, ok ? 'Correcto' : (v ? 'Revisar' : 'Ausente'), ok ? 'Informativo' : 'Bajo', fn, risk, rec,
      v && !ok ? 'El valor esperado es "nosniff".' : ''));
  }

  // Referrer-Policy
  {
    const v = h['referrer-policy'];
    const fn = 'Controla cuánta información de la URL de origen se envía en la cabecera Referer al navegar a otros sitios.';
    const risk = 'Una política laxa puede filtrar rutas o parámetros internos a sitios de terceros. Los navegadores modernos ya aplican strict-origin-when-cross-origin por defecto.';
    const rec = 'Definir Referrer-Policy: strict-origin-when-cross-origin (o más estricta, como no-referrer, si no se necesita el origen).';
    const weak = v && /(unsafe-url|no-referrer-when-downgrade)/i.test(v);
    out.push(item('referrer', 'Referrer-Policy', !!v, v, !v ? 'Ausente' : (weak ? 'Revisar' : 'Correcto'), weak ? 'Bajo' : 'Informativo', fn, risk, rec,
      !v ? 'Impacto limitado: el valor por defecto del navegador ya es razonable.' : (weak ? 'El valor indicado envía la URL completa a otros orígenes.' : '')));
  }

  // Permissions-Policy
  {
    const v = h['permissions-policy'] || h['feature-policy'];
    const fn = 'Permite desactivar o limitar funciones del navegador (cámara, micrófono, geolocalización, pagos...) para la página y los marcos incrustados.';
    const risk = 'Sin restricciones, contenido de terceros incrustado podría solicitar funciones sensibles del navegador.';
    const rec = 'Definir Permissions-Policy con las funciones que el sitio no utiliza desactivadas, por ejemplo: camera=(), microphone=(), geolocation=().';
    out.push(item('permissions', 'Permissions-Policy', !!v, v, v ? 'Correcto' : 'Ausente', 'Informativo', fn, risk, rec,
      v && !h['permissions-policy'] ? 'Se usa la cabecera antigua Feature-Policy; conviene migrar a Permissions-Policy.' : (v ? '' : 'Mejora de endurecimiento; su ausencia es habitual.')));
  }

  // X-Frame-Options
  {
    const v = h['x-frame-options'];
    const csp = parseCsp(h['content-security-policy']);
    const hasFa = !!csp['frame-ancestors'];
    const fn = 'Impide que otros sitios incrusten la página en un marco (clickjacking).';
    const risk = 'Sin protección, otro sitio podría incrustar la página y engañar al usuario para que haga clic en acciones ocultas. Es relevante sobre todo en páginas con acciones sensibles.';
    const rec = 'Usar Content-Security-Policy: frame-ancestors \'self\' (preferido) o X-Frame-Options: DENY/SAMEORIGIN.';
    if (v) {
      const bad = /allow-from/i.test(v);
      out.push(item('xfo', 'X-Frame-Options', true, v, bad ? 'Revisar' : 'Correcto', bad ? 'Bajo' : 'Informativo', fn, risk, rec,
        bad ? 'ALLOW-FROM está obsoleto y los navegadores modernos lo ignoran; use frame-ancestors.' : ''));
    } else if (hasFa) {
      out.push(item('xfo', 'X-Frame-Options', false, null, 'Correcto', 'Informativo', fn, risk, rec, 'No presente, pero la protección está cubierta por CSP frame-ancestors.'));
    } else {
      out.push(item('xfo', 'X-Frame-Options', false, null, 'Ausente', 'Bajo', fn, risk, rec, 'Sin X-Frame-Options ni frame-ancestors en CSP.'));
    }
  }

  return out;
}

module.exports = { analyzeSecurityHeaders, parseCsp };
