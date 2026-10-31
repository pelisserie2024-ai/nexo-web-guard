'use strict';
/**
 * Análisis de infraestructura (solo DNS público): registros, IP, DNS inverso, ASN/proveedor,
 * seguridad del correo (SPF/DMARC), CAA y CNAME colgante.
 * No se conecta al sitio ni a puertos: únicamente consultas DNS.
 * ASN y país de registro: servicio DNS público de Team Cymru (IP to ASN mapping).
 */
const dns = require('dns');
const { isPublicIp, parseIPv6 } = require('./net-guard');

const PRIVATE_SUFFIXES = [
  'netlify.app', 'vercel.app', 'github.io', 'pages.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com',
  'blogspot.com', 'wordpress.com', 'azurewebsites.net', 'onrender.com', 'fly.dev', 'surge.sh', 'workers.dev'
];
const SECOND_LEVEL = new Set(['com', 'co', 'net', 'org', 'gov', 'edu', 'ac', 'gob', 'or', 'ne', 'go']);

/** Dominio "registrable" aproximado (sin lista pública de sufijos completa; ver limitaciones). */
function registrableDomain(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  for (const s of PRIVATE_SUFFIXES) {
    if (h === s) return s;
    if (h.endsWith('.' + s)) {
      const labels = h.slice(0, -(s.length + 1)).split('.');
      return labels[labels.length - 1] + '.' + s;
    }
  }
  const p = h.split('.');
  if (p.length <= 2) return h;
  const tld = p[p.length - 1];
  const sld = p[p.length - 2];
  if (tld.length === 2 && SECOND_LEVEL.has(sld)) return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}

async function safe(fn) {
  try {
    return { ok: true, v: await fn() };
  } catch (e) {
    return { ok: false, code: (e && e.code) || 'ERROR' };
  }
}

function recordOf(r, map) {
  if (r.ok) {
    return { status: r.v.length ? 'presente' : 'sin registros', values: (map ? r.v.map(map) : r.v).slice(0, 15) };
  }
  if (r.code === 'ENODATA' || r.code === 'ENOTFOUND') return { status: 'sin registros', values: [] };
  return { status: 'no verificable', values: [], error: r.code };
}

const txtJoin = (chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)).slice(0, 400);

function originName(ip, family) {
  if (family === 4) return ip.split('.').reverse().join('.') + '.origin.asn.cymru.com';
  const g = parseIPv6(ip);
  const hex = g.map((x) => x.toString(16).padStart(4, '0')).join('');
  return hex.split('').reverse().join('.') + '.origin6.asn.cymru.com';
}

async function enrichIp(resolver, ip, family, asCache) {
  const out = { ip, family, public: true, ptr: [], asn: null, prefix: null, country: null, registry: null, asName: null };
  const [ptr, origin] = await Promise.all([
    safe(() => resolver.reverse(ip)),
    safe(() => resolver.resolveTxt(originName(ip, family)))
  ]);
  if (ptr.ok) out.ptr = ptr.v.slice(0, 3);
  if (origin.ok && origin.v.length) {
    const parts = txtJoin(origin.v[0]).split('|').map((s) => s.trim());
    const asn = (parts[0] || '').split(/\s+/)[0];
    if (/^\d{1,10}$/.test(asn)) {
      out.asn = 'AS' + asn;
      out.prefix = parts[1] || null;
      out.country = /^[A-Z]{2}$/.test(parts[2] || '') ? parts[2] : null;
      out.registry = parts[3] || null;
      if (!asCache.has(asn)) {
        asCache.set(asn, safe(() => resolver.resolveTxt('AS' + asn + '.asn.cymru.com')).then((r) => {
          if (!(r.ok && r.v.length)) return null;
          return txtJoin(r.v[0]).split('|').map((s) => s.trim())[4] || null;
        }));
      }
      out.asName = await asCache.get(asn);
    }
  }
  return out;
}

const ASN_PROVIDERS = [
  [/cloudflare/i, 'Cloudflare', 'CDN / protección'], [/amazon|aws/i, 'Amazon Web Services', 'Nube'],
  [/google/i, 'Google', 'Nube'], [/microsoft|azure/i, 'Microsoft Azure', 'Nube'],
  [/fastly/i, 'Fastly', 'CDN / protección'], [/akamai/i, 'Akamai', 'CDN / protección'],
  [/netlify/i, 'Netlify', 'Alojamiento'], [/digitalocean/i, 'DigitalOcean', 'Alojamiento'],
  [/hetzner/i, 'Hetzner', 'Alojamiento'], [/\bovh/i, 'OVH', 'Alojamiento'], [/linode/i, 'Linode (Akamai)', 'Alojamiento'],
  [/incapsula|imperva/i, 'Imperva', 'CDN / protección'], [/sucuri/i, 'Sucuri', 'CDN / protección'],
  [/godaddy/i, 'GoDaddy', 'Alojamiento'], [/vercel/i, 'Vercel', 'Alojamiento'], [/github/i, 'GitHub Pages', 'Alojamiento']
];
const CNAME_PROVIDERS = [
  [/\.netlify\.app\.?$|netlify\.com\.?$/i, 'Netlify', 'Alojamiento'], [/vercel-dns\.com\.?$|\.vercel\.app\.?$/i, 'Vercel', 'Alojamiento'],
  [/\.cloudfront\.net\.?$/i, 'Amazon CloudFront', 'CDN / protección'], [/\.github\.io\.?$/i, 'GitHub Pages', 'Alojamiento'],
  [/herokudns\.com\.?$|herokuapp\.com\.?$/i, 'Heroku', 'Alojamiento'], [/myshopify\.com\.?$/i, 'Shopify', 'Plataforma'],
  [/wixdns\.net\.?$/i, 'Wix', 'Plataforma'], [/azurewebsites\.net\.?$|azureedge\.net\.?$|trafficmanager\.net\.?$/i, 'Microsoft Azure', 'Nube'],
  [/\.fastly\.net\.?$/i, 'Fastly', 'CDN / protección'], [/cdn\.cloudflare\.net\.?$/i, 'Cloudflare', 'CDN / protección']
];
const NS_PROVIDERS = [
  [/\.ns\.cloudflare\.com\.?$/i, 'Cloudflare'], [/awsdns/i, 'Amazon Route 53'], [/azure-dns/i, 'Azure DNS'],
  [/googledomains|google\.com\.?$|googlehosted/i, 'Google Cloud DNS'], [/domaincontrol\.com\.?$/i, 'GoDaddy'],
  [/nsone\.net\.?$/i, 'NS1'], [/digitalocean\.com\.?$/i, 'DigitalOcean'], [/registrar-servers\.com\.?$/i, 'Namecheap'],
  [/dnsimple|dnsmadeeasy|ultradns|akam\.net\.?$/i, 'DNS gestionado de terceros']
];

function detectHosting(ips, cnames, nsList) {
  const found = new Map();
  const add = (name, role, confidence, evidence) => {
    const k = name + '|' + role;
    if (!found.has(k)) found.set(k, { name, role, confidence, evidence: [] });
    if (!found.get(k).evidence.includes(evidence)) found.get(k).evidence.push(evidence);
  };
  ips.forEach((i) => {
    if (!i.asName) return;
    const hit = ASN_PROVIDERS.find((p) => p[0].test(i.asName));
    if (hit) add(hit[1], hit[2], 'Media', i.ip + ' pertenece a ' + i.asn + ' (' + i.asName + ')');
  });
  cnames.forEach((c) => {
    const hit = CNAME_PROVIDERS.find((p) => p[0].test(c));
    if (hit) add(hit[1], hit[2], 'Alta', 'CNAME hacia ' + c);
  });
  nsList.forEach((n) => {
    const hit = NS_PROVIDERS.find((p) => p[0].test(n));
    if (hit) add(hit[1], 'Proveedor de DNS', 'Media', 'Servidor de nombres ' + n);
  });
  return Array.from(found.values());
}

function analyzeSpf(txts) {
  const spfs = txts.filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!spfs.length) return { present: false, value: null, qualifier: null, assessment: 'Ausente', note: 'No se encontró un registro SPF.' };
  if (spfs.length > 1) return { present: true, value: spfs[0].slice(0, 300), qualifier: null, assessment: 'Revisar', note: 'Hay varios registros SPF; la especificación exige uno solo (los receptores pueden rechazarlos todos).' };
  const v = spfs[0];
  const m = v.match(/\s([+\-~?]?)all\b/i);
  const q = m ? (m[1] || '+') : null;
  const lookups = (v.match(/\b(include:|a\b|mx\b|ptr\b|exists:|redirect=)/gi) || []).length;
  let assessment = 'Correcto';
  let note = 'Política SPF estricta (-all).';
  if (!m) { assessment = 'Revisar'; note = 'El registro no termina con un mecanismo "all"; la política no queda definida.'; }
  else if (q === '+') { assessment = 'Inseguro'; note = '"+all" autoriza a cualquier servidor a enviar correo en nombre del dominio.'; }
  else if (q === '?') { assessment = 'Revisar'; note = '"?all" es neutral: no protege contra suplantación.'; }
  else if (q === '~') { assessment = 'Aceptable'; note = '"~all" (softfail) es habitual; "-all" es más estricto.'; }
  if (lookups > 10) note += ' Se estiman más de 10 consultas DNS (límite de la especificación); no se resolvieron los "include" para contarlas con exactitud.';
  return { present: true, value: v.slice(0, 300), qualifier: q, assessment, note };
}

function analyzeDmarc(txts) {
  const d = txts.filter((t) => /^v=DMARC1\s*;?/i.test(t));
  if (!d.length) return { present: false, value: null, policy: null, assessment: 'Ausente', note: 'No se encontró un registro DMARC en _dmarc.' };
  const v = d[0];
  const tag = (k) => (v.match(new RegExp('(?:^|;)\\s*' + k + '\\s*=\\s*([^;\\s]+)', 'i')) || [])[1] || null;
  const policy = (tag('p') || '').toLowerCase() || null;
  let assessment = 'Correcto';
  let note = 'Política "' + policy + '".';
  if (policy === 'none') { assessment = 'Monitoreo'; note = 'p=none solo supervisa; no bloquea correos suplantados.'; }
  else if (!['quarantine', 'reject'].includes(policy)) { assessment = 'Revisar'; note = 'No se pudo interpretar la política (p=).'; }
  const pct = tag('pct');
  if (pct && Number(pct) < 100) note += ' Se aplica solo al ' + pct + '% de los correos.';
  return { present: true, value: v.slice(0, 300), policy, rua: tag('rua'), assessment, note };
}

function mkFinding(n, f) {
  return Object.assign({
    id: 'NWG-I' + String(n).padStart(3, '0'), category: 'Infraestructura y DNS', severity: 'Informativo', confidence: 'Media',
    evidence: [], source: 'Consultas DNS públicas', description: '', recommendation: '', limitations: ''
  }, f);
}

const SOURCES = [
  { title: 'RFC 7208 - Sender Policy Framework (SPF)', url: 'https://datatracker.ietf.org/doc/html/rfc7208' },
  { title: 'RFC 7489 - DMARC', url: 'https://datatracker.ietf.org/doc/html/rfc7489' },
  { title: 'RFC 8659 - DNS CAA', url: 'https://datatracker.ietf.org/doc/html/rfc8659' },
  { title: 'Team Cymru - IP to ASN mapping', url: 'https://www.team-cymru.com/ip-asn-mapping' }
];

async function run(host, deps) {
  const d = deps || {};
  const resolver = d.resolver || new dns.promises.Resolver({ timeout: 2500, tries: 1 });
  const now = d.now ? d.now() : new Date();
  const domain = registrableDomain(host);
  const q = safe;

  const [a, aaaa, cname, ns, mx, txt, caa, dmarcTxt] = await Promise.all([
    q(() => resolver.resolve4(host)), q(() => resolver.resolve6(host)), q(() => resolver.resolveCname(host)),
    q(() => resolver.resolveNs(domain)), q(() => resolver.resolveMx(domain)), q(() => resolver.resolveTxt(domain)),
    q(() => resolver.resolveCaa(domain)), q(() => resolver.resolveTxt('_dmarc.' + domain))
  ]);

  const records = {
    A: recordOf(a), AAAA: recordOf(aaaa), CNAME: recordOf(cname), NS: recordOf(ns),
    MX: recordOf({ ok: mx.ok, v: mx.ok ? mx.v.slice().sort((x, y) => x.priority - y.priority) : [], code: mx.code }, (m) => m.priority + ' ' + m.exchange),
    TXT: recordOf(txt, txtJoin),
    CAA: recordOf(caa, (c) => Object.keys(c).filter((k) => k !== 'critical').map((k) => k + ' ' + c[k]).join(' '))
  };
  const result = {
    host, domain, queriedAt: now.toISOString(), records, ips: [], hosting: [], email: null, findings: [],
    limitations: [], sources: SOURCES, available: true
  };
  const allUnverifiable = ['A', 'AAAA', 'CNAME', 'NS'].every((k) => records[k].status === 'no verificable');
  if (allUnverifiable) {
    result.available = false;
    result.limitations.push('El resolvedor DNS no respondió a tiempo: el análisis de infraestructura no pudo completarse. Repita el análisis.');
    return result;
  }

  // Sin ningún registro: el nombre no existe o está mal escrito. No se emiten hallazgos (evita falsos positivos).
  if (['A', 'AAAA', 'CNAME', 'NS'].every((k) => records[k].status === 'sin registros')) {
    result.noRecords = true;
    result.limitations.push('No se encontró ningún registro DNS (A, AAAA, CNAME ni NS) para ' + host + '. El dominio puede no existir, estar mal escrito o no ser consultable desde el servidor de análisis. No se evaluaron IP, proveedor ni correo.');
    return result;
  }

  let n = 0;
  const addF = (f) => { n++; result.findings.push(mkFinding(n, f)); };

  // ----- IP, PTR, ASN -----
  const asCache = new Map();
  const ipList = []
    .concat((a.ok ? a.v : []).map((ip) => ({ ip, family: 4 })), (aaaa.ok ? aaaa.v : []).map((ip) => ({ ip, family: 6 })))
    .slice(0, 6);
  result.ips = await Promise.all(ipList.map((i) => {
    if (!isPublicIp(i.ip)) return Promise.resolve({ ip: i.ip, family: i.family, public: false, ptr: [], asn: null, prefix: null, country: null, registry: null, asName: null });
    return enrichIp(resolver, i.ip, i.family, asCache);
  }));
  result.ips.filter((i) => !i.public).forEach((i) => {
    addF({ title: 'El dominio resuelve a una dirección IP no pública (' + i.ip + ')', severity: 'Bajo', confidence: 'Alta',
      evidence: ['Registro DNS público con la IP ' + i.ip], description: 'Un registro DNS público que apunta a una red privada suele ser un error de configuración y puede revelar la topología interna.',
      recommendation: 'Revisar y eliminar el registro, o publicar solo direcciones accesibles desde Internet.', limitations: 'Puede ser intencional en configuraciones de DNS de horizonte dividido.' });
  });

  // ----- Proveedor -----
  const cnameTargets = cname.ok ? cname.v : [];
  result.hosting = detectHosting(result.ips, cnameTargets, ns.ok ? ns.v : []);
  const net = result.hosting.filter((h) => h.role !== 'Proveedor de DNS');
  if (net.length) {
    addF({ title: 'Infraestructura detectada: ' + net.map((h) => h.name + ' (' + h.role + ')').join(', '), confidence: net.some((h) => h.confidence === 'Alta') ? 'Alta' : 'Media',
      evidence: [].concat.apply([], net.map((h) => h.evidence)).slice(0, 6),
      description: 'Proveedor deducido de los registros DNS y del sistema autónomo (ASN) de las IP.',
      recommendation: 'Confirmar que el proveedor es el esperado y que las medidas de protección (WAF, límites, HTTPS) están activas en su panel.',
      limitations: 'Con un CDN o proxy, la IP no corresponde al servidor de origen; el país mostrado es el de registro del bloque IP, no una ubicación física.' });
  }

  // ----- DNS: servidores de nombres, CAA -----
  if (ns.ok && ns.v.length === 1) {
    addF({ title: 'El dominio tiene un solo servidor de nombres', severity: 'Bajo', confidence: 'Alta', evidence: ['NS: ' + ns.v[0]],
      description: 'Sin redundancia de DNS, una caída de ese servidor deja el dominio inaccesible.', recommendation: 'Configurar al menos dos servidores de nombres, idealmente en redes distintas.',
      limitations: 'Algunos proveedores usan un nombre único con múltiples servidores detrás (anycast).' });
  }
  if (records.CAA.status === 'sin registros') {
    addF({ title: 'El dominio no define registros CAA', severity: 'Informativo', confidence: 'Alta', evidence: ['Sin registros CAA en ' + domain],
      description: 'CAA limita qué autoridades pueden emitir certificados para el dominio.', recommendation: 'Añadir registros CAA con las autoridades que usa realmente (por ejemplo, 0 issue "letsencrypt.org").',
      limitations: 'Mejora de endurecimiento; no es una vulnerabilidad por sí sola.' });
  }

  // ----- Correo -----
  const txts = txt.ok ? txt.v.map(txtJoin) : [];
  const dmarcs = dmarcTxt.ok ? dmarcTxt.v.map(txtJoin) : [];
  const hasMx = mx.ok && mx.v.length > 0 && !(mx.v.length === 1 && /^\.?$/.test(mx.v[0].exchange));
  const mxKnown = mx.ok || mx.code === 'ENODATA' || mx.code === 'ENOTFOUND';
  const spf = txt.ok || txt.code === 'ENODATA' ? analyzeSpf(txts) : null;
  const dmarc = dmarcTxt.ok || dmarcTxt.code === 'ENODATA' || dmarcTxt.code === 'ENOTFOUND' ? analyzeDmarc(dmarcs) : null;
  result.email = { domain, receivesMail: mxKnown ? hasMx : null, spf, dmarc, dkim: 'No verificable con las comprobaciones disponibles: DKIM requiere conocer el selector del proveedor de correo.' };
  const mailLim = 'Se evalúa el dominio ' + domain + '. Si el correo se envía desde subdominios o servicios externos, la configuración puede diferir.';
  if (spf) {
    if (spf.assessment === 'Inseguro') addF({ title: 'SPF inseguro (+all)', severity: 'Medio', confidence: 'Alta', evidence: ['SPF: ' + spf.value], description: spf.note, recommendation: 'Sustituir "+all" por "-all" (o "~all" durante la transición) listando solo los remitentes legítimos.', limitations: mailLim });
    else if (!spf.present && hasMx) addF({ title: 'El dominio recibe correo pero no publica SPF', severity: 'Bajo', confidence: 'Alta', evidence: ['MX presente: ' + records.MX.values.slice(0, 2).join(', '), 'Sin registro SPF'], description: 'Sin SPF es más fácil suplantar el dominio en correos fraudulentos.', recommendation: 'Publicar un registro TXT SPF con los servidores autorizados y terminar en "-all".', limitations: mailLim });
    else if (!spf.present && !hasMx && mxKnown) addF({ title: 'Dominio sin correo y sin SPF', severity: 'Informativo', confidence: 'Media', evidence: ['Sin MX ni SPF'], description: 'Si el dominio no envía correo, conviene declararlo para impedir su suplantación.', recommendation: 'Publicar "v=spf1 -all" y un DMARC con p=reject.', limitations: mailLim });
    else if (spf.present && spf.assessment !== 'Correcto') addF({ title: 'SPF a revisar (' + spf.assessment.toLowerCase() + ')', severity: 'Informativo', confidence: 'Alta', evidence: ['SPF: ' + spf.value], description: spf.note, recommendation: 'Ajustar el registro SPF según la nota indicada.', limitations: mailLim });
  }
  if (dmarc) {
    if (!dmarc.present && hasMx) addF({ title: 'El dominio recibe correo pero no publica DMARC', severity: 'Bajo', confidence: 'Alta', evidence: ['Sin registro TXT en _dmarc.' + domain], description: 'Sin DMARC, los receptores no saben cómo tratar correos que suplantan al dominio.', recommendation: 'Publicar DMARC empezando con p=none y rua=mailto:..., y avanzar a quarantine/reject.', limitations: mailLim });
    else if (dmarc.present && dmarc.assessment === 'Monitoreo') addF({ title: 'DMARC en modo monitoreo (p=none)', severity: 'Informativo', confidence: 'Alta', evidence: ['DMARC: ' + dmarc.value], description: dmarc.note, recommendation: 'Tras revisar los informes, pasar a p=quarantine y luego p=reject.', limitations: mailLim });
  }

  // ----- CNAME colgante (solo DNS) -----
  if (cname.ok && cname.v.length) {
    const target = cname.v[0];
    const [ta, taaaa] = await Promise.all([safe(() => resolver.resolve4(target)), safe(() => resolver.resolve6(target))]);
    const gone = (r) => !r.ok && (r.code === 'ENOTFOUND' || r.code === 'ENODATA');
    if (gone(ta) && gone(taaaa)) {
      addF({ title: 'El CNAME apunta a un destino que no resuelve (posible "subdomain takeover")', severity: 'Medio', confidence: 'Media',
        evidence: [host + ' -> CNAME ' + target, 'El destino no tiene registros A/AAAA'],
        description: 'Si el servicio externo al que apunta fue cancelado, un tercero podría reclamarlo y servir contenido bajo este dominio.',
        recommendation: 'Eliminar el registro CNAME si ya no se usa, o restablecer el servicio de destino.',
        limitations: 'Solo se comprobó el DNS; no se verificó el estado del servicio de destino. Un fallo temporal del DNS puede dar el mismo resultado.' });
    }
  }

  result.limitations.push(
    'Todo se obtiene de consultas DNS públicas hechas desde el servidor de análisis; los resultados pueden variar según el resolvedor y la ubicación.',
    'El país mostrado es el de registro del bloque IP (RIR), no la ubicación física del servidor. Con CDN o proxy, la IP no es la del servidor de origen.',
    'DKIM no es verificable sin conocer el selector.',
    'El dominio registrable se estima sin la lista pública de sufijos completa; en dominios con sufijos poco comunes puede ser inexacto.'
  );
  return result;
}

module.exports = { PRIVATE_SUFFIXES, run, registrableDomain, analyzeSpf, analyzeDmarc, originName, detectHosting, SOURCES };
