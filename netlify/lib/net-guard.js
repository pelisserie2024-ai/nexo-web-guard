'use strict';
/**
 * Protección SSRF: validación de URL, de IPs (v4/v6) y resolución DNS segura.
 * Política: se deniega por defecto; solo se permiten direcciones públicas (unicast global).
 */
const net = require('net');
const dns = require('dns').promises;

const V4_BLOCKS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
];

const BLOCKED_SUFFIXES = [
  '.localhost', '.local', '.internal', '.lan', '.home', '.home.arpa', '.intranet',
  '.corp', '.private', '.localdomain', '.in-addr.arpa', '.ip6.arpa'
];

function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}

function inV4Block(ip, block) {
  const bits = block[1];
  const mask = bits === 0 ? 0 : ((~0 << (32 - bits)) >>> 0);
  return ((ipv4ToInt(ip) & mask) >>> 0) === ((ipv4ToInt(block[0]) & mask) >>> 0);
}

function isPublicIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  return !V4_BLOCKS.some((b) => inV4Block(ip, b));
}

/** Devuelve 8 grupos de 16 bits o null si no es válida. */
function parseIPv6(input) {
  let ip = String(input).split('%')[0];
  if (ip.includes('.')) {
    const idx = ip.lastIndexOf(':');
    const v4 = ip.slice(idx + 1);
    if (!net.isIPv4(v4)) return null;
    const p = v4.split('.').map(Number);
    ip = ip.slice(0, idx + 1) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = head.concat(Array(fill).fill('0'), tail);
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN));
  if (nums.some((n) => Number.isNaN(n))) return null;
  return nums;
}

function v4FromGroups(hi, lo) {
  return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');
}

function isPublicIPv6(ip) {
  const g = parseIPv6(ip);
  if (!g) return false;
  const firstSixZero = g.slice(0, 6).every((x) => x === 0);
  if (firstSixZero) return false; // ::, ::1 y direcciones compatibles con IPv4 (obsoletas)
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return isPublicIPv4(v4FromGroups(g[6], g[7])); // IPv4 mapeada
  }
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return isPublicIPv4(v4FromGroups(g[6], g[7])); // NAT64
  }
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return false; // NAT64 local
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return false; // descarte
  if (g[0] === 0x2002) return isPublicIPv4(v4FromGroups(g[1], g[2])); // 6to4
  if (g[0] === 0x2001 && g[1] === 0) return false; // Teredo
  if (g[0] === 0x2001 && g[1] === 0x0db8) return false; // documentación
  if (g[0] === 0x2001 && g[1] >= 0x10 && g[1] <= 0x2f) return false; // ORCHID
  return (g[0] & 0xe000) === 0x2000; // solo unicast global 2000::/3
}

function isPublicIp(ip) {
  if (net.isIPv4(ip)) return isPublicIPv4(ip);
  if (net.isIPv6(ip)) return isPublicIPv6(ip);
  return false;
}

function fail(code, message) {
  return { ok: false, code, error: message };
}

/** Valida la URL de destino (usada en frontend-backend, y en cada redirección). */
function validateTarget(raw) {
  if (typeof raw !== 'string') return fail('INVALID', 'La URL no es válida.');
  const s = raw.trim();
  if (!s) return fail('INVALID', 'Introduce una URL.');
  if (s.length > 2048) return fail('INVALID', 'La URL es demasiado larga.');
  if (/[\u0000- \u007f]/.test(s)) return fail('INVALID', 'La URL contiene caracteres no permitidos.');
  let u;
  try {
    u = new URL(s);
  } catch (e) {
    return fail('INVALID', 'La URL no tiene un formato válido. Ejemplo: https://ejemplo.cl');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return fail('PROTOCOL', 'Solo se admiten direcciones http:// o https://.');
  }
  if (u.username || u.password) return fail('INVALID', 'La URL no puede incluir usuario ni contraseña.');
  if (u.port && u.port !== '80' && u.port !== '443') {
    return fail('PORT', 'Solo se permiten los puertos estándar 80 y 443.');
  }
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253) return fail('INVALID', 'El nombre de dominio no es válido.');
  if (host.startsWith('[') || net.isIP(host)) {
    return fail('BLOCKED', 'Introduce un nombre de dominio, no una dirección IP.');
  }
  if (!host.includes('.') || host === 'localhost' || BLOCKED_SUFFIXES.some((x) => host.endsWith(x))) {
    return fail('BLOCKED', 'Ese dominio no está permitido (nombres internos o locales).');
  }
  if (!/^[a-z0-9.-]+$/.test(host)) return fail('INVALID', 'El nombre de dominio contiene caracteres no válidos.');
  return { ok: true, url: u, host };
}

/** Resuelve DNS y exige que TODAS las direcciones sean públicas. Devuelve IPv4 primero. */
async function resolvePublicHost(host, resolver) {
  const lookup = resolver || ((h) => dns.lookup(h, { all: true, verbatim: true }));
  let list;
  try {
    list = await lookup(host);
  } catch (e) {
    const err = new Error('No se pudo resolver el dominio.');
    err.code = e.code || 'ENOTFOUND';
    return { ok: false, error: 'No se pudo resolver el dominio.', code: err.code };
  }
  if (!list || !list.length) return { ok: false, error: 'El dominio no tiene direcciones IP.', code: 'ENOTFOUND' };
  for (const a of list) {
    if (!isPublicIp(a.address)) {
      return { ok: false, error: 'El dominio resuelve a una dirección no pública; la solicitud fue bloqueada.', code: 'NWG_BLOCKED' };
    }
  }
  const sorted = list.slice().sort((a, b) => a.family - b.family);
  return { ok: true, addresses: sorted };
}

module.exports = { isPublicIp, isPublicIPv4, isPublicIPv6, parseIPv6, validateTarget, resolvePublicHost };
