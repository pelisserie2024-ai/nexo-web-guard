'use strict';
/**
 * Ciclo de soporte de PHP.
 * Tabla interna basada en https://www.php.net/supported-versions.php (fechas de fin de soporte de seguridad).
 * IMPORTANTE: debe revisarse periódicamente (campo REVIEWED) porque puede cambiar.
 * Las distribuciones Linux (Debian, Ubuntu, RHEL...) pueden dar soporte extendido y
 * retroportar correcciones a versiones que php.net ya no mantiene.
 */
const REVIEWED = '2026-10-28';

const SECURITY_END = {
  '5.6': '2018-12-31', '7.0': '2018-12-03', '7.1': '2019-12-01', '7.2': '2020-11-30',
  '7.3': '2021-12-06', '7.4': '2022-11-28', '8.0': '2023-11-26', '8.1': '2025-12-31',
  '8.2': '2026-12-31', '8.3': '2027-12-31', '8.4': '2028-12-31', '8.5': '2029-12-31'
};

function parseVersion(v) {
  const m = String(v || '').match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: m[3] === undefined ? null : +m[3], branch: m[1] + '.' + m[2] };
}

/**
 * @returns {{branch, status, endDate, daysLeft, note}}
 * status: 'sin_soporte' | 'soporte_seguridad' | 'desconocido'
 */
function phpSupportStatus(version, now) {
  const p = parseVersion(version);
  const today = now instanceof Date ? now : new Date();
  if (!p) return { branch: null, status: 'desconocido', endDate: null, daysLeft: null, note: 'Versión no interpretable.' };
  const end = SECURITY_END[p.branch];
  if (!end) {
    const known = Object.keys(SECURITY_END);
    const older = p.major < 5 || (p.major === 5 && p.minor < 6);
    if (older) {
      return { branch: p.branch, status: 'sin_soporte', endDate: null, daysLeft: null, note: 'Rama anterior a PHP 5.6, sin soporte desde hace años.' };
    }
    return {
      branch: p.branch, status: 'desconocido', endDate: null, daysLeft: null,
      note: 'La rama ' + p.branch + ' no figura en la tabla interna (revisada ' + REVIEWED + '; ramas conocidas: ' + known[0] + ' a ' + known[known.length - 1] + '). Consulte php.net/supported-versions.php.'
    };
  }
  const endDate = new Date(end + 'T23:59:59Z');
  const daysLeft = Math.ceil((endDate.getTime() - today.getTime()) / 86400000);
  return {
    branch: p.branch,
    status: daysLeft < 0 ? 'sin_soporte' : 'soporte_seguridad',
    endDate: end,
    daysLeft,
    note: daysLeft < 0
      ? 'El soporte de seguridad oficial de PHP ' + p.branch + ' terminó el ' + end + '.'
      : 'El soporte de seguridad oficial de PHP ' + p.branch + ' termina el ' + end + '.'
  };
}

module.exports = { phpSupportStatus, parseVersion, REVIEWED, SECURITY_END };
