'use strict';
/**
 * Copia jsPDF desde node_modules a /vendor para servirlo desde el propio sitio
 * (así la política CSP puede limitarse a 'self' y no depende de CDN externos).
 * Netlify ejecuta "npm install" y luego "npm run build" automáticamente.
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const src = path.join(root, 'node_modules', 'jspdf', 'dist', 'jspdf.umd.min.js');
const destDir = path.join(root, 'vendor');
const dest = path.join(destDir, 'jspdf.umd.min.js');

if (!fs.existsSync(src)) {
  console.error('ERROR: no se encontró ' + src + '. Ejecuta "npm install" antes de "npm run build".');
  process.exit(1);
}
fs.mkdirSync(destDir, { recursive: true });
fs.copyFileSync(src, dest);
console.log('jsPDF copiado a vendor/jspdf.umd.min.js (' + fs.statSync(dest).size + ' bytes)');
