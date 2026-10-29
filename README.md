# NEXO WEB GUARD

Análisis defensivo y no intrusivo de seguridad web. Frontend estático + 3 Netlify Functions. Sin base de datos, sin cuentas.

## Estructura
```
index.html  styles.css  app.js  netlify.toml  package.json
js/core.js  js/pdf-report.js        (lógica de riesgo y generador PDF)
vendor/jspdf.umd.min.js             (se genera con "npm run build")
netlify/functions/  analyze-site.js  security-headers.js  vulnerability-lookup.js
netlify/lib/        (SSRF, fetch seguro, detección, cabeceras, PHP, NVD, robots)
assets/logo.svg     tests/run-tests.js
```

## Publicar en Netlify (gratis, sin dominio propio)
1. **Archivos**: descomprime el ZIP en una carpeta, por ejemplo `nexo-web-guard`.
2. **Probar en local (opcional)**: instala Node 18+ y ejecuta `npm install`, `npm run build`, `npm test`.
3. **GitHub**: crea un repositorio vacío en github.com y sube la carpeta
   (`git init`, `git add .`, `git commit -m "NEXO WEB GUARD"`, `git branch -M main`,
   `git remote add origin <URL>`, `git push -u origin main`). No subas `node_modules` (ya está en `.gitignore`).
4. **Conectar**: en app.netlify.com → *Add new site* → *Import an existing project* → GitHub → elige el repositorio.
5. **Compilación**: Netlify lee `netlify.toml` solo. Debe mostrar *Build command* `npm run build`, *Publish directory* `.` y *Functions* `netlify/functions`. (El build instala jsPDF y lo copia a `vendor/`.)
6. **Variables de entorno (opcional)**: *Site configuration → Environment variables* → `NVD_API_KEY` con tu clave gratuita de https://nvd.nist.gov/developers/request-an-api-key . Sin clave funciona, pero NVD limita mucho las consultas (5 por 30 s). Después, *Deploys → Trigger deploy*.
7. **Publicar**: pulsa *Deploy*. Tu sitio quedará en `https://<nombre>.netlify.app`.
8. **Probar las funciones**: abre el sitio, marca la casilla de autorización y analiza un sitio **tuyo**.
   También: `curl -X POST https://<nombre>.netlify.app/.netlify/functions/vulnerability-lookup -H "Content-Type: application/json" -d '{"product":"php","version":"8.1.2"}'`
9. **Verificar el PDF**: tras un análisis pulsa *DESCARGAR INFORME PDF*; se guarda `NEXO-WEB-GUARD-informe-AAAA-MM-DD.pdf`. Ábrelo y comprueba URL, fecha, ID y hallazgos.
10. **Errores frecuentes**
    - *«No se pudo cargar la biblioteca de PDF»*: el build no corrió. Revisa en Deploys que `npm run build` terminó bien.
    - *404 en `/.netlify/functions/...`*: revisa que `netlify/functions` exista en el repositorio y el log de Functions.
    - *«NVD limitó las solicitudes»*: configura `NVD_API_KEY` o espera unos segundos.
    - *«Origen no permitido»*: las funciones solo aceptan llamadas desde el propio sitio.
    - *Timeout*: el sitio analizado tarda demasiado; repite el análisis. Las funciones gratuitas tienen un límite de ~10 s (el análisis se corta a 8,5 s).
    - *En local las funciones no responden*: usa `npx netlify dev`.

## Seguridad y límites
- Solo HTTP/HTTPS, puertos 80/443. Se bloquean localhost, IP privadas/link-local/IPv6 internas, nombres internos y redirecciones hacia ellos; DNS resuelto una vez y conexión fijada a esa IP (anti-rebinding).
- Máx. 10 solicitudes por análisis, 8,5 s en total, 600 KB por respuesta, 6 análisis/10 min por IP (en memoria; por instancia serverless, mejor esfuerzo).
- Respeta `robots.txt` y se detiene ante HTTP 429/503.
- Tabla de soporte de PHP (`netlify/lib/php-support.js`): revisada 2026-10-28; actualízala periódicamente con php.net/supported-versions.php.
