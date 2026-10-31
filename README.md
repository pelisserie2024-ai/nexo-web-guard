# NEXO WEB GUARD

Análisis defensivo y no intrusivo de seguridad web. Frontend estático + 3 Netlify Functions. Sin base de datos, sin cuentas.

## Estructura
```
index.html  styles.css  app.js  netlify.toml  package.json
js/core.js  js/pdf-report.js        (lógica de riesgo y generador PDF)
vendor/jspdf.umd.min.js             (se genera con "npm run build")
netlify/functions/  analyze-site.js  security-headers.js  vulnerability-lookup.js  infrastructure.js  domain-intel.js  subdomains.js
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

## Panel «Infraestructura y DNS» (v1.1, Fase 1)
Se ejecuta en cada análisis, en paralelo, solo con consultas DNS públicas (no se conecta al sitio):
- IP (A/AAAA), DNS inverso (PTR), red (ASN) y país de registro del bloque IP (servicio DNS público de Team Cymru; solo recibe la IP).
- Proveedor de alojamiento/CDN y de DNS deducido de ASN, CNAME y servidores de nombres.
- Registros DNS (A, AAAA, CNAME, NS, MX, TXT, CAA).
- Seguridad del correo: SPF y DMARC (DKIM no es verificable sin el selector).
- Alertas: IP privada en DNS público, un solo NS, sin CAA, CNAME que apunta a un destino que no resuelve (posible subdomain takeover).
- El país mostrado es el de registro de la IP, no la ubicación física; con un CDN no se ve el servidor de origen.

## Panel «Dominio, ubicación y DNSSEC» (v1.2, Fase 2)
Usa servicios públicos externos (se informa en la sección de Privacidad de la página):
- **RDAP** (vía rdap.org → registro oficial): registrador, fechas de registro, expiración y última modificación, estados y servidores de nombres. No se muestran datos personales del titular. No se consulta en subdominios de plataformas (netlify.app, vercel.app, etc.).
- **Ubicación aproximada de las IP** (ipwho.is): país, región, ciudad, organización y zona horaria. Solo se envían IP públicas.
- **DNSSEC** (Google Public DNS): si el dominio tiene registros DS y si el resolvedor los validó.
- Alertas: dominio vencido o que vence en 30 días o menos, dominio registrado hace menos de 30 días, sin bloqueo de transferencia y sin DNSSEC (estas dos últimas informativas).
- Las redirecciones de RDAP se validan con las mismas reglas anti-SSRF; los destinos son fijos y la función no es un proxy abierto.
- Si un servicio externo falla, el resultado se muestra como «No verificable», nunca se inventan datos.

## Panel «Subdominios» (v1.3, Fase 3)
- Lista los subdominios que aparecen en certificados públicos (Certificate Transparency) consultando **Cert Spotter** y **crt.sh**, que reciben el dominio.
- Sobre los subdominios **solo se hacen consultas DNS** (máximo 40 por análisis, los de nombre sensible primero): no hay conexiones HTTP, ni fuerza bruta de nombres, ni transferencias de zona.
- Alertas: nombres sensibles que resuelven (admin, dev, staging, backup, vpn…), CNAME abandonados hacia servicios de terceros (posible *subdomain takeover*, Medio) y otros CNAME que no resuelven (Bajo).
- Límites: la lista puede estar incompleta o incluir nombres que ya no existen; no se verifica con el proveedor si un nombre puede reclamarse. Si los servicios de certificados no responden, el resultado es «No verificable».
- Límite de uso: 6 análisis de subdominios cada 10 minutos por conexión.

## Calidad y presentación (v1.4, Fase 4)
- **Resumen ejecutivo** al inicio de los resultados y del PDF: puntos clave y las 3 prioridades, calculados solo con datos del análisis (sin porcentajes).
- **Sin repeticiones:** los módulos se fusionan con una única función (`Core.mergeModule`), que no duplica limitaciones ni fuentes. El CNAME abandonado del propio sitio se informa una sola vez, y se corrigió una limitación desactualizada.
- **Auditoría automática:** pruebas que combinan todos los módulos y comprueban IDs, limitaciones y fuentes sin repetir.

## Seguridad y límites
- Solo HTTP/HTTPS, puertos 80/443. Se bloquean localhost, IP privadas/link-local/IPv6 internas, nombres internos y redirecciones hacia ellos; DNS resuelto una vez y conexión fijada a esa IP (anti-rebinding).
- Máx. 10 solicitudes por análisis, 8,5 s en total, 600 KB por respuesta, 6 análisis/10 min por IP (en memoria; por instancia serverless, mejor esfuerzo).
- Respeta `robots.txt` y se detiene ante HTTP 429/503.
- Tabla de soporte de PHP (`netlify/lib/php-support.js`): revisada 2026-10-28; actualízala periódicamente con php.net/supported-versions.php.
