---
title: "Self-SVG XSS: ATO asistido por bot mediante carga de SVG"
date: "2026-08-01"
description: "Prueba de concepto de una vulnerabilidad Self-XSS en NeuroChat que permite secuestrar sesiones de administrador mediante SVG malicioso y un bot automatizado."
tags: ["xss", "svg", "bug-bounty", "ato", "self-xss", "seguridad", "pentesting"]
readTime: "8 min"
published: true
---

## Self_svg_XSS — Self-XSS → ATO asistido por bot mediante carga de SVG

Este post es una prueba de concepto paso a paso para una vulnerabilidad en la que un archivo SVG cargado sin sanitizar se convierte en un exploit remoto cuando un bot administrativo abre el archivo.

El pago reportado para la vulnerabilidad es de **$750**, y la cadena de ataque demuestra cómo es posible una toma de control de sesión (`ATO`) dentro del origen de la aplicación.

---

## Cadena de ataque

1. Un atacante sube un archivo SVG malicioso al sistema.
2. El servidor devuelve el archivo con `Content-Type: image/svg+xml` y lo sirve en línea.
3. La interfaz crea una URL de blob desde el archivo descargado y llama a `window.open(blobUrl)`.
4. Un documento SVG cargado como `blob:` hereda el origen del creador.
5. El script insertado en el SVG se ejecuta en el origen de la aplicación.
6. El token JWT almacenado en `localStorage['nc_token']` es accesible desde ese contexto.
7. Un bot Chromium automatizado entra al chat, abre el adjunto y ejecuta la carga útil.
8. El atacante exfiltra el token admin y secuestra la sesión.

---

## Causas fundamentales (lo que hace que la cadena funcione)

1. **Carga de SVG sin sanitizar.**
   - `files.ts` conserva `Content-Type: image/svg+xml` y sirve el SVG tal cual.
   - No se valida ni se filtra el contenido antes de entregarlo.

2. **Apertura de la URL del blob de nivel superior.**
   - `FileAttachment.tsx` crea una URL de blob desde el archivo descargado.
   - `window.open(blobUrl)` carga el SVG como documento.
   - Las `blob:` URLs heredan el origen del creador, de modo que el `<script>` del SVG se ejecuta dentro del origen de NeuroChat.

3. **JWT en `localStorage`.**
   - `auth.ts` devuelve el token en el cuerpo de la respuesta JSON.
   - El cliente almacena el JWT en `localStorage['nc_token']`.
   - Cualquier script ejecutado desde el origen puede leer `localStorage`.

4. **Invitaciones de chat abiertas.**
   - Cualquier usuario puede invitar a cualquier persona a un chat que posea.
   - Esto incluye cuentas con privilegios elevados como `admin@neurochat.ai`.

5. **Un bot administrativo entusiasta.**
   - Un bot Chromium sin interfaz gráfica carga el chat.
   - Hace clic en el botón "Abrir en una pestaña nueva" para cada archivo adjunto.
   - Al abrir el SVG malicioso, el exploit se ejecuta automáticamente.

---

## 1) Exploración

- Inicia sesión como atacante.
- Sube un archivo SVG cuya visualización sea sencilla.
- Haz clic en **Abrir en una pestaña nueva**.
- Observa que se abre una URL de tipo `blob:`.
- En la pestaña de red, verifica que `/api/files/:id` devuelve `Content-Type: image/svg+xml`.

---

## 2) Prueba de ejecución del script

Sube un archivo SVG como el siguiente:

```svg
<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40">
  <text y="25">hi</text>
  <script>alert(document.domain)</script>
</svg>
```

- Haz clic en **Abrir en una pestaña nueva**.
- Si aparece el `alert` con `localhost:1338`, la vulnerabilidad está confirmada.
- Esto demuestra un **XSS autoinfligido** (`Self-XSS`) válido dentro del origen.

---

## 3) Armar

- Tu ID de usuario es visible en cualquier JWT decodificado.
- Si no tienes admin, puedes usar `atob(token.split('.')[1])` para leer el payload.
- Crea un SVG que exfiltre `localStorage` mediante una petición POST a `/api/exfil/<id>`.
- El exploit puede usar JavaScript dentro del SVG para enviar el token al servidor del atacante.

---

## 4) Entregar

- Sube el SVG malicioso a un chat.
- Invita a `admin@neurochat.ai`.
- El bot sondeará el chat cada ~15 segundos.
- El bot aceptará la invitación, visitará el chat y hará clic en el archivo adjunto.

---

## 5) Cosecha

- Revisa `/stolen` en la interfaz de usuario.
- O consulta `/api/exfil` para encontrar los datos capturados.
- Espera una entrada con `email = admin@neurochat.ai`.
- El token robado aparecerá en el registro de exfiltración.

---

## 6) Adquisición

- Haz clic en **Secuestrar sesión** en la captura.
- O copia el token y colócalo en `localStorage['nc_token']`.
- Navega a `/admin`.
- Si el token es válido, obtendrás acceso al panel de administración y la bandera.

---

## Prueba de concepto (automatizada)

El archivo `exploit.py` automatiza los pasos de la prueba de concepto de extremo a extremo:

```text
[1] Login as attacker@neurochat.ai
    ✓ logged in as #1 (Alex Morgan) · role=user
[2] Create attacker-owned chat
    ✓ chat id = 5
[3] Craft SVG payload (exfil → /api/exfil/1)
    ✓ 1.4 KB
[4] Upload dashboard-mockup.svg
    ✓ mime preserved as image/svg+xml
[5] Post message referencing file
[6] Invite admin@neurochat.ai
[7] Poll /api/exfil for captured admin token
    ✓ captured admin JWT
[8] Hit /api/admin with stolen JWT
      FLAG{e7a15c…}
```

La automatización completa demuestra cómo una cadena de errores en el manejo de archivos, la creación de blobs y el uso de tokens en `localStorage` puede derivar en un compromiso total.

---

## Conclusión

Este caso ilustra una vulnerabilidad crítica de **XSS basado en SVG** que no es solo un problema de navegador, sino un fallo de diseño en la forma en que la aplicación maneja archivos y la confianza en `blob:` como contenedor de contenido.

Las aplicaciones deben:

- sanitizar y validar SVG antes de servirlos,
- evitar servir documentos SVG directamente con origen heredado,
- no almacenar tokens sensibles en `localStorage` sin protección adicional,
- limitar las invitaciones y los accesos automáticos a bots.

Una buena mitigación detiene el ataque antes de que el bot llegue a ejecutar el payload.
