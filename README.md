# 🛡️ CYBER-BLOG

**CYBER-BLOG** es un blog técnico y repositorio de conocimiento enfocado en la **ciberseguridad ofensiva y defensiva**, orientado al aprendizaje práctico, la experimentación controlada y la documentación técnica basada en escenarios reales.

Este proyecto nace con el objetivo de **convertir el conocimiento en habilidad real**, proporcionando contenido claro, reproducible y alineado con situaciones que ocurren en entornos productivos, siempre desde un enfoque **ético y responsable**.

---

## 🌐 ¿De qué trata esta web?

CYBER-BLOG funciona como una **plataforma personal de publicaciones técnicas**, donde se documentan análisis, investigaciones y aprendizajes continuos relacionados con el ecosistema de la ciberseguridad.

En el blog encontrarás principalmente:

- 📰 **Noticias y tendencias relevantes** del sector de la ciberseguridad  
- 🧪 **Writeups técnicos** de laboratorios y reto-máquinas  
  - Hack The Box  
  - TryHackMe  
  - INE / eLearnSecurity  
- 🛠️ **Análisis profundos de herramientas** utilizadas en:
  - Pentesting
  - Bug Bounty
  - Red Team
  - Blue Team / DFIR

---

## 🎯 Enfoque del contenido

El enfoque de CYBER-BLOG es **100% práctico y reproducible**, diseñado exclusivamente para:

- Entornos controlados
- Laboratorios locales
- Plataformas de entrenamiento
- Escenarios simulados

Cada publicación busca ir más allá de la teoría y explicar de forma clara:

- 🔍 **Cómo** se explota una vulnerabilidad  
- 🧠 **Por qué** ocurre  
- 💥 **Impacto real** en un entorno productivo  
- 🛡️ **Medidas de mitigación**, hardening y mejora de la postura de seguridad  

> ⚠️ Todas las técnicas ofensivas documentadas están orientadas únicamente al aprendizaje, la defensa y la mejora de la seguridad.

---

## 👥 ¿A quién está dirigido?

CYBER-BLOG está pensado para:

- 🎓 Estudiantes de ciberseguridad
- 🐞 Bug Bounty Hunters
- 🧑‍💻 Pentesters junior y profesionales
- 🔐 Personas que desean mantenerse actualizadas y afinar sus habilidades técnicas

Si buscas **ejemplos reales, explicaciones directas y aprendizaje continuo basado en la práctica**, este blog funciona como un **laboratorio personal y comunitario**.

---

## 🧠 Filosofía del proyecto

- Aprender haciendo
- Documentar para reforzar el conocimiento
- Pensar como atacante para defender mejor
- Priorizar técnicas reales sobre teoría vacía
- Mantener una mentalidad ética y profesional

---

## 👤 ¿Quién está detrás de CYBER-BLOG?

CYBER-BLOG es mantenido por **Zuk4r1**, estudiante de ciberseguridad y hacking ético, enfocado en:

- Pentesting práctico
- Explotación controlada de vulnerabilidades
- Automatización de auditorías
- Investigación continua de amenazas

Este blog funciona como un **repositorio vivo de aprendizaje**, donde se documentan:

- Laboratorios
- Técnicas reales
- Errores comunes
- Soluciones efectivas
- Buenas prácticas ofensivas y defensivas

Con el objetivo de reforzar su crecimiento profesional y aportar valor real a la comunidad.

---

## ⚙️ Áreas de enfoque

- 🛡️ Hacking avanzado y explotación controlada
- 🛠️ Desarrollo de herramientas propias para pentesting y bug bounty
- 🎯 Preparación de certificaciones ofensivas:
  - eJPT
  - Ruta hacia OSCP

---

## 🖼️ Cómo añadir imágenes a un post

Cada post vive en `src/posts/<nombre>-YYYY-MM-DD.md`. Las imágenes se sirven desde `public/imagenes/<slug-del-post>/`, una carpeta por post para evitar colisiones de nombres entre writeups.

### 1. Optimizar la imagen

```bash
npm run image <ruta-de-la-captura> <slug-del-post> [nombre-salida] [--width=1600]
```

Ejemplo:

```bash
npm run image ~/capturas/burp-request.png hackthebox-jerry
```

El script redimensiona (máx. 1600px de ancho por defecto), convierte a `.webp` y deja el archivo en:

```
public/imagenes/hackthebox-jerry/burp-request.webp
```

e imprime la ruta exacta a usar en el post.

### 2. Imagen destacada (portada)

En el frontmatter del `.md`, añade `coverImage` (y opcionalmente `coverAlt`). Se usa como miniatura en las tarjetas del listado, banner en la cabecera del post, y como imagen de Open Graph/Twitter al compartir el enlace:

```yaml
---
title: "HackTheBox Jerry: de Tomcat a SYSTEM"
...
coverImage: "/imagenes/hackthebox-jerry/cover.webp"
coverAlt: "Panel de Tomcat Manager expuesto"
---
```

Si se omite, el post simplemente no muestra portada (no rompe el layout).

### 3. Imágenes dentro del cuerpo del post

Markdown estándar, en cualquier parte del contenido:

```markdown
![Petición interceptada en Burp Suite](/imagenes/hackthebox-jerry/burp-request.webp)
```

El texto entre `[]` se usa como `alt` y como pie de foto. Al hacer click, la imagen se abre en un lightbox a pantalla completa (útil para leer capturas de terminal o de Burp).

### Reglas de seguridad

- Las rutas locales solo se aceptan dentro de `/imagenes/` o `/assets/` (previene path traversal).
- También se admiten URLs `https://` externas, pero se recomienda alojar todo en `/imagenes/` para no depender de servicios de terceros.
- Si una imagen no carga, se oculta sola sin romper el resto del post.

---

## 📌 Aviso legal

Todo el contenido publicado en CYBER-BLOG tiene fines **educativos y de investigación**.  
El autor **no se hace responsable del uso indebido** de la información aquí presentada.

---

## 🚀 Estado del proyecto

📖 En desarrollo continuo  
🔄 Actualizaciones frecuentes  
🧪 Aprendizaje constante  

---

> **CYBER-BLOG no es solo un blog.  
> Es un entorno de entrenamiento continuo para pensar como atacante y defender como profesional.**

