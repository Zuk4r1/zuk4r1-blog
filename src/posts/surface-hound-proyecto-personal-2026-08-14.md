---
title: "Surface Hound: reconocimiento pasivo en Bug Bounty"
description: "Extensión de navegador para reconocimiento pasivo en vivo durante Bug Bounty, con análisis de endpoints, parámetros, IDOR, CORS/CSP y puente a herramientas CLI."
date: 2026-08-14
tags:
- bug-bounty
- ciberseguridad
- desarrollo
- extensión
- proyectos-personales
---

# 🐺 Surface Hound

Hace unos meses empecé a desarrollar un proyecto personal que tenía una idea muy clara: transformar la navegación normal de un objetivo en una fuente de inteligencia para la fase de reconocimiento durante Bug Bounty y pentesting autorizado.

Ese proyecto es **Surface Hound**, una extensión de navegador para **Chrome y Firefox** pensada para detectar y correlacionar información en tiempo real mientras se visita un sitio dentro de scope.

La idea no es reemplazar herramientas especializadas, sino complementar el flujo natural de trabajo: mirar una app, navegar por sus flujos, y que la extensión te ayude a detectar automáticamente endpoints, parámetros, patrones de IDOR, secretos expuestos, hallazgos de CORS/CSP y mucho más, sin tener que estar revisando cada request a mano.

---

## ¿Qué es Surface Hound?

Surface Hound es una extensión de navegador orientada al **reconocimiento pasivo en vivo**.

Mientras navegas normalmente, la herramienta captura tráfico de la aplicación, organiza la superficie de ataque, identifica rutas importantes y genera hipótesis de vulnerabilidad con grados de confianza, en lugar de dejarte una lista de datos crudos que luego tengas que interpretar tú mismo.

Es decir, la extensión intenta poner el foco en lo útil:

🟢 Qué endpoints existen.

🟢 Qué parámetros se usan.

🟢 Si hay identificadores sensibles.

🟢 Si existen relaciones entre recursos.

🟢 Si se están exponiendo secretos, tokens o configuraciones frágiles.

🟢 Si aparecen riesgos de CORS, CSP, GraphQL o IDOR.

🟢 Si ese análisis puede pasar directamente a un flujo de validación más avanzado.

> La intención es clara: llevar una parte del reconocimiento a la misma actividad de "cazar" en el navegador, sin romper el flujo de trabajo.

---

## El problema que quería resolver

En Bug Bounty y pentesting, una gran parte del tiempo se consume en tareas repetitivas:

🟢 revisar requests.

🟢 identificar parámetros relevantes.

🟢 mapear la estructura de rutas.

🟢 detectar patrones de recursos y relaciones.

🟢 agrupar endpoints por entidad.

🟢 clasificar posibles vulnerabilidades.

🟢 explorar si un comportamiento es más bien ruido o una hipótesis real.

Muchos de esos pasos pueden automatizarse parcialmente, especialmente durante la fase pasiva. Con Surface Hound quise construir una herramienta que hiciera eso sin salir del navegador, manteniendo un enfoque orientado a la productividad y a la validación humana.

---

## Funcionalidades principales

La extensión está pensada como un panel central donde cada tipo de dato se organiza por pestañas. Eso sirve para no mezclar tráfico, hallazgos y análisis. Entre sus principales capacidades están:

### 1. Mapa de la superficie de ataque

Se construye un árbol interactivo con rutas agrupadas por segmentos. Esto permite ver de un vistazo la estructura de la aplicación y sus endpoints clave.

Además, los nodos pueden revelar el valor real de identificadores tipo `{id}` y tienen métricas de confianza para candidatos a IDOR.

### 2. Endpoints y metadata

La extensión lista cada request capturada con:

🟢 método HTTP.

🟢 URL completa.

🟢 cantidad de apariciones.

🟢 última hora observada.

🟢 código de respuesta.

🟢 si la request iba autenticada.

🟢 y detalles de la respuesta y del script que la disparó.

Esto reduce enormemente el tiempo de contextualización cuando se busca un endpoint sospechoso.

### 3. Parámetros y clasificaciones

Se analizan los parámetros observados y se thematizan hipótesis como:

🟢 IDOR.

🟢 SSRF.

🟢 Open Redirect.

🟢 LFI.

🟢 SQLi.

🟢 SSTI.

🟢 Mass Assignment.

🟢 XSS.

🟢 Command Injection.

La clave aquí es que no se trata de una simple lista: cada parámetro se evalúa con contexto y puede sumar evidencia de si esa hipótesis es realmente plausible.

### 4. IDOR con confianza calculada

Uno de los módulos que más me interesó fue la detección pasiva de IDOR.

El sistema combina señales como:

🟢 si el identificador es numérico o UUID.

🟢 si aparece en la ruta o en query params.

🟢 si el recurso es identificable.

🟢 cuántos valores distintos se observan.

🟢 y si se reflejan en la respuesta JSON.

Esto permite generar un porcentaje de confianza en vez de marcarlo todo como vulnerable por nombre.

### 5. Entidades y correlación

Cuando dos IDs aparecen juntos en la misma respuesta, la herramienta intenta encontrar relaciones entre entidades. Eso ayuda a detectar accesos cruzados o comportamiento sospechoso entre tenants, organizaciones o recursos relacionados.

### 6. JWT, secretos y configuraciones de seguridad

Surface Hound también recoge y clasifica:

🟢 JWT vistos en tráfico.

🟢 tokens y secretos expuestos en JS.

🟢 hallazgos de CORS/CSP.

🟢 señales de seguridad frágil como headers problemáticos o configuraciones de frontend mal definidas.

Este tipo de información suele ser muy útil para priorizar lo importante antes de entrar en validaciones activas.

### 7. GraphQL y WebSocket

El proyecto también está pensado para detectar flujos modernos que muchas herramientas tradicionales no tienen en cuenta bien:

🟢 GraphQL por forma del body, no solo por URL.

🟢 batching y operaciones mutantes.

🟢 introspection detectada.

🟢 y tráfico WebSocket con mensajes en vivo.

Esto es muy valioso porque muchas aplicaciones actuales no exponen toda su API como REST simple y se puede perder información importante si uno se queda solo con la capa clásica.

### 8. Scope Guard

Otro punto importante del proyecto es la protección de alcance.

La extensión permite definir patrones allow/deny y marca automáticamente lo que está dentro o fuera de scope. Además, cualquier acción activa puede quedar bloqueada si se intenta operar fuera del alcance autorizado.

Esto ayuda a evitar errores de seguridad prácticos: el tipo de fallo humano que suele pasar durante auditorías intensas.

---

## El enfoque de trabajo

Lo más valioso de Surface Hound no es solo que detecte cosas, sino que organiza la información de forma que el auditor pueda decidir mejor.

La lógica es:

🟢 observar sin generar ruido innecesario.
   
🟢 detectar patrones y correlaciones.
   
🟢 priorizar hipótesis de forma razonada.
   
🟢 preparar validaciones puntuales.

🟢 llevar evidencia en un reporte limpio.

En otras palabras, la herramienta intenta convertir la observación pasiva en un sistema de asistencia para la investigación, no en una caja negra que supuestamente "resuelve" la vulnerabilidad sola.

---

## Puente a la CLI local

Una de las decisiones más útiles del proyecto fue permitir un puente opcional hacia herramientas CLI locales, como:

🟢 nuclei.

🟢 httpx.

🟢 katana.

🟢 arjun.

🟢 dalfox.

🟢 ffuf.

🟢 dnsx.

🟢 gau.

🟢 subfinder.

Esto permite que lo detectado en la extensión pase a un flujo de validación avanzada sin salir de la fase de investigación. El usuario puede ver exactamente qué comando va a ejecutarse y decidir si quiere correrlo personalmente o dejar que la herramienta lo haga desde el agente nativo.

Este tipo de integración ayuda mucho porque no se trata de hacer un análisis aislado: se conecta la observación pasiva con la validación técnica real.

---

## Instalación y uso rápido

El proyecto está pensado para cargar directamente como extensión:

🟢 Chrome / Chromium / Brave: cargar la carpeta `chrome/` en modo desarrollador.

🟢 Firefox: cargar el archivo `firefox/manifest.json` como complemento temporal.

Además, el proyecto incluye un agente nativo opcional para integrar el puente con herramientas de CLI en local.

El flujo recomendado es:

🟢 navegar un objetivo dentro de scope.

🟢 dejar que la extensión capture la superficie de ataque.

🟢 revisar el mapa y los endpoints.

🟢 revisar candidatos a IDOR, GraphQL o secretos.

🟢 preparar el reporte y exportarlo cuando termine la sesión.

---

## ¿Por qué este proyecto me importa?

Para mí, Surface Hound no es solo una herramienta útil; es una forma de materializar una idea concreta sobre cómo debería funcionar el reconocimiento moderno en Bug Bounty.

La idea central es simple:

> la fase de reconocimiento no tiene por qué separarse de la actividad normal del navegador; puede convertirse en un flujo continuo, integrado y mucho más consciente del contexto.

Además, el proyecto me ayudó a trabajar varias cosas a la vez:

🟢 investigación de vulnerabilidades.

🟢 diseño de UX para análisis técnico.

🟢 arquitectura de extensiones de navegador.

🟢 automatización de observación.

🟢 ingeniería de detección heurística.

🟢 pensamiento orientado a la utilidad real para un auditor.

Ese tipo de proyectos suelen ser muy formativos, porque te obligan a pensar no solo en la detección de vulnerabilidades, sino también en cómo presentarlas, cómo priorizarlas, cómo contextualizarlas y cómo evitar falsos positivos con una lógica sensata.

---

## Conclusión

Surface Hound nació como un proyecto personal para resolver un problema real: la cantidad de ruido y trabajo manual que existe durante la fase de reconocimiento.

Hoy sigue siendo una idea muy útil y muy concreta: una extensión que ayuda a **ver más, entender mejor y validar con menos esfuerzo**, siempre dentro del marco de programas autorizados y de una actividad responsable.

Es un proyecto que me ha permitido combinar ciberseguridad, ingeniería y productividad, y sigue siendo una buena base para seguir iterando en nuevas ideas.

Si te interesa el tema de Bug Bounty, reconocimiento pasivo, seguridad web y herramientas de auditoría, este tipo de proyectos suelen ser una de las mejores formas de aprender y, al mismo tiempo, construir algo útil.

---

## Enlaces

🟢 🐙 [Github](https://github.com/Zuk4r1/surface-hound.git)

🟢 ⚖️ [License](https://github.com/Zuk4r1/surface-hound/blob/main/LICENSE)

Si te interesa, en próximas publicaciones puedo contar más detalles sobre la arquitectura interna o tambien me puedes escribir al [correo](investigacion1956@gmail.com), los módulos de detección, y las decisiones de diseño que tomé para construir la extensión.
