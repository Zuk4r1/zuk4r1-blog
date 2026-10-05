---
title: "BBLabs: practicar bug bounty para crecer como hunter"
description: "Cómo BBLabs ayuda a entrenar con vulnerabilidades web inspiradas en errores reales, reforzar metodología y mejorar como bug bounty hunter."
author: "Zuk4r1"
date: "2026-10-05"
published: true
tags: ["bblabs", "bug-bounty", "web-security", "xss", "hacking-etico"]
readTime: "6 min"
---

## Aprender a cazar también se entrena

Cuando empecé a practicar bug bounty, una de las cosas que más rápido entendí fue que conocer muchas herramientas no significa necesariamente saber encontrar vulnerabilidades.

Puedes tener Burp Suite, Nuclei, ffuf o cualquier otra herramienta preparada, pero cuando tienes delante una aplicación real necesitas algo más: **saber observar, entender cómo funciona, plantear hipótesis y comprobarlas**.

Y precisamente ahí es donde BBLabs me ha resultado interesante.

BBLabs es una plataforma de laboratorios orientada al aprendizaje de **Bug Bounty y seguridad web**, donde puedo practicar diferentes vulnerabilidades en escenarios controlados. Más que intentar resolver los retos simplemente buscando el payload correcto, he empezado a utilizar los laboratorios como una forma de entrenar el proceso de investigación que después puedo aplicar durante un hunting.

**El dashboard permite ver los laboratorios que voy resolviendo y los módulos en los que he ido practicando.**

## Del reto a la metodología

Una de las cosas que intento evitar cuando practico es convertir un laboratorio en una búsqueda de "qué payload funciona".

Prefiero detenerme a entender primero qué está ocurriendo.

Mi proceso suele ser algo parecido a esto:

1. **Entender la funcionalidad.**
   Primero recorro la aplicación y observo qué hace normalmente. Intento identificar qué datos puedo controlar y dónde terminan esos datos.

2. **Buscar un comportamiento interesante.**
   Si encuentro algo que llama mi atención, intento entender por qué ocurre antes de lanzar diferentes payloads sin un objetivo claro.

3. **Plantear una hipótesis.**
   A partir de ese comportamiento intento determinar qué vulnerabilidad podría existir y qué tendría que demostrar para confirmarla.

4. **Validar la hipótesis.**
   Utilizo pruebas pequeñas y controladas para comprobar si realmente existe un problema de seguridad.

5. **Entender el impacto.**
   No todo comportamiento extraño es una vulnerabilidad. Intento determinar qué podría conseguir un atacante y bajo qué condiciones.

6. **Documentar lo encontrado.**
   Finalmente, intento dejar los pasos suficientemente claros para que otra persona pueda reproducir el resultado, como si estuviera preparando un reporte de bug bounty.

Con la práctica empiezas a reconocer ciertos patrones: datos que llegan a lugares donde no deberían, validaciones que solamente existen en el cliente, controles que pueden saltarse o funcionalidades que confían demasiado en información proporcionada por el usuario.

## Un ejemplo: DOM XSS y esquemas de URL

Uno de los laboratorios que aparece en mi recorrido trabaja un escenario de **DOM XSS dentro de un runtime de formularios embebibles**, relacionado con la inyección mediante un esquema de URL.

Este tipo de laboratorio me parece especialmente interesante porque obliga a mirar más allá de una simple reflexión de parámetros.

La pregunta no es solamente:

> "¿Mi entrada aparece en la página?"

La pregunta realmente importante es:

> **"¿Qué ocurre con esa entrada después de llegar al DOM?"**

Ahí es donde empieza el análisis interesante.

Hay que seguir el flujo del dato, entender qué código lo procesa, determinar en qué contexto termina y comprobar cómo interpreta el navegador ese valor.

En un entorno autorizado, la validación puede hacerse con una prueba inocua que permita demostrar la ejecución sin afectar a otros usuarios. Después, el objetivo es poder explicar claramente el recorrido:

**entrada controlada → procesamiento → sink → ejecución → impacto.**

Ese proceso de seguir el flujo es mucho más valioso para mí que simplemente conseguir que aparezca un `alert()`.

## Lo que me está aportando BBLabs

Una de las ventajas que encuentro en este tipo de plataformas es que permiten repetir una misma idea hasta que deja de ser algo puramente teórico.

* Puedo equivocarme.

* Puedo probar una hipótesis que no funciona.

* Puedo volver atrás.

* Puedo analizar nuevamente la aplicación.

* Y puedo intentar entender por qué la solución funciona en lugar de limitarme a copiarla.

Ese ciclo de prueba y error es importante porque muchas veces una vulnerabilidad no aparece de forma evidente. En un programa real, probablemente no voy a encontrar un parámetro acompañado de una etiqueta que diga "aquí tienes tu XSS".

**Voy a tener que descubrirlo.**

Por eso considero que los laboratorios son una buena forma de entrenar esa capacidad de observación.

## No es lo mismo resolver un lab que hacer Bug Bounty

También creo que es importante hacer esta distinción.

Resolver laboratorios no significa automáticamente estar preparado para encontrar vulnerabilidades en cualquier programa de bug bounty.

En un laboratorio conozco el objetivo y sé que existe una vulnerabilidad que debo encontrar. En un programa real puedo pasar horas investigando una funcionalidad sin encontrar nada.

Además, aparecen otros factores:

* El alcance del programa.
* Las reglas de engagement.
* Las tecnologías utilizadas.
* La lógica específica de la aplicación.
* El impacto real de cada vulnerabilidad.
* Los falsos positivos.
* La calidad de la evidencia.
* Los criterios de severidad y aceptación del programa.

Aun así, creo que los laboratorios cumplen una función importante: **permiten entrenar los músculos necesarios para el hunting**.

## Lo que más me interesa como hunter

* Para mí, el valor de BBLabs no está solamente en acumular laboratorios resueltos.

* Lo interesante está en lo que ocurre mientras intento resolverlos.

* Cada reto me obliga a practicar una parte diferente del proceso:

**observar → investigar → plantear hipótesis → validar → entender el impacto → documentar.**

* Con el tiempo, esa repetición ayuda a que ciertas situaciones empiecen a resultar familiares.

* Una aplicación que confía demasiado en un parámetro.

* Una validación que solamente ocurre en JavaScript.

* Un flujo que se comporta de manera diferente dependiendo del contexto.

* Un dato controlado por el usuario que termina en un lugar inesperado.

* Son precisamente esos pequeños detalles los que pueden convertirse en una buena pista durante una investigación real.

## Mi conclusión

Después de practicar diferentes laboratorios, cada vez veo más claro que **aprender Bug Bounty no consiste únicamente en aprender vulnerabilidades**, también hay que aprender a investigar.

Las herramientas ayudan muchísimo, pero no sustituyen la capacidad de observar una aplicación y hacerse las preguntas correctas.

BBLabs me está sirviendo precisamente para entrenar esa parte: enfrentarme a escenarios concretos, equivocarme, volver a analizar el comportamiento y entender finalmente por qué existe la vulnerabilidad, al final, resolver el laboratorio es solo una parte.

Lo realmente útil es poder terminarlo pensando:

**"Ahora entiendo qué estaba pasando y sé cómo buscar algo parecido en otra aplicación."**

Y probablemente ahí está una de las diferencias entre aprender a explotar una vulnerabilidad y empezar a aprender a **cazar vulnerabilidades**.

> Practica siempre dentro de laboratorios o programas con autorización explícita. En un programa real, respeta siempre el alcance, las reglas y las políticas del objetivo.

