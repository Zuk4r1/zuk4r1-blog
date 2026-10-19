---
title: "Cómo redactar un reporte de vulnerabilidad claro y reproducible"
description: "Guía práctica para documentar hallazgos de Bug Bounty: pasos de reproducción, evidencia, impacto demostrado y una plantilla reutilizable para reportes técnicos."
author: "Zuk4r1"
date: "2026-10-19"
published: true
tags: ["bug-bounty", "reporting", "pentesting", "metodologia", "hacking-etico"]
readTime: "9 min"
---

## Encontrar el fallo es solo una parte del trabajo

Una vulnerabilidad puede ser real y aun así resultar difícil de evaluar si el reporte no explica qué ocurre, cómo reproducirlo o cuál es el impacto demostrado. Un buen informe reduce las dudas del equipo que lo recibe y facilita que pueda validar y corregir el problema.

La meta no es escribir mucho ni utilizar términos sofisticados. Es dejar una historia técnica verificable:

**contexto → pasos → evidencia → impacto → recomendación.**

Esta guía propone un método y una plantilla para documentar hallazgos en laboratorios, auditorías propias o programas donde exista autorización explícita. Antes de probar nada en un programa, revisa su alcance, sus reglas y sus límites de interacción.

## Antes de redactar: confirma el hallazgo

Detén la exploración y organiza lo observado. Antes de llamarlo vulnerabilidad, comprueba:

1. **Alcance:** el activo y la funcionalidad están permitidos por las reglas aplicables.
2. **Reproducibilidad:** puedes repetir el comportamiento con pasos concretos.
3. **Causa:** puedes describir qué control falla, no solo qué respuesta te sorprendió.
4. **Impacto:** distingues entre lo que demostraste y lo que solo supones que podría ocurrir.
5. **Seguridad:** no accediste a datos ajenos ni realizaste acciones destructivas para probar la hipótesis.

Si una comprobación requiere afectar a otra persona, alterar información real o superar el alcance autorizado, no la realices. Explica la limitación y consulta el canal definido por el programa.

## Una estructura que ayuda al triage

### 1. Título específico

Resume el fallo, su ubicación y el efecto comprobado. Evita títulos vagos como «Bug importante» o etiquetas de severidad sin contexto.

Una estructura práctica es:

> `[Tipo de fallo] en [funcionalidad o endpoint] permite [impacto demostrado]`

Por ejemplo, en un entorno de pruebas propio:

> `Control de acceso ausente en la descarga de facturas permite a otro usuario del laboratorio leerlas`

El título describe el resultado observado; no afirma consecuencias que todavía no verificaste.

### 2. Resumen breve

En dos o tres frases, explica qué componente está afectado, qué condición provoca el fallo y por qué importa. Una persona que no conozca tu investigación debería poder entender el problema sin leer todo el informe.

### 3. Entorno y precondiciones

Incluye únicamente el contexto necesario para repetir la prueba:

- URL o nombre del activo autorizado.
- Fecha y hora aproximadas, si pueden ayudar a localizar registros.
- Tipo de cuenta y permisos utilizados, sin incluir contraseñas ni tokens.
- Navegador, cliente o versión, si influyen en el comportamiento.
- Datos preparados específicamente para la prueba.

Redacta cookies, tokens, direcciones de correo y otros datos personales antes de compartir capturas o solicitudes.

### 4. Pasos de reproducción

Escribe una acción por paso, en el orden exacto. Usa dos cuentas controladas por ti solo cuando las reglas permitan crear y utilizar esas cuentas. Identifícalas como **Cuenta A** y **Cuenta B**; nunca uses cuentas de otras personas.

Los pasos deben responder:

1. ¿Con qué cuenta se inicia la sesión?
2. ¿Qué acción crea o selecciona el recurso de prueba?
3. ¿Qué solicitud o interacción provoca el comportamiento?
4. ¿Qué resultado se observa y cómo se confirma?

En lugar de «cambiar el ID y funciona», indica cuál era el estado inicial, qué variable cambiaste y qué mostró la aplicación. Mantén los ejemplos limitados a recursos ficticios o creados para la prueba.

### 5. Resultado observado y esperado

Separa con claridad ambos resultados:

- **Observado:** lo que la aplicación hizo durante la reproducción.
- **Esperado:** lo que debería hacer según el modelo de permisos o el flujo previsto.

Esta separación evita que una interpretación se confunda con la evidencia.

### 6. Evidencia mínima y suficiente

Adjunta una captura, una solicitud/respuesta redactada o un video corto si aporta claridad. La evidencia debería probar el comportamiento sin revelar secretos ni datos que no sean necesarios.

Antes de adjuntarla, revisa y elimina:

- `Authorization`, `Cookie`, claves API y tokens.
- Datos personales o información de terceros.
- Contenido de archivos que no sea necesario para explicar el fallo.
- Información de infraestructura que no aporte a la reproducción.

No recopiles más datos para «hacer más convincente» el hallazgo. Una demostración pequeña, controlada y repetible suele ser mejor.

## Impacto: describe lo que probaste

El impacto debe conectar la causa técnica con una consecuencia concreta. Evita basarte únicamente en el nombre de una categoría o en la severidad asignada por una herramienta.

Puedes redactarlo con esta secuencia:

1. **Capacidad:** qué acción no autorizada puede realizarse.
2. **Límite afectado:** qué separación de usuarios, permisos o datos deja de cumplirse.
3. **Evidencia:** qué observación respalda la afirmación.
4. **Alcance:** qué no comprobaste o qué limitaciones tuvo la prueba.

No afirmes que hay «toma de control de cuentas», «exposición masiva» o «acceso administrativo» si no lo demostraste de forma autorizada. Si un impacto mayor es plausible pero no seguro de validar, decláralo como posibilidad y explica por qué no lo probaste.

## Recomendación útil para quien corrige

Propón una dirección de mitigación, no una solución improvisada que ignore el diseño de la aplicación. En un problema de autorización, por ejemplo, la recomendación general es comprobar en el servidor que la identidad autenticada tiene permiso para realizar esa acción sobre ese recurso en cada operación relevante.

Según el hallazgo, también puede ser útil sugerir:

- Aplicar denegación por defecto.
- Validar permisos en operaciones de lectura y escritura.
- No confiar en identificadores o roles proporcionados por el cliente.
- Añadir pruebas de regresión con usuarios y permisos distintos.
- Revisar registros para detectar accesos que ya hayan ocurrido.

Mantén la recomendación vinculada al fallo observado. No es necesario rediseñar todo el sistema en un reporte.

## Plantilla reutilizable

Puedes copiar esta estructura y completar solo lo que hayas confirmado:

```markdown
# [Tipo de fallo] en [funcionalidad] permite [impacto demostrado]

## Resumen
[Qué falla, dónde y bajo qué condición.]

## Activo afectado
- URL o componente:
- Entorno:
- Cuenta y permisos utilizados:

## Precondiciones
- [Condiciones necesarias para reproducirlo.]

## Pasos de reproducción
1. [Acción inicial usando una cuenta de prueba autorizada.]
2. [Acción que prepara el recurso de prueba.]
3. [Solicitud o interacción exacta, con secretos redactados.]
4. [Resultado que confirma el comportamiento.]

## Resultado observado
[Comportamiento reproducible.]

## Resultado esperado
[Comportamiento correcto según los permisos previstos.]

## Impacto demostrado
[Consecuencia concreta respaldada por la evidencia.]

## Evidencia
[Captura o solicitud/respuesta redactada.]

## Recomendación
[Control que debería validarse o reforzarse.]

## Límites de la prueba
[Qué no se probó para evitar acceder a datos ajenos o afectar el servicio.]
```

## Revisión final antes de enviar

- [ ] El activo está dentro del alcance y respeté las reglas del programa.
- [ ] Otra persona puede seguir los pasos sin adivinar información.
- [ ] El resultado esperado está separado del observado.
- [ ] El impacto está respaldado por evidencia y no por especulación.
- [ ] Los secretos y datos personales están redactados.
- [ ] La prueba se limitó a cuentas y recursos controlados.
- [ ] La recomendación aborda la causa probable del fallo.
- [ ] No incluí acciones destructivas ni datos innecesarios.

Un reporte claro también es parte del trabajo de seguridad: permite validar el riesgo, coordinar la corrección y aprender del fallo sin aumentar su impacto. La calidad no se mide por la cantidad de capturas, sino por lo fácil que resulta entender y verificar lo que realmente ocurrió.
