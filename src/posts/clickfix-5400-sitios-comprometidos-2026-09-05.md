---
title: "Más de 5.400 sitios comprometidos distribuyen ClickFix desde la blockchain"
date: "2026-09-05"
description: "Una campaña masiva aprovecha sitios legítimos comprometidos y contratos de la BNB Smart Chain para servir instrucciones ClickFix y engañar a los usuarios para que ejecuten comandos maliciosos."
tags: ["ciberseguridad", "clickfix", "ingenieria-social", "malware", "blockchain", "noticias"]
readTime: "8 min"
published: true
---

## Una campaña convierte miles de webs legítimas en trampas para usuarios

Una campaña de ingeniería social está utilizando más de **5.400 sitios web comprometidos** para distribuir cargas de ClickFix almacenadas en contratos inteligentes de la BNB Smart Chain. El dato fue publicado por [BleepingComputer el 5 de septiembre de 2026](https://www.bleepingcomputer.com/news/security/over-5-400-hacked-sites-serve-clickfix-payloads-stored-on-the-blockchain/).

El caso combina dos técnicas que ya eran peligrosas por separado: la confianza que genera visitar una web legítima y una instrucción falsa que presenta una acción manual como si fuera una solución técnica. La blockchain añade una capa de disponibilidad y dificulta retirar el contenido malicioso de forma convencional.

## ¿Qué es ClickFix?

ClickFix es una familia de campañas basadas en **ingeniería social**, no una vulnerabilidad concreta. La víctima suele ver un aviso que simula un error del navegador, una verificación de seguridad o un problema con una aplicación. El mensaje le pide copiar y pegar un comando en PowerShell, en la terminal o en el cuadro de ejecución de Windows.

El flujo habitual es:

1. La persona llega a una página legítima que ha sido modificada o a un sitio que redirige a la campaña.
2. Un aviso falso le indica que debe completar una supuesta verificación.
3. La instrucción copia un comando controlado por el atacante en el portapapeles.
4. La víctima lo pega y lo ejecuta con sus propios permisos.
5. El comando descarga la siguiente fase del malware o roba información del equipo.

El punto clave es que el atacante intenta que el propio usuario autorice la ejecución. Por eso los controles tradicionales que bloquean una descarga automática pueden no ser suficientes.

## Por qué la blockchain cambia el juego

En esta campaña, los sitios comprometidos consultan contratos de la BNB Smart Chain para obtener instrucciones o contenido de la infraestructura ClickFix. El uso de contratos inteligentes puede aportar varias ventajas operativas al atacante:

- **Resistencia a la retirada:** no depende de un único servidor web que pueda darse de baja.
- **Distribución:** los operadores pueden actualizar el contenido consultado sin modificar cada sitio comprometido.
- **Dificultad de atribución:** la infraestructura se reparte entre webs vulneradas, dominios y direcciones de cadena.
- **Persistencia:** aunque se bloquee una URL concreta, otras páginas pueden recuperar la misma campaña.

Esto no significa que la blockchain vuelva invisible el ataque. Las transacciones son públicas y las direcciones pueden convertirse en indicadores de compromiso. El reto es detectar y bloquear la cadena completa: página, contrato, dominio, comando y carga final.

## El impacto para las organizaciones

La escala de la campaña aumenta la probabilidad de que una persona encuentre el señuelo durante una navegación normal. Además, el sitio que sirve la primera etapa puede pertenecer a una pequeña empresa, una asociación o un proveedor que el equipo de seguridad considera confiable.

Los riesgos principales son:

- robo de credenciales, cookies de sesión y tokens;
- instalación de infostealers o troyanos de acceso remoto;
- compromiso de cuentas corporativas con sesiones ya autenticadas;
- movimiento lateral desde un equipo de usuario con acceso a recursos internos;
- uso de cuentas comprometidas para nuevas campañas de phishing.

La cadena de ataque depende de la interacción humana, pero eso no la hace menos técnica. Una vez ejecutado el comando, la respuesta debe tratarse como un posible incidente de endpoint y de identidad.

## Qué deberían hacer los equipos de seguridad

### Bloquear la ejecución desde el portapapeles

Las políticas de Windows y las herramientas EDR pueden detectar o restringir la ejecución de PowerShell, `mshta`, `rundll32`, `wscript` y otros intérpretes cuando se lanzan desde aplicaciones de oficina, navegadores o rutas temporales. La regla debe probarse para no romper flujos legítimos, pero el objetivo es elevar la fricción cuando un usuario pega comandos en una consola.

### Vigilar la cadena completa

Conviene buscar en telemetría:

- procesos de PowerShell iniciados por navegadores;
- comandos pegados que contienen descargas, codificación o ejecución en memoria;
- consultas de DNS y conexiones a dominios recién registrados;
- acceso a direcciones o contratos de la BNB Smart Chain desde endpoints corporativos;
- creación de tareas programadas, claves de inicio automático y archivos en directorios temporales.

### Reforzar la respuesta ante una ejecución accidental

Si un usuario ejecutó el comando:

1. Aislar el equipo de la red sin apagarlo, si la política permite conservar evidencias.
2. Revocar sesiones y rotar credenciales usadas en ese dispositivo.
3. Revisar procesos, persistencia, conexiones salientes y actividad de la cuenta.
4. Buscar el mismo indicador en el resto de endpoints.
5. Registrar la URL, el texto mostrado y el comando para alimentar las detecciones.

## La lección principal

ClickFix demuestra que la confianza en una web y la confianza en una instrucción son cosas distintas. Una página legítima puede estar comprometida, y un aviso visualmente convincente no convierte en segura una orden de terminal.

La defensa más efectiva combina aislamiento de endpoints, mínimo privilegio, telemetría de procesos, autenticación resistente al robo de sesión y formación breve orientada a una regla concreta: **ningún sitio web debería pedir al usuario que pegue y ejecute comandos para completar una verificación**.

### Fuente

- [BleepingComputer: Over 5,400 hacked sites serve ClickFix payloads stored on the blockchain](https://www.bleepingcomputer.com/news/security/over-5-400-hacked-sites-serve-clickfix-payloads-stored-on-the-blockchain/), 5 de septiembre de 2026.