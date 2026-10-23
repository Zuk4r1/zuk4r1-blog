---
title: "PHP corrige dos vulnerabilidades críticas de RCE en el motor"
description: "Análisis de CVE-2026-109618 y CVE-2026-109619: fallos de memoria y estado entre solicitudes, escenarios afectados, versiones corregidas y medidas prioritarias."
author: "Zuk4r1"
date: "2026-10-23"
published: true
tags: ["php", "ciberseguridad", "vulnerabilidad", "rce", "cve", "seguridad-web"]
readTime: "10 min"
---

## Dos fallos del motor, una prioridad: actualizar

El 21 de octubre de 2026, el equipo de PHP publicó actualizaciones de seguridad para corregir dos vulnerabilidades críticas que pueden permitir **ejecución remota de código (RCE) sin autenticación** bajo determinadas condiciones:

- **CVE-2026-109618**, relacionada con corrupción de estado durante errores de falta de memoria (*out of memory*, OOM).
- **CVE-2026-109619**, relacionada con referencias obsoletas a memoria de una solicitud anterior (*use-after-free*).

No son fallos de una aplicación o framework concreto: las causas descritas están en el ciclo de vida de solicitudes y en el estado interno que conserva un proceso PHP entre peticiones. La exposición exacta depende de la versión, el SAPI, la configuración, las extensiones y el flujo de la aplicación.

> Este artículo resume los avisos publicados por el equipo de PHP. No incluye una prueba de concepto ni instrucciones para explotar servidores. La prioridad operativa es identificar las instalaciones afectadas y aplicar las versiones corregidas.

## CVE-2026-109618: estado inconsistente tras un OOM

PHP puede interrumpir una operación cuando una asignación de memoria falla. El aviso describe contextos donde esa salida temprana deja parte de la memoria de la solicitud en un estado incompleto. Durante la limpieza posterior, el proceso puede leer o utilizar ese estado de forma insegura.

El equipo de PHP documentó rutas que pueden llevar al agotamiento de memoria durante el procesamiento de solicitudes multipart, por ejemplo, cuando la representación interna de ciertos datos consume más memoria que el cuerpo recibido. También puede haber causas específicas de una aplicación que disparen asignaciones grandes o repetidas.

La advertencia importante es que el problema ocurre en el tratamiento de errores y la finalización de la solicitud: no depende necesariamente de que una ruta PHP de la aplicación haya comenzado a ejecutarse.

El aviso confirma una explotación con RCE a través de HTTP en una configuración con **Apache mod_php**. También señala que el análisis del código considera susceptible a **FPM**, pero distingue ese análisis de la demostración confirmada para mod_php. No conviene asumir que usar FPM elimina el riesgo.

## CVE-2026-109619: referencias que sobreviven a su solicitud

Los procesos PHP persistentes conservan estado interno para atender varias solicitudes. Ese estado debe limpiarse antes de liberar la memoria perteneciente a cada petición. El segundo aviso explica que ciertos caminos de error pueden dejar referencias a esa memoria o volver a publicar estado después de su limpieza.

El fallo requiere una secuencia de eventos: una operación deja estado asociado a una petición, la memoria de esa petición se libera y una operación posterior del mismo proceso consulta la referencia antes de que PHP la inicialice correctamente.

El aviso de PHP describe un caso confirmado en mod_php y una ruta validada en FPM bajo condiciones específicas. No significa que cualquier instalación de PHP sea explotable de la misma manera: influyen la versión, la configuración, el manejo de errores y las operaciones disponibles en la aplicación.

## Versiones afectadas y corregidas

Según los registros CVE publicados por PHP, estas ramas están afectadas antes de sus versiones de corrección:

| Rama afectada | Versión corregida |
| --- | --- |
| PHP 8.2.x | 8.2.35 |
| PHP 8.3.x | 8.3.36 |
| PHP 8.4.x | 8.4.27 |
| PHP 8.5.x | 8.5.12 |

El equipo de PHP publicó las cuatro versiones como actualizaciones de seguridad y recomienda actualizar. Si tu entorno está en una rama anterior o fuera de soporte, no asumas que una configuración alternativa resuelve el problema: planifica la migración a una rama que reciba correcciones.

## Qué debe hacer un equipo de operaciones

1. **Inventariar todos los runtimes PHP.** Incluye servidores web, contenedores, workers, tareas programadas, entornos de staging y servicios administrados.
2. **Identificar la versión realmente ejecutada.** Revisa la versión de CLI y, por separado, la usada por Apache, FPM u otro SAPI; pueden ser distintas.
3. **Actualizar a una versión corregida.** Aplica el paquete oficial o el paquete mantenido por tu distribución y confirma que el servicio cargó la nueva versión.
4. **Reiniciar los procesos persistentes.** Un cambio de archivos no reemplaza automáticamente workers ya iniciados.
5. **Revisar la configuración del procesamiento de solicitudes.** Mantén límites razonables de tamaño, entradas, archivos y consumo; estas medidas reducen abuso y agotamiento de recursos, pero no sustituyen la actualización.
6. **Validar la aplicación después del cambio.** Prueba carga de archivos, formularios, sesiones, integraciones y extensiones en un entorno controlado.
7. **Revisar registros y alertas.** Investiga errores repetidos de memoria, reinicios inesperados de workers y actividad anómala alrededor de los endpoints de carga. La ausencia de eventos en un log no demuestra que una instalación esté protegida.

Los avisos oficiales indican que **actualizar es la única mitigación completa**. Las medidas de configuración pueden reducir ciertas rutas o el impacto operativo, pero no corrigen todas las formas posibles en que el estado interno puede quedar inconsistente.

## Qué significa para desarrolladores

Estos fallos recuerdan que los errores de memoria y las interrupciones no son solo cuestiones de disponibilidad. En un proceso persistente, una solicitud fallida puede afectar el estado que se usará durante una petición posterior si el ciclo de limpieza no es correcto.

Desde el lado de la aplicación:

- Evita depender de configuraciones del runtime como sustituto de los parches.
- Trata las cargas y entradas complejas con límites adecuados y pruebas de regresión.
- Mantén PHP, extensiones y paquetes base bajo un proceso de actualización definido.
- En productos propios basados en PHP, confirma qué versión y SAPI utiliza cada entorno antes de evaluar exposición.

## Conclusión

CVE-2026-109618 y CVE-2026-109619 afectan a mecanismos centrales del motor: el tratamiento de falta de memoria y la limpieza del estado entre solicitudes. Los avisos oficiales describen RCE remota bajo condiciones específicas, así que deben tratarse como actualizaciones prioritarias, no como simples errores internos.

La acción principal es clara: **actualizar a 8.2.35, 8.3.36, 8.4.27 o 8.5.12 —según la rama— y reiniciar los workers**. Después, verifica la versión que realmente sirve tráfico y conserva controles de límites y monitoreo como defensa adicional.

## Fuentes

- [Aviso oficial de PHP: GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [Aviso oficial de PHP: GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP 8.2.35: anuncio de seguridad](https://www.php.net/releases/8_2_35.php)
- [PHP 8.3.36: anuncio de seguridad](https://www.php.net/releases/8_3_36.php)
- [PHP 8.4.27: anuncio de seguridad](https://www.php.net/releases/8_4_27.php)
- [PHP 8.5.12: anuncio de seguridad](https://www.php.net/releases/8_5_12.php)
- [Registro CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618)
- [Registro CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)

> Las versiones y el estado de las recomendaciones corresponden a las fuentes consultadas el 23 de octubre de 2026. Consulta los avisos oficiales antes de tomar decisiones de actualización en producción.
