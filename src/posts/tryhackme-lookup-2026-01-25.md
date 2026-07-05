---
title: "tryhackme-lookup"
description: "Writeup de la máquina Lookup de TryHackMe: Enumeración de usuarios, explotación de elFinder y escalada de privilegios mediante Path Hijacking y Sudo."
date: "2026-01-25"
published: true
tags: ["tryhackme", "writeup", "linux", "elfinder", "path-hijacking", "gtfobins"]
readTime: "12 min"
---

# 🔍 TryHackMe — Lookup (Paso a Paso)

**Lookup** es una máquina Linux de dificultad media en TryHackMe que pone a prueba nuestras habilidades de enumeración web, fuerza bruta y escalada de privilegios explotando configuraciones inseguras y binarios SUID personalizados.

---

## 1) Reconocimiento y Enumeración

Comenzamos con un escaneo básico de puertos utilizando `nmap` para identificar los servicios expuestos.

```bash
nmap -sC -sV -Pn -oN  <IP_MACHINE>
```

**Puertos abiertos:**
- `22/tcp`: SSH (OpenSSH)
- `80/tcp`: HTTP (Apache)

Al visitar el puerto 80, el sitio nos redirige a `lookup.thm`. Debemos agregar este dominio a nuestro archivo `/etc/hosts`.

```bash
echo "<IP_MACHINE> lookup.thm" | sudo tee -a /etc/hosts
```

### Enumeración Web

El sitio web muestra un formulario de inicio de sesión. Al probar credenciales por defecto (`admin:admin`), notamos un comportamiento interesante en los mensajes de error:
- "Wrong user": El usuario no existe.
- "Wrong password": El usuario existe, pero la contraseña es incorrecta.

Esto nos permite enumerar usuarios válidos. Podemos usar un script en Python o `hydra` si configuramos bien los mensajes de error, pero una enumeración manual o con `ffuf` revela dos usuarios potenciales:
- `admin`
- `jose`

Tras intentar fuerza bruta contra `jose` usando `hydra` y `rockyou.txt`:

```bash
hydra -l jose -P /usr/share/wordlists/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong password"
```

Obtenemos la contraseña válida. Al iniciar sesión, somos redirigidos a un nuevo subdominio: `files.lookup.thm`. Lo agregamos también al `/etc/hosts`.

---

## 2) Explotación: elFinder

Al acceder a `files.lookup.thm`, nos encontramos con **elFinder**, un gestor de archivos web. La versión detectada es **2.1.47**.

Esta versión es vulnerable a una **Inyección de Comandos (Command Injection)** (CVE-2019-9194). La vulnerabilidad reside en el conector PHP (`connect.minimal.php`), que permite subir archivos y ejecutar comandos arbitrarios al manipular el nombre del archivo.

### Obtención de Shell

Podemos utilizar un exploit público para esta versión o hacerlo manualmente. El objetivo es subir un archivo PHP malicioso (webshell) o ejecutar un comando reverso.

Existen scripts en Python disponibles en SearchSploit o GitHub para explotar esta versión automáticamente.

```bash
searchsploit elfinder
# Usamos el exploit para Command Injection
python3 exploit_elfinder.py http://files.lookup.thm/php/connector.minimal.php
```

Una vez ejecutado, logramos ejecución remota de comandos (RCE) y establecemos una Reverse Shell para ganar acceso como el usuario `www-data`.

---

## 3) Escalada de Privilegios (Usuario)

Ya dentro del sistema, enumeramos los usuarios en `/home` y encontramos al usuario `think`.

En el directorio raíz `/`, o buscando binarios SUID, encontramos un ejecutable inusual: `/usr/sbin/pwm`.

```bash
find / -perm -4000 2>/dev/null
```

Al ejecutar `pwm`, parece ser una herramienta que gestiona contraseñas. Si analizamos su comportamiento (usando `strings` o `ltrace`), vemos que llama al comando `id` para verificar el usuario actual y luego intenta leer un archivo de contraseñas en su home.

El problema es que llama a `id` sin la ruta absoluta (es decir, usa `id` en lugar de `/usr/bin/id`). Esto es vulnerable a **Path Hijacking**.

### Path Hijacking

1. Creamos un script falso llamado `id` en `/tmp` que imprima lo que queremos (por ejemplo, que diga que somos el usuario `think` o simplemente ejecute una shell).
2. Damos permisos de ejecución.
3. Modificamos la variable de entorno `$PATH` para que `/tmp` esté primero.

```bash
cd /tmp
echo -e '#!/bin/bash\necho "uid=1000(think) gid=1000(think) groups=1000(think)"' > id
chmod +x id
export PATH=/tmp:$PATH
```

Al ejecutar `/usr/sbin/pwm` ahora, utilizará nuestro `id` falso. Esto engaña al binario haciéndole creer que somos `think` y nos revela sus credenciales o nos permite acceder a su información.

Con las credenciales obtenidas, nos conectamos por SSH como `think`.

---

## 4) Escalada de Privilegios (Root)

Como usuario `think`, comprobamos los permisos de `sudo`:

```bash
sudo -l
```

Vemos que podemos ejecutar el comando `/usr/bin/look` como `root` sin contraseña.

### Explotación con Look

Consultamos **GTFOBins** para `look`. Esta herramienta sirve para mostrar líneas que comienzan con una cadena dada en un archivo, pero si se ejecuta con `sudo`, podemos leer archivos privilegiados.

Para leer la flag de root (`/root/root.txt`) o la clave SSH privada:

```bash
sudo look '' /root/root.txt
# O para leer la clave SSH
sudo look '' /root/.ssh/id_rsa
```

El comando `look '' FILE` imprime todo el contenido del archivo porque todas las líneas "comienzan" con una cadena vacía.

¡Y con esto hemos comprometido la máquina por completo!

---

## Resumen

1. **Reconocimiento**: Enumeración de subdominios (`lookup.thm`, `files.lookup.thm`).
2. **Acceso Inicial**: Enumeración de usuarios y fuerza bruta en el login -> Explotación de CVE en elFinder.
3. **Escalada a Usuario**: Path Hijacking en binario SUID `pwm`.
4. **Escalada a Root**: Abuso de permisos `sudo` con la herramienta `look` (File Read).
