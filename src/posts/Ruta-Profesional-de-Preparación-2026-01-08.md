---
title: "Ruta Profesional de Preparación para el Examen eJPT"
description: "Guía práctica y orientada al examen eJPT con una ruta clara de laboratorios TryHackMe. Enfocada en reconocimiento, enumeración, SMB, Windows, Drupal, WordPress, pivoting y escalada de privilegios, tal como se evalúa en el examen real."
date: "2026-01-08"
published: true
tags: ["ejpt", "pentesting", "tryhackme", "cybersecurity", "red-teaming", "enumeracion", "privilege-escalation"]
readTime: "18 min"
---

# Ruta Profesional de Preparación para el Examen **eJPT**

**Objetivo:** Proporcionar una ruta clara, práctica y 100% orientada al examen **eJPT (eLearnSecurity Junior Penetration Tester)**, enfocada en reconocimiento, enumeración, explotación básica, pivoting y escalada de privilegios, tal como se evalúa en el entorno real del examen.

---

## 🟢 RECONOCIMIENTO Y ENUMERACIÓN

### *(DMZ, Sistema Operativo, Servicios)*

La base del eJPT es **identificar correctamente el sistema operativo, los servicios expuestos y posibles vectores de ataque**. Una mala enumeración conduce a fallos tempranos en el examen.

### ✅ Network Services

📌 **Nivel:** Free

📌 **Enfoque:** Enumeración inicial

**Habilidades clave:**

* Descubrimiento de hosts activos
* Identificación de servicios y versiones
* Detección de sistema operativo

**Herramientas:**

* `nmap -sn`
* `nmap -sV`
* `nmap -O`

**Servicios tratados:**

* SMB
* FTP
* HTTP
* Detección Windows / Linux

---

### ✅ Network Services 2

📌 **Nivel:** Free

📌 **Enfoque:** Enumeración profunda de servicios

**Habilidades clave:**

* Enumeración SMB
* Acceso FTP anónimo
* Enumeración de shares y usuarios

**Técnicas:**

* `smbclient`
* `enum4linux`
* `ftp-anon`

---

## 🟢 SMB / WINDOWS ENUMERATION (CLAVE PARA eJPT)

Windows + SMB es uno de los pilares del examen. Entender cómo enumerar y explotar estos servicios es **crítico**.

### ✅ Blue

📌 **Nivel:** Free

**Habilidades clave:**

* Enumeración Windows
* SMB exploitation
* EternalBlue (MS17-010)
* Uso básico de Meterpreter

---

### ✅ Steel Mountain

📌 **Nivel:** Free

**Habilidades clave:**

* Windows Server
* Enumeración Web + SMB
* Escalada básica de privilegios

---

## 🟢 WORDPRESS / DRUPAL / WEB

El eJPT evalúa **enumeración web realista**, no ataques complejos. Saber identificar CMS vulnerables es suficiente para avanzar.

### ✅ WordPress: Basics

📌 **Nivel:** Free

**Habilidades clave:**

* Enumeración con `wpscan`
* Ataques de fuerza bruta
* Análisis de `wp-config.php`

---

### ✅ Blog

📌 **Nivel:** Free

**Habilidades clave:**

* WordPress vulnerable
* Enumeración web realista

---

### ✅ DVWA

📌 **Nivel:** Free

**Habilidades clave:**

* Command Injection
* Descubrimiento de archivos
* Credenciales en texto claro

---

### ✅ Vulnversity

📌 **Nivel:** Free

**Habilidades clave:**

* Web fuzzing
* `dirb` / `gobuster`
* Escalada de privilegios en Linux

---

## 🟢 DRUPAL (MUY IMPORTANTE)

Drupal aparece **directamente** en múltiples escenarios del examen.

### ✅ Overpass

📌 **Nivel:** Free

**Habilidades clave:**

* Enumeración Drupal
* Obtención de credenciales
* Linux privilege escalation

---

### ✅ Internal

📌 **Nivel:** Free

**Habilidades clave:**

* Drupal en red interna
* Pivoting
* Movimiento lateral

---

## 🟢 FTP / MYSQL / SERVICIOS

### ✅ Kenobi

📌 **Nivel:** Free

**Habilidades clave:**

* FTP anónimo
* Enumeración MySQL
* Linux privilege escalation

---

## 🟢 PIVOTING / RED INTERNA (EXAMEN REAL)

El pivoting **sí aparece en el eJPT**, aunque de forma básica.

### ✅ Wreath

📌 **Nivel:** Free

**Habilidades clave:**

* Pivoting
* `autoroute`
* `portfwd`

---

### ✅ Internal (Red Interna)

📌 **Nivel:** Free

**Habilidades clave:**

* Hosts inaccesibles desde DMZ
* Movimiento lateral

---

## 🟢 METASPLOIT / METERPRETER

### ✅ Metasploit

📌 **Nivel:** Free

**Habilidades clave:**

* `msfconsole`
* `hta_server`
* `autoroute`

---

## 🟢 PASSWORDS / HASHES

### ✅ Crack the Hash

📌 **Nivel:** Free

**Habilidades clave:**

* SHA-512
* Uso de `rockyou.txt`

---

## 🧠 MAPEO RÁPIDO (ORIENTADO AL EXAMEN)

* SMB / Windows → **Blue**
* WordPress → **Blog**
* Drupal → **Overpass**
* FTP anon → **Kenobi**
* Command Injection → **DVWA**
* Pivoting → **Internal**
* Linux PrivEsc → **Vulnversity**
* Meterpreter → **Metasploit**

---

## 🎯 RUTA ÓPTIMA (SI SOLO HACES 7 LABS)

1. Network Services
2. Blue
3. Blog
4. Overpass
5. Kenobi
6. Vulnversity
7. Internal

> **Conclusión:** Si completas esta ruta y **entiendes lo que haces**, no solo memorizas comandos, **puedes aprobar el eJPT sin problemas** y con criterio profesional.

---

✍️ *Documento orientado a pentesters junior y candidatos al eJPT con enfoque práctico, realista y alineado al examen oficial.*