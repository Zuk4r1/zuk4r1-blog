---
title: "Ruta de Preparación Profesional para eJPT"
description: "Guía estratégica y estructurada para dominar el examen eJPT utilizando laboratorios gratuitos de TryHackMe. Cubre desde enumeración básica hasta pivoting y explotación avanzada."
date: "2026-01-08"
published: true
tags: ["ejpt", "certificaciones", "pentesting", "tryhackme", "roadmap"]
readTime: "15 min"
---

# 🛡️ Dominando el eJPT: Ruta de Estudio Profesional

El examen **eJPT (eLearnSecurity Junior Penetration Tester)** es una certificación 100% práctica que evalúa tus habilidades reales en un entorno dinámico de caja negra. A diferencia de los exámenes teóricos, aquí debes enumerar, explotar y pivotar a través de una red corporativa simulada.

Eh diseñado esta ruta de preparación utilizando laboratorios **gratuitos** de TryHackMe, seleccionados quirúrgicamente para cubrir los vectores de ataque más frecuentes en el examen real. Sigue este plan para maximizar tus posibilidades de éxito.

---

## 🟢 Fase 1: Reconocimiento y Enumeración
*La base de todo ataque exitoso. Si fallas aquí, fallarás en la explotación.*

### 1. Network Services
**📌 Nivel:** Free | **🎯 Enfoque:** Protocolos básicos

Esta sala es fundamental para entender cómo interactuar con servicios comunes sin herramientas automatizadas complejas.
- **Herramientas clave:** `nmap` `-sn`, `-sV`, `-O`, clientes SMB, FTP y HTTP.
- **Objetivos de aprendizaje:**
  - Detección de sistemas operativos (Windows vs Linux).
  - Enumeración de puertos abiertos y versiones de servicios.

### 2. Network Services 2
**📌 Nivel:** Free | **🎯 Enfoque:** Enumeración profunda

Profundiza en la configuración insegura de servicios de red, un escenario clásico en el eJPT.
- **Técnicas clave:**
  - **SMB Enumeration:** Listado de recursos compartidos (`shares`) y usuarios.
  - **FTP Anónimo:** Verificación de acceso `ftp-anon` y exfiltración de archivos.

---

## 🟢 Fase 2: Entorno Windows y SMB
*El examen eJPT tiene una fuerte carga de entornos Windows. Dominar SMB es obligatorio.*

### 3. Blue
**📌 Nivel:** Free | **🎯 Enfoque:** Explotación de vulnerabilidades críticas

El escenario perfecto para practicar la identificación y explotación de fallos históricos como EternalBlue.
- **Técnicas clave:**
  - Enumeración exhaustiva de Windows.
  - Detección y explotación de **MS17-010 (EternalBlue)**.
  - Manejo básico de sesiones **Meterpreter**.

### 4. Steel Mountain
**📌 Nivel:** Free | **🎯 Enfoque:** Servidores Windows y Escalada

Simula un entorno corporativo con Windows Server, combinando vulnerabilidades web con escalada de privilegios.
- **Técnicas clave:**
  - Enumeración de servicios HTTP en puertos no estándar.
  - Escalada de privilegios en Windows (PowerShell scripts, servicios vulnerables).

---

## 🟢 Fase 3: Hacking Web y CMS
*WordPress y Drupal son los CMS más recurrentes en el examen. Debes saber auditarlos manualmente y con herramientas.*

### 5. WordPress: Basics & Blog
**📌 Nivel:** Free | **🎯 Enfoque:** Enumeración y Fuerza Bruta

Dos salas esenciales para dominar el ataque al CMS más popular del mundo.
- **Técnicas clave:**
  - Uso de **WPScan** para enumerar usuarios, plugins y temas.
  - Ataques de fuerza bruta a paneles de login.
  - Extracción de credenciales de archivos de configuración (`wp-config.php`).

### 6. DVWA (Damn Vulnerable Web App)
**📌 Nivel:** Free | **🎯 Enfoque:** Vulnerabilidades Web Clásicas

Un entorno controlado para entender la lógica detrás de los fallos web.
- **Técnicas clave:**
  - **Command Injection:** Ejecución de comandos del sistema a través de inputs web.
  - Descubrimiento de archivos y credenciales en texto claro.

### 7. Vulnversity
**📌 Nivel:** Free | **🎯 Enfoque:** Fuzzing y Uploads

Práctica intensiva de reconocimiento web y explotación de subidas de archivos.
- **Técnicas clave:**
  - Fuzzing de directorios con `dirb` o `gobuster`.
  - Bypass de restricciones de subida de archivos.
  - Escalada de privilegios en Linux (SUID, GTFOBins).

---

## 🟢 Fase 4: Drupal (Punto Crítico)
*Drupal suele ser el "filtro" en el examen. Muchos estudiantes fallan aquí por falta de práctica específica.*

### 8. Overpass & Internal
**📌 Nivel:** Free | **🎯 Enfoque:** CMS complejo y Pivoting
- **Técnicas clave:**
  - Enumeración de versiones de Drupal y explotación (Drupalgeddon, etc.).
  - Obtención de credenciales y acceso inicial.
  - **Pivoting:** Conceptos de túneles hacia redes internas.

---

## 🟢 Fase 5: Servicios e Infraestructura
### 9. Kenobi
**📌 Nivel:** Free | **🎯 Enfoque:** Samba, NFS y ProFTPD

Una máquina "todo en uno" que combina múltiples vectores de entrada.
- **Técnicas clave:**
  - Explotación de FTP anónimo y montajes NFS.
  - Enumeración de MySQL.
  - Manipulación de binarios con SUID para escalada.

---

## 🟢 Fase 6: Pivoting y Redes Internas
*El diferencial del eJPT. Debes saber moverte de una máquina comprometida a otra inaccesible.*

### 10. Wreath & Internal
**📌 Nivel:** Free | **🎯 Enfoque:** Movimiento Lateral
- **Técnicas clave:**
  - Configuración de `autoroute` y `portfwd` en Metasploit.
  - Escaneo de hosts en redes ocultas/internas.
  - Uso de Chisel o SSH tunneling (opcional pero recomendado).

---

## 🧠 Resumen Estratégico

### Mapeo Rápido de Temas
Utiliza esta tabla para reforzar áreas específicas donde te sientas débil antes del examen.

Tema Clave                   Room Recomendada (Free) 

**SMB / Windows**            Blue 
**WordPress**                Blog 
**Drupal**                   Overpass 
**FTP Anon**                 Kenobi
**Command Injection**        DVWA 
**Pivoting**                 Internal
**Linux PrivEsc**            Vulnversity
**Meterpreter**              Metasploit

### 🎯 La Ruta Óptima (Time-Crunch)
Si tienes poco tiempo y necesitas cubrir el 80% del examen con el mínimo esfuerzo, completa estas 7 salas en orden:

1.  **Network Services** (Bases de enumeración)
2.  **Blue** (Dominio de Windows/SMB)
3.  **Blog** (Ataques a WordPress)
4.  **Overpass** (Manejo de Drupal y web)
5.  **Kenobi** (Samba/NFS y Linux)
6.  **Vulnversity** (Fuzzing y PrivEsc)
7.  **Internal** (Pivoting y Redes)

> **Conclusión Profesional:**
> Esta ruta no solo te prepara para aprobar el eJPT, sino que construye una metodología sólida de pentesting. La clave del éxito en el examen no es memorizar herramientas, sino entender el flujo: **Enumerar > Identificar Vector > Explotar > Post-Explotación > Pivotar**.

## *¡Mucha suerte en tu certificación! Mantén la calma, enumera todo dos veces y "Try Harder".*

