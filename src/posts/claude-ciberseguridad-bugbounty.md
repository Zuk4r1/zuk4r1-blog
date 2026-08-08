---
title: "Uso de Claude en ciberseguridad: configuración y skills"
description: "Guía práctica para integrar y configurar Claude en tareas de ciberseguridad defensiva, y los skills más útiles."
date: 2026-08-08
tags:

- ciberseguridad
- IA
- Claude
---

# Uso de Claude en ciberseguridad y Bug Bounty

Claude puede convertirse en un excelente copiloto para **pentesting autorizado, Bug Bounty, análisis de código, reconocimiento, validación de hallazgos y elaboración de reportes**.

La clave no está solamente en utilizar el modelo, sino en darle un contexto de trabajo consistente mediante crea dos archivos en mayusculas los cuales son `CLAUDE.md`, mantener una bitácora con `PROGRESO.md` y añadir Skills especializadas.

> **Importante:** esta configuración debe utilizarse únicamente en activos propios, laboratorios, CTFs o programas de Bug Bounty en los que exista autorización y el objetivo esté dentro del alcance permitido.

---

## 1. ¿Por qué utilizar Claude para Bug Bounty?

Durante una investigación se acumula una gran cantidad de información:

- Subdominios.
- Endpoints.
- Requests y responses.
- Archivos JavaScript.
- Tecnologías.
- Parámetros.
- Flujos de autenticación.
- Posibles problemas de autorización.
- Hallazgos descartados.
- Evidencias.
- Hipótesis pendientes de validar.

Un LLM puede ayudar a conectar toda esta información y convertirla en una metodología de trabajo más organizada.

Claude puede utilizarse como apoyo para:

- Analizar JavaScript.
- Revisar APIs.
- Analizar mecanismos de autenticación.
- Revisar controles de autorización.
- Identificar posibles problemas de lógica de negocio.
- Analizar configuraciones.
- Revisar evidencias.
- Crear scripts auxiliares para entornos autorizados.
- Organizar la investigación.
- Preparar reportes técnicos.

La validación final, especialmente cuando se trata de una vulnerabilidad, debe realizarse de forma controlada.

---

# 2. Iniciar Claude Code

Una vez instalado Claude Code, una forma habitual de iniciar una sesión es:

```bash
claude
```

Para iniciar Claude omitiendo las solicitudes interactivas de permisos se puede utilizar:

```bash
claude --dangerously-skip-permissions
```

### ⚠️ Advertencia

`--dangerously-skip-permissions` reduce las barreras de confirmación y permite que Claude ejecute acciones con mucha mayor autonomía.

Por ello, **no es recomendable utilizarlo indiscriminadamente en el sistema principal**.

Lo ideal es utilizarlo dentro de un entorno de laboratorio, una VM, un contenedor o un directorio de trabajo específicamente preparado para la auditoría.

---

# 3. Continuar una sesión anterior

Si se quiere continuar una sesión existente:

```bash
claude --dangerously-skip-permissions --continue
```

Esto resulta especialmente útil cuando una investigación se divide en varias sesiones.

Por ejemplo:

```text
Día 1
Reconocimiento
       ↓
Día 2
Análisis de endpoints
       ↓
Día 3
Validación
       ↓
Día 4
Reporting
```

El archivo `progreso.md` complementa este mecanismo porque permite mantener explícitamente el estado de la investigación.

---

# 4. Crear el directorio de trabajo

Una estructura recomendable para una auditoría es:

```text
bugbounty/
└── objetivo/
    ├── CLAUDE.md
    ├── progreso.md
    │
    ├── .claude/
    │   └── skills/
    │
    ├── recon/
    ├── requests/
    ├── responses/
    ├── js/
    ├── scripts/
    ├── evidencias/
    └── reportes/
```

Podemos crearla rápidamente:

```bash
mkdir -p bugbounty/objetivo/{recon,requests,responses,js,scripts,evidencias,reportes}

cd bugbounty/objetivo

touch CLAUDE.md
touch progreso.md
```

---

# 5. El archivo `CLAUDE.md`

`CLAUDE.md` es uno de los elementos más importantes de la configuración.

Aquí podemos definir el contexto de la auditoría, metodología, reglas, objetivo y comportamiento esperado del agente.

Una configuración orientada a Bug Bounty puede ser mucho más específica que un simple prompt.

## Ejemplo de `CLAUDE.md`

```markdown
# CLAUDE.md

## Rol

Actúa como un Bug Bounty Hunter profesional y analista de seguridad
especializado en aplicaciones web, APIs, autenticación, autorización,
JavaScript y lógica de negocio.

Tu función es ayudar a investigar vulnerabilidades dentro de objetivos
autorizados y respetar estrictamente el alcance definido por el programa.

---

## Objetivo de la auditoría

Objetivo:

[DOMINIO / APLICACIÓN]

Alcance:

[INDICAR AQUÍ EL SCOPE DEL PROGRAMA]

Fuera de alcance:

[INDICAR ACTIVOS, ENDPOINTS O ACCIONES EXCLUIDAS]

---

## Comportamiento

Debes actuar como un Bug Bounty Hunter profesional:

1. Analiza primero la superficie de ataque.
2. Identifica tecnologías y componentes.
3. Prioriza los activos de mayor interés.
4. Formula hipótesis de vulnerabilidad.
5. Propón pruebas controladas.
6. Valida las hipótesis antes de clasificarlas como vulnerabilidades.
7. Registra las evidencias.
8. Evita conclusiones basadas únicamente en anomalías.
9. Mantén una separación clara entre observación, hipótesis,
   validación y hallazgo confirmado.
10. Actualiza progreso.md durante la investigación.

---

## Áreas prioritarias

Buscar y analizar, cuando estén dentro del alcance:

### Reconocimiento

- Subdominios.
- Hosts activos.
- Tecnologías.
- Endpoints.
- APIs.
- JavaScript.
- Parámetros.
- Archivos expuestos.

### Web

- XSS.
- SQL Injection.
- SSRF.
- LFI.
- SSTI.
- XXE.
- CSRF.
- CORS.
- Open Redirect.
- Host Header Injection.
- HTTP Request Smuggling.
- Cache Poisoning.

### Autenticación

- Authentication bypass.
- Session management.
- OAuth.
- JWT.
- SSO.
- MFA.
- Account takeover.

### Autorización

- IDOR / BOLA.
- Privilege escalation.
- Broken Access Control.
- Missing authorization.
- Insecure direct object references.
- Diferencias de permisos entre roles.

### APIs

- REST.
- GraphQL.
- WebSockets.
- gRPC.
- API authorization.
- Mass assignment.
- Excessive data exposure.
- Rate limiting.

### Lógica de negocio

- Manipulación de cantidades.
- Cupones.
- Precios.
- Estados.
- Flujos de pago.
- Race conditions.
- Validaciones inconsistentes.
- Bypass de restricciones.

### Client-side

- JavaScript.
- DOM XSS.
- Secrets expuestos.
- Endpoints ocultos.
- Feature flags.
- Información sensible.
- Source maps.

---

## Metodología

Utilizar el siguiente ciclo:

RECON
  ↓
MAPEAR SUPERFICIE
  ↓
PRIORIZAR
  ↓
FORMULAR HIPÓTESIS
  ↓
VALIDAR
  ↓
DOCUMENTAR
  ↓
REPORTAR

No considerar una vulnerabilidad confirmada hasta disponer de evidencia
suficiente.

---

## Herramientas

Cuando sea apropiado y esté permitido por el alcance, se puede trabajar
con herramientas como:

- Burp Suite
- Nmap
- httpx
- subfinder
- amass
- katana
- ffuf
- nuclei
- dalfox
- dnsx
- gau
- arjun
- LinkFinder
- JSluice
- SecretFinder

Las herramientas deben utilizarse respetando el scope y las reglas del
programa.

---

## Evidencias

Cada posible hallazgo debe registrar:

- Endpoint.
- Método HTTP.
- Parámetros.
- Request.
- Response.
- Usuario/rol utilizado.
- Condiciones necesarias.
- Resultado esperado.
- Resultado observado.
- Impacto.
- Reproducción.
- Evidencia.

---

## Clasificación de hallazgos

Utilizar:

- Observación
- Hipótesis
- Pendiente de validación
- Validado
- Falso positivo
- Reportable

No confundir una posibilidad con una vulnerabilidad demostrada.

---

## Reporting

Cuando un hallazgo esté validado, preparar:

# Título

## Resumen

## Severidad

## CWE

## Activo afectado

## Endpoint

## Pasos de reproducción

## Evidencia

## Impacto

## Remediación

## Referencias

---

## Reglas de seguridad

- Trabajar únicamente sobre objetivos autorizados.
- Respetar el scope.
- No realizar DoS.
- No destruir información.
- No modificar datos de terceros.
- No acceder innecesariamente a información sensible.
- Utilizar cuentas de prueba cuando sea posible.
- Minimizar el impacto de las pruebas.
- Mantener evidencia suficiente para reproducir el hallazgo.

---

## Progreso

Leer `progreso.md` antes de comenzar una nueva fase.

Actualizar `progreso.md` después de descubrimientos importantes.

Nunca asumir que una prueba ya fue realizada si no existe evidencia
registrada.
```

Esta configuración hace que Claude tenga una orientación mucho más clara que simplemente decirle:

> "Busca vulnerabilidades".

---

# 6. El archivo `progreso.md`

El segundo archivo importante es:

```text
progreso.md
```

Su función es mantener una bitácora de la auditoría.

Ejemplo:

```markdown
# Progreso de auditoría

## Objetivo

https://objetivo.example

## Estado

- [x] Reconocimiento
- [x] Subdominios
- [x] Hosts activos
- [x] Enumeración de endpoints
- [x] Análisis JavaScript
- [ ] Autenticación
- [ ] Autorización
- [ ] API
- [ ] Lógica de negocio
- [ ] Validación
- [ ] Reporting

---

## Hallazgos potenciales

### H-001

Tipo:

Broken Access Control

Endpoint:

/api/users/{id}

Estado:

PENDIENTE DE VALIDACIÓN

Hipótesis:

Comprobar si un usuario puede acceder a recursos pertenecientes
a otro usuario.

---

## Descartados

### H-002

Open Redirect

Resultado:

Falso positivo.

Motivo:

El servidor valida correctamente el destino.

---

## Próximos pasos

1. Crear dos cuentas de prueba.
2. Comparar permisos.
3. Revisar endpoints relacionados.
4. Validar controles server-side.
```

Esto permite que cada sesión tenga continuidad.

---

# 7. Instalar Claude-BugHunter

Una de las piezas más interesantes para ampliar Claude en Bug Bounty es el proyecto **Claude-BugHunter** de `elementalsouls`.

El repositorio incluye un conjunto de Skills orientadas a bug hunting, red team externo, recon, aplicaciones web, APIs, autenticación, autorización, reporting y otras áreas.

El repositorio indica actualmente **82 Skills y 15 slash commands**. fileciteturn1file0

Repositorio:

urlClaude-BugHunter en GitHubhttps://github.com/elementalsouls/Claude-BugHunter.git

---

# 8. Instalación mediante Git

Una opción es clonar el repositorio:

```bash
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
```

Después, en Linux/macOS:

```bash
bash scripts/install.sh
```

En Windows PowerShell:

```powershell
pwsh ./scripts/install.ps1
```

El proyecto documenta que esta modalidad copia las Skills y comandos a:

```text
~/.claude/
```

En Windows:

```text
%USERPROFILE%\.claude\
```

Por lo tanto, una vez instalado podemos encontrar las Skills dentro de la estructura de Claude:

```text
~/.claude/
├── skills/
└── commands/
```

El repositorio también documenta una instalación como plugin:

```text
/plugin marketplace add elementalsouls/Claude-BugHunter
/plugin install claude-bughunter@elementalsouls
```

La instalación como plugin mantiene las Skills bajo el namespace:

```text
claude-bughunter:
```

fileciteturn1file0

---

# 9. Instalar las Skills para Bug Bounty

Para disponer del conjunto de Skills del proyecto:

```bash
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
```

Después:

```bash
bash scripts/install.sh
```

La estructura resultante dependerá del método de instalación, pero conceptualmente tendremos:

```text
~/.claude/
│
├── skills/
│   ├── recon/
│   ├── web/
│   ├── api/
│   ├── authentication/
│   ├── authorization/
│   ├── business-logic/
│   ├── javascript/
│   └── reporting/
│
└── commands/
```

El proyecto documenta categorías que incluyen web application hunting, autenticación e identidad, APIs, infraestructura, concurrencia, recon/OSINT y reporting. fileciteturn1file0

---

# 10. ¿Qué aportan las Skills?

La diferencia entre utilizar Claude sin Skills y utilizar un conjunto especializado puede representarse así:

```text
Claude básico

Prompt
  ↓
Respuesta
```

Mientras que un entorno con Skills puede funcionar conceptualmente como:

```text
                    CLAUDE.md
                       │
                       ▼
                 Contexto del objetivo
                       │
                       ▼
                    Claude
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        Recon        Web/API     Reporting
          │            │            │
          └────────────┼────────────┘
                       ▼
                  Investigación
```

Las Skills proporcionan conocimiento y procedimientos especializados que pueden cargarse según el tema de la investigación.

---

# 11. Configurar el modelo al iniciar una auditoría

Al comenzar una investigación se puede seleccionar el modelo desde Claude Code.

En el flujo solicitado para este entorno:

```text
/model
```

y seleccionar:

```text
Sonnet 5
```

También es recomendable definir el contexto del objetivo antes de empezar:

```text
Objetivo:
https://objetivo.example

Scope:
*.objetivo.example

Tipo:
Bug Bounty autorizado

Prioridad:
Web + API + Auth + Authorization + Business Logic
```

> **Nota:** los nombres y alias de modelos disponibles pueden cambiar según la versión de Claude Code y la cuenta utilizada. Si `Sonnet 5` no aparece en `/model`, debe utilizarse el modelo que Claude Code muestre actualmente como disponible.

---

# 12. Flujo completo recomendado

Una configuración práctica quedaría:

```text
                    Claude Code
                         │
                         ▼
                    CLAUDE.md
                         │
                         ▼
                   Scope + Rol
                         │
                         ▼
                  Claude-BugHunter
                         │
       ┌─────────────────┼─────────────────┐
       ▼                 ▼                 ▼
     Recon             Web/API          Reporting
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ▼
                   progreso.md
                         │
                         ▼
                     Evidencias
                         │
                         ▼
                  Hallazgo validado
                         │
                         ▼
                      Reporte
```

---

# 13. Estructura final del proyecto

Después de configurar todo, una estructura bastante completa puede ser:

```text
objetivo/
│
├── CLAUDE.md
├── progreso.md
│
├── .claude/
│   └── skills/
│       ├── recon/
│       ├── web/
│       ├── api/
│       ├── authentication/
│       ├── authorization/
│       ├── business-logic/
│       ├── javascript/
│       └── reporting/
│
├── recon/
│   ├── subdomains.txt
│   ├── hosts.txt
│   └── urls.txt
│
├── requests/
│
├── responses/
│
├── js/
│
├── scripts/
│
├── evidencias/
│
└── reportes/
```

Mientras tanto, las Skills globales instaladas mediante Claude-BugHunter pueden encontrarse en:

```text
~/.claude/skills/
```

y los comandos en:

```text
~/.claude/commands/
```

---

# 14. Claude como Bug Bounty Hunter profesional

Una de las partes más importantes es el contenido de `CLAUDE.md`.

No basta con decir:

```text
Busca vulnerabilidades.
```

Es mucho mejor definir:

```text
Actúa como un Bug Bounty Hunter profesional.

Analiza únicamente el objetivo autorizado indicado en el scope.

Realiza una investigación sistemática comenzando por reconocimiento
y enumeración de superficie.

Prioriza vulnerabilidades con impacto real.

Analiza:

- autenticación
- autorización
- IDOR/BOLA
- APIs
- OAuth
- JWT
- XSS
- SSRF
- SQLi
- CORS
- CSRF
- file upload
- lógica de negocio
- race conditions
- exposición de información
- JavaScript
- source maps
- secretos
- configuraciones inseguras

Para cada posible vulnerabilidad:

1. Explica la hipótesis.
2. Identifica el endpoint afectado.
3. Define las condiciones necesarias.
4. Propón una prueba controlada.
5. Analiza el resultado.
6. Determina si está realmente validada.
7. Estima el impacto.
8. Asigna CWE cuando corresponda.
9. Guarda la evidencia.
10. Prepara un reporte si el hallazgo es válido.

No clasifiques como vulnerabilidad algo que no haya sido demostrado.

Mantén siempre el trabajo dentro del scope autorizado.
```

Esto cambia completamente la calidad del contexto proporcionado al modelo.

---

# 15. Una metodología más importante que el propio modelo

La IA no reemplaza la metodología del investigador.

Un buen flujo es:

```text
RECON
  ↓
ENUMERACIÓN
  ↓
MAPEO
  ↓
PRIORIZACIÓN
  ↓
HIPÓTESIS
  ↓
PRUEBA
  ↓
VALIDACIÓN
  ↓
IMPACTO
  ↓
EVIDENCIA
  ↓
REPORTE
```

Y no:

```text
Claude → "encontré una vulnerabilidad" → Reportar
```

La diferencia es fundamental.

Claude puede ayudar a generar hipótesis, pero el investigador debe comprobarlas.

---

# 16. Configuración mínima recomendada

Si se quiere comenzar rápidamente:

```bash
mkdir -p ~/bugbounty/objetivo
cd ~/bugbounty/objetivo

touch CLAUDE.md
touch progreso.md

mkdir -p .claude/skills
```

Después instalar Claude-BugHunter:

```bash
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
bash scripts/install.sh
```

Y comenzar Claude desde el directorio de trabajo:

```bash
cd ~/bugbounty/objetivo

claude --dangerously-skip-permissions
```

Para continuar posteriormente:

```bash
claude --dangerously-skip-permissions --continue
```

---

# 17. Conclusión

La combinación:

```text
Claude Code
     +
CLAUDE.md
     +
progreso.md
     +
Claude-BugHunter Skills
     +
Burp Suite
     +
herramientas de recon
     +
evidencias
```

permite construir un entorno de trabajo mucho más organizado para Bug Bounty y pentesting autorizado.

La parte más importante es `CLAUDE.md`, porque ahí se define **qué debe hacer Claude, cuál es el objetivo, cuál es el scope, qué metodología debe seguir y cómo debe documentar los resultados**.

`progreso.md` mantiene el estado de la investigación, mientras que las Skills especializadas amplían las capacidades de Claude para diferentes fases del proceso.

Finalmente, aunque Claude pueda comportarse como un copiloto de investigación muy potente, **la validación técnica y la decisión de reportar un hallazgo siguen siendo responsabilidad del investigador**.
