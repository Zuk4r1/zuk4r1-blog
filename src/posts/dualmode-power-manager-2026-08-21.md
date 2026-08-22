---
title: "DualMode: administra la energía de tu portátil durante un pentest"
description: "Conoce DualMode, un conjunto de scripts de PowerShell para alternar entre rendimiento, ahorro y restauración en Windows, con casos de uso prácticos para bug bounty."
author: "Zuk4r1"
date: "2026-08-21"
published: true
tags: ["windows", "powershell", "pentesting", "bug bounty", "productividad", "virtualización"]
readTime: "10 min"
---

# DualMode: energía bajo control para pentesting y bug bounty

Cuando trabajas en **bug bounty**, una parte importante del tiempo se invierte fuera del navegador: levantando una máquina virtual con Kali Linux, ejecutando proxies, navegadores, herramientas de reconocimiento y varias terminales al mismo tiempo. Todo ese flujo puede consumir muchos recursos, especialmente en un portátil.

**DualMode** es un pequeño administrador de energía para Windows que permite cambiar rápidamente entre tres configuraciones: rendimiento para auditorías intensivas, ahorro para el trabajo diario y restauración para volver a los valores predeterminados de Windows.

No es una herramienta de explotación ni descubre vulnerabilidades por sí misma. Su utilidad está en preparar el equipo para que el entorno de trabajo sea más estable, predecible y cómodo.

## ¿Qué es DualMode?

El proyecto concentra la lógica en un único script de PowerShell, `DualMode.ps1`. Tres lanzadores `.bat` invocan ese motor con el modo correspondiente:

```text
pentest.bat    -> DualMode.ps1 -Mode Pentest
ahorro.bat     -> DualMode.ps1 -Mode Ahorro
restaurar.bat  -> DualMode.ps1 -Mode Restaurar
```

Los archivos deben permanecer juntos en la misma carpeta. Al abrir uno de los lanzadores, el script solicita permisos elevados mediante UAC cuando los necesita.

## Los tres modos

### Modo Pentest

Está pensado para sesiones en las que la prioridad es que la máquina virtual y las herramientas mantengan el máximo rendimiento posible.

- CPU limitada al 100 % tanto con batería como conectado a corriente.
- Suspensión automática desactivada.
- La pantalla se apaga después de 20 minutos.
- Activación del plan de alto rendimiento.

Esto resulta útil cuando estás ejecutando una VM de Kali con Burp Suite, un navegador con muchas pestañas, herramientas de reconocimiento y una terminal de apoyo. La suspensión desactivada evita que una auditoría larga se interrumpa porque el equipo entró en reposo.

El script no fuerza el uso de una GPU ni modifica la BIOS, el firmware o la configuración de aceleración de la máquina virtual. El rendimiento real seguirá dependiendo del hardware, del hipervisor y de la carga de trabajo.

### Modo Ahorro

Está orientado al uso diario y a las fases de análisis que no requieren tener todos los recursos disponibles.

- CPU limitada al 70 % cuando el equipo funciona con batería.
- CPU al 100 % cuando está conectado a corriente.
- Pantalla apagada después de 5 minutos en batería y 15 minutos con corriente.
- Suspensión después de 10 minutos en batería y 30 minutos con corriente.
- Suspensión selectiva de USB activada.
- Apagado del disco después de 3 minutos en batería y 20 minutos con corriente si se detecta un HDD mecánico.

La gestión del disco se omite en SSD y NVMe, donde esa opción no aporta el mismo beneficio y puede provocar activaciones innecesarias. Así, el modo se adapta mejor al tipo de almacenamiento del equipo.

### Modo Restaurar

Este modo restaura los planes integrados de Windows, como **Equilibrado**, **Alto rendimiento** y **Economizador**, a sus valores de fábrica.

Es útil para deshacer los cambios de DualMode antes de devolver un portátil a un uso normal o cuando quieres empezar de nuevo con la configuración energética. Ten presente que también elimina personalizaciones manuales que hubieras hecho sobre esos planes.

## ¿Cómo puede ayudar en bug bounty?

DualMode no sustituye un proceso de investigación ni una metodología de seguridad. Su aporte está en reducir fricciones del entorno local.

### 1. Preparar una sesión de reconocimiento

Antes de iniciar una sesión autorizada, puedes activar **Modo Pentest** y levantar tu VM con las herramientas necesarias. Al no suspenderse el sistema, los procesos largos no se detendrán si te alejas unos minutos del equipo.

En esta fase conviene trabajar siempre dentro del alcance definido por el programa. La configuración de energía mejora la disponibilidad del equipo, pero no cambia qué objetivos están autorizados.

### 2. Mantener un laboratorio con varias herramientas

Una investigación de bug bounty suele combinar navegador, proxy local, editor, documentación y una o más terminales. Si además usas una VM, el consumo de CPU y RAM aumenta rápidamente.

El plan de alto rendimiento puede ser útil durante pruebas activas y reproducción de comportamientos. Cuando solo estás leyendo respuestas, redactando un informe o esperando una tarea autorizada, puedes volver a **Modo Ahorro** para evitar consumo innecesario.

### 3. Evitar interrupciones durante pruebas largas

Algunas tareas legítimas, como preparar un entorno, ejecutar una comprobación autorizada o dejar un proceso de análisis local, pueden tardar bastante. La suspensión automática puede cortar la conexión de la VM o dejar la sesión en un estado inesperado.

El modo Pentest mantiene el equipo despierto, pero la pantalla sigue apagándose después de 20 minutos. Esto ofrece un equilibrio razonable entre continuidad y consumo, especialmente cuando el portátil está conectado a corriente.

### 4. Separar trabajo intensivo y uso cotidiano

Cambiar manualmente varios parámetros cada vez es fácil de olvidar. Los lanzadores convierten esa transición en una acción clara:

```text
Inicio de sesión de bug bounty -> Pentest
Lectura, documentación o pausa -> Ahorro
Fin del laboratorio              -> Restaurar
```

La ventaja principal es la consistencia. El equipo queda en un estado conocido y no dependes de recordar qué límite de CPU o temporizador modificaste anteriormente.

## Instalación y uso

1. Descarga `DualMode.ps1`, `pentest.bat`, `ahorro.bat` y `restaurar.bat`.
2. Coloca los cuatro archivos en la misma carpeta.
3. Haz doble clic en el lanzador del modo que quieras activar.
4. Acepta la solicitud de UAC si aparece.

Los lanzadores utilizan PowerShell con `-NoProfile` y `-ExecutionPolicy Bypass` para poder ejecutar el motor sin depender de la política de ejecución configurada para el usuario. En equipos corporativos, una directiva de grupo puede impedirlo igualmente.

También puedes ejecutarlo desde una consola de PowerShell como administrador:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\DualMode.ps1" -Mode Pentest
```

Sustituye `Pentest` por `Ahorro` o `Restaurar` según corresponda.

## Comprobación y registro

Cada ejecución comprueba el código de salida de los comandos `powercfg`. Si una operación falla, se muestra un mensaje de error en consola en lugar de continuar en silencio.

El registro se guarda en:

```text
%TEMP%\dualmode.log
```

Para verificar qué plan está activo puedes ejecutar:

```powershell
powercfg /getactivescheme
```

El log también ayuda a confirmar si el equipo detectó un HDD o si omitió correctamente el apagado del disco por tratarse de un SSD o NVMe.

## Buenas prácticas para usarlo en una auditoría

- Usa DualMode solo en equipos que administras o sobre los que tienes autorización.
- Define el alcance del programa de bug bounty antes de lanzar cualquier prueba.
- No confundas alto rendimiento con mayor velocidad de red o permisos adicionales.
- Vigila la temperatura del portátil durante sesiones intensivas y usa una superficie ventilada.
- Guarda los informes y evidencias con frecuencia; la configuración de energía no reemplaza una estrategia de respaldo.
- Ejecuta `restaurar.bat` cuando termines si prefieres dejar los planes de Windows en su estado original.

## Limitaciones importantes

DualMode modifica planes de energía del sistema. No optimiza automáticamente la asignación de RAM a la VM, no configura el hipervisor, no cambia el rendimiento de la GPU y no mejora una conexión de red.

Además, restaurar los planes integrados a sus valores de fábrica puede borrar ajustes personales. Si tienes una configuración energética propia, documenta sus valores o exporta el plan antes de utilizar el modo Restaurar.

## Conclusión

Para un bug bounty hunter que trabaja desde un portátil Windows, DualMode ofrece una automatización sencilla para cambiar de contexto: potencia cuando la VM y las herramientas lo necesitan, ahorro durante el análisis tranquilo y restauración al cerrar el laboratorio.

Su valor no está en atacar objetivos, sino en hacer más fiable el puesto de trabajo. Combinado con un alcance bien definido, una VM correctamente configurada y una metodología responsable, puede convertirse en una pequeña pieza útil del flujo diario de pentesting.