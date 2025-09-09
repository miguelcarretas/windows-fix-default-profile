# windows-fix-default-profile
# Guía de funcionamiento — `Fix-DefaultProfile.ps1 (v1.5)`

## Objetivo

Reparar perfiles nuevos que no se crean bien (menú **Inicio** “en blanco”, shell que no carga, etc.) en **Windows Server 2019** tras clonar/plantillar una máquina.

El script:

1. **Repone** `C:\Users\Default` desde el **DVD** (install.wim/esd) de Server 2019.
2. **Normaliza ACLs** del perfil por defecto.
3. **Asegura servicios** clave del shell/perfiles.
4. **Repara la imagen** con **DISM/SFC** usando siempre el **DVD** como origen y, si no basta, **bypassea WSUS** temporalmente para usar **Windows Update**.
5. **Re-registra** los componentes del shell (solo los presentes en 2019).
6. **Verifica** puntos críticos y, opcionalmente, **crea un usuario de prueba**.

> **Mi opinión (basada en campo):** con `Default` limpio + ACLs canónicas + DISM/SFC desde fuente válida, el Inicio vuelve en **>80%** de casos en WS2019. Si no, el reseteo de **StateRepository** en Modo Seguro eleva la tasa de éxito a **>90%**.

---

## Requisitos

* Ejecutar **como Administrador** (el script lo comprueba).
* Medio **DVD** montado con `\sources\install.wim` o `install.esd`.
* Mantener la consola abierta (se habilita **Transcript**).
* Idempotencia: `C:\Users\Default` existente se respalda como `Default.BAD.<timestamp>`.

---

## Flujo del script (pantalla a pantalla)

### Paso 0 — Limpieza de montajes DISM

* Ejecuta `dism /Cleanup-Mountpoints`.

**Por qué:** evita errores tipo *0xc1420114* (“directorio de montaje no vacío”).

---

### Paso 1 — Detección del DVD y del origen

* Localiza la unidad `DriveType=5` y busca `install.wim/esd` en `X:\sources`.

**Errores manejados:** falla controladamente si no hay DVD o no existe WIM/ESD.

---

### Paso 2 — Selección de edición (índice)

* Intenta `Get-WindowsImage`.
* *Fallback:* parsea `dism /Get-ImageInfo /English`.
* Criterio: **Standard + Desktop Experience/Experiencia**; si no, el primero.

**Resultado típico:** `Index = 2` (WS2019 Standard Desktop).

---

### Paso 3 — Obtener `Default` y fuente DISM desde el DVD

* Crea **carpeta temporal única** para montar.
* **Plan A:** `dism /Mount-Image /ReadOnly` → usa `...\Windows` como **/Source** y copia `...\Users\Default`.
* **Plan B:** `dism /Apply-Image` a una carpeta temporal si el montaje falla.

**Ventaja:** no modifica el WIM; solo lectura o extracción.

---

### Paso 4 — Reemplazo de `C:\Users\Default`

* Si existe: `takeown` + `icacls` → renombra a `Default.BAD.<timestamp>`.
* Copia **en modo backup** con `robocopy /B` desde el `Default` del DVD.

**Por qué:** asegura `NTUSER.DAT`, carpetas, accesos directos y estructura *limpia*.

---

### Paso 5 — ACLs canónicas en `Default`

* Habilita herencia, **reset** de ACLs y concede por **SID** (independiente del idioma):

  * `*S-1-5-18` → **SYSTEM (F)**
  * `*S-1-5-32-544` → **Administrators (F)**
  * `*S-1-5-32-545` → **Users (RX)**

> **Esperado:** “**Acceso denegado**” en:
>
> * `...\AppData\Local\Microsoft\WindowsApps`
> * `...\Start Menu\Programs\Windows PowerShell`
>
> Son rutas protegidas y **no afectan** al éxito.

---

### Paso 6 — Servicios del shell/perfiles

* Verifica/ajusta **Automático** y arranca si es necesario:

  * `StateRepository` (BD AppX)
  * `AppReadiness`
  * `ProfSvc` (User Profile Service)

**Por qué:** prerrequisito para componer Inicio y perfilar usuarios.

---

### Paso 7 — Reparación de imagen (DISM/SFC)

* **Plan A (preferido):** DISM con fuente **DVD montado**

  ```powershell
  dism /Online /Cleanup-Image /RestoreHealth /Source:"<Mount>\Windows;<Mount>\Windows\WinSxS" /LimitAccess
  ```

  > Ojo: las **comillas** son necesarias por el `;` en PowerShell.

* **Plan B (si falla A con 0x800f0954/0x800f081f):** **bypass WSUS** temporal (`UseWUServer=0`), reinicia `wuauserv`, ejecuta `DISM /RestoreHealth` y **restaura** la clave.

* Ejecuta `sfc /scannow`.

**Por qué:** corrige corrupción de componentes que afecta a AppX/Start.

---

### Paso 8 — Re-registro del shell disponible

* Enumera `C:\Windows\SystemApps\Microsoft.Windows.*ExperienceHost*`.
* Registra cada `AppxManifest.xml` encontrado con `Add-AppxPackage`.

> En **WS2019 (17763/1809)** **no** existe `StartMenuExperienceHost` separado; el crítico es **ShellExperienceHost**.
> `0x80073CF6` con interno `0x800705AA` suele ser **locks/recursos/paginación**; tras DISM/SFC y servicios OK, normalmente cede.

---

### Paso 9 — Verificaciones

* `NTUSER.DAT` presente (tamaño razonable).
* ACLs actuales del `Default`.
* **Políticas de Start Layout** (HKCU/HKLM): `StartLayoutFile` / `LockedStartLayout`.
* Paquetes **aprovisionados** (Provisioned) y **instalados** (AllUsers) del shell.
* Eventos **1508/1509/1511/1515/1530** de *User Profile Service* (últimos 20).

---

### Paso 10 — Limpieza

* **Desmonta** el WIM (o limpia la extracción) y borra temporales.
* Cierra **Transcript** y muestra la ruta del log.

---

## Qué **no** hace (y cuándo añadirlo)

* **No** automatiza el reseteo del **StateRepository** (BD AppX) en **Modo Seguro**.

  * Úsalo si, tras el script, un **usuario virgen** aún no abre Inicio.
  * Procedimiento aparte (ver más abajo) — en WS2019 resuelve **>90%** de casos rebeldes cuando ya has limpiado `Default` y sanado la imagen.

---

## Cómo ejecutarlo

```powershell
PowerShell -ExecutionPolicy Bypass -File "C:\Users\YOUR_USER_HERE\Desktop\Fix-DefaultProfile.ps1"

# Opcional: que cree automáticamente un usuario de prueba
PowerShell -ExecutionPolicy Bypass -File "C:\Users\YOUR_USER_HERE\Desktop\Fix-DefaultProfile.ps1" -CreateTestUser
```

---

## Señales claras de éxito

* `C:\Users\Default` con `NTUSER.DAT` (> \~256 KB) y estructura típica.
* ACLs muestran **SYSTEM (F)**, **Administrators (F)**, **Users (RX)**.
* `DISM /RestoreHealth` finaliza sin error (DVD o fallback WU).
* `Get-AppxPackage -AllUsers -Name Microsoft.Windows.ShellExperienceHost` → **Status: Ok** y `InstallLocation` en `C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy`.
* Un **usuario nuevo** inicia sesión, **se crea el perfil** y el **Inicio** funciona.

---

## Dónde mirar si algo no cuadra

* **Transcript del script:** `C:\Temp\FixDefaultProfile-YYYYMMDD-HHMMSS.log`
* **DISM:** `C:\Windows\Logs\DISM\dism.log`
* **SFC/CBS:** `C:\Windows\Logs\CBS\CBS.log`
* **User Profile Service:** eventos **1508/1509/1511/1515/1530** (Registro **Aplicación**).
* **RDP/LSM:** *LocalSessionManager/Operational* y *RemoteConnectionManager/Operational* si la sesión queda en “Esperando a Configuración de Escritorio remoto”.

---

## Apéndice — Reset de **StateRepository** (Modo Seguro)

> Úsalo solo si, tras el script, un **usuario virgen** aún no abre **Inicio**.

### A) Entrar en Modo Seguro (mínimo)

```cmd
bcdedit /set {current} safeboot minimal
shutdown /r /t 0
```

### B) En Modo Seguro (PowerShell **elevado**)

```powershell
$ErrorActionPreference = 'Stop'
'StateRepository','AppXSVC','ClipSVC','AppReadiness' | % { try { Stop-Service $_ -Force -ErrorAction SilentlyContinue } catch {} }

$repo = 'C:\ProgramData\Microsoft\Windows\AppRepository'
cmd /c "takeown /F `"$repo`" /R /A /D S" | Out-Null
icacls $repo /grant "*S-1-5-32-544:(OI)(CI)(F)" /T | Out-Null

$stamp = Get-Date -f 'yyyyMMdd-HHmmss'
$bak   = Join-Path $repo ("Backup_$stamp")
New-Item $bak -ItemType Directory -Force | Out-Null
robocopy $repo $bak /MIR /R:1 /W:1 | Out-Null

Get-ChildItem $repo -Filter 'StateRepository*' -File | % { Rename-Item $_.FullName ($_.Name + '.old') }
```

### C) Salir de Modo Seguro

```cmd
bcdedit /deletevalue {current} safeboot
shutdown /r /t 0
```

### D) Remate en modo normal

```powershell
# DVD como fuente para DISM
$dvd = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=5" | Select-Object -First 1).DeviceID
$src = @("$dvd\sources\install.wim","$dvd\sources\install.esd") | ? { Test-Path $_ } | Select-Object -First 1
$idx = 2
$mnt = Join-Path $env:TEMP ("WIM_{0}" -f (Get-Date -f 'yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $mnt | Out-Null
dism /Mount-Image /ImageFile:$src /Index:$idx /MountDir:$mnt /ReadOnly
dism /Online /Cleanup-Image /RestoreHealth /Source:"$mnt\Windows;$mnt\Windows\WinSxS" /LimitAccess
dism /Unmount-Image /MountDir:$mnt /Discard
Remove-Item $mnt -Recurse -Force -ErrorAction SilentlyContinue
sfc /scannow

# Re-registro del shell (solo lo presente) y servicios
$sys = Join-Path $env:windir 'SystemApps'
Get-ChildItem $sys -Directory | ? { $_.Name -like 'Microsoft.Windows.*ExperienceHost*' } |
  % { $m = Join-Path $_.FullName 'AppxManifest.xml'; if (Test-Path $m) { try { Add-AppxPackage -DisableDevelopmentMode -Register $m } catch {} } }
Start-Service StateRepository,AppReadiness -ErrorAction SilentlyContinue
```

---


User Profile Service: Eventos 1508/1509/1511/1515/1530 (Registro Aplicación).

RDP/LSM: LocalSessionManager/Operational y RemoteConnectionManager/Operational si la sesión se queda en “Esperando a Configuración de Escritorio remoto”.

## PASOS EXTRAS

Además, se ha utilizado esta herramienta para limpiar valores de la siguiente clave del registro de Windows (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications):
https://github.com/Lazy-256/clnotifications 

** También está la carpeta "clnotifications-master" en la raíz de mi proyecto, por lo que al descargar este proyecto, se te descargará también dicha herramienta. **

Descargar el proyecto (https://github.com/Lazy-256/clnotifications/archive/refs/heads/master.zip) y copiar el .ZIP a la máquina a arreglar.

Descomprimir el ZIP y la carpeta "clnotifications.zip" > entrar a la carpeta clnotifications y lanzar un "cmd.exe" desde la barra superior del explorador de Windows donde estamos.

Ahora, ejecutar:

```powershell
.\clnotifications.exe -cleanup
```

### Comprobaciones finales
- Reiniciar la máquina por completo y esperar (el proceso puede ser bastante lento).
- Crear un usuario virgen y verificar que el menú de Inicio se abre correctamente.
- Chequear que también funciona para usuarios existentes previamente creados.
