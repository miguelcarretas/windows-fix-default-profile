<# 
  Script Name : Fix-DefaultProfile.ps1 (v1.5)
  Author      : Miguel Carretas Perulero
  Date        : 09/09/2025
  Version     : v1.5
  Purpose     : Reponer C:\Users\Default desde el DVD (install.wim/esd),
                reparar imagen con DISM usando SIEMPRE el DVD como source (y
                fallback a WU desactivando WSUS temporalmente), re-registrar
                el shell y verificar que los perfiles nuevos creen Start OK.
#>

[CmdletBinding()]
param(
  [switch]$CreateTestUser = $false,
  [string]$TestUserName = "prueba",
  [string]$TestUserPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Start-MyTranscript {
  try {
    if (-not (Test-Path 'C:\Temp')) { New-Item -ItemType Directory -Path 'C:\Temp' | Out-Null }
    $Global:TranscriptPath = "C:\Temp\FixDefaultProfile-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
    Start-Transcript -Path $Global:TranscriptPath -Force | Out-Null
  } catch { Write-Warning ("No se pudo iniciar transcript: {0}" -f $_.Exception.Message) }
}
Start-MyTranscript

function Assert-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw "Este script debe ejecutarse como **Administrador**." }
}
Assert-Admin

function Invoke-DismRepairOffline {
  param([Parameter(Mandatory=$true)][string]$WindowsRoot)
  Write-Host "    DISM (offline) usando $WindowsRoot ..." -ForegroundColor Yellow
  dism /Online /Cleanup-Image /RestoreHealth /Source:"$WindowsRoot;$WindowsRoot\WinSxS" /LimitAccess
  return $LASTEXITCODE
}

function Invoke-DismRepairWithWUBypass {
  Write-Host "    DISM (fallback) usando Windows Update y bypass de WSUS temporal..." -ForegroundColor Yellow
  $auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  $old = $null
  try {
    if (Test-Path $auKey) { $old = (Get-ItemProperty -Path $auKey -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer }
    else { New-Item -Path $auKey -Force | Out-Null }
    New-ItemProperty -Path $auKey -Name UseWUServer -PropertyType DWord -Value 0 -Force | Out-Null
  } catch { Write-Warning ("No se pudo preparar el bypass de WSUS: {0}" -f $_.Exception.Message) }

  try { net stop wuauserv | Out-Null } catch {}
  try { net start wuauserv | Out-Null } catch {}

  dism /Online /Cleanup-Image /RestoreHealth
  $rc = $LASTEXITCODE

  # Restaurar WSUS a su estado anterior
  try {
    if ($null -eq $old) {
      Remove-ItemProperty -Path $auKey -Name UseWUServer -ErrorAction SilentlyContinue
    } else {
      Set-ItemProperty -Path $auKey -Name UseWUServer -Value $old -ErrorAction SilentlyContinue
    }
    net stop wuauserv | Out-Null
    net start wuauserv | Out-Null
  } catch {
    Write-Warning ("No se pudo restaurar la configuración de WSUS: {0}" -f $_.Exception.Message)
  }

  return $rc
}

Write-Host "==> Paso 0: limpiar montajes DISM..." -ForegroundColor Cyan
try { dism /Cleanup-Mountpoints | Out-Null } catch { }

Write-Host "==> Paso 1: detectar DVD y origen..." -ForegroundColor Cyan
$dvd = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=5" | Select-Object -First 1).DeviceID
if (-not $dvd) { throw "No se detectó unidad de DVD montada. Monta el medio e inténtalo de nuevo." }
$src = @("$dvd\sources\install.wim","$dvd\sources\install.esd") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $src) { throw ("No se encontró install.wim/esd en {0}\sources" -f $dvd) }
Write-Host ("    DVD: {0} | Origen: {1}" -f $dvd, $src)

Write-Host "==> Paso 2: elegir índice de la edición adecuada..." -ForegroundColor Cyan
$index = $null; $nameSel = $null
try {
  Import-Module Dism -ErrorAction SilentlyContinue | Out-Null
  $images = Get-WindowsImage -ImagePath $src -ErrorAction Stop
  if ($images) {
    $best = $images | Where-Object { $_.ImageName -match '(?i)Standard' -and ($_.ImageName -match '(?i)Desktop\s*Experience|Experiencia') } | Select-Object -First 1
    if (-not $best) { $best = $images | Where-Object { $_.ImageName -match '(?i)Desktop\s*Experience|Experiencia' } | Select-Object -First 1 }
    if (-not $best) { $best = $images | Select-Object -First 1 }
    $index = [int]$best.ImageIndex; $nameSel = $best.ImageName
  }
} catch { }
if (-not $index) {
  $dismInfo = (dism /Get-ImageInfo /ImageFile:$src /English) -join "`n"
  if ($LASTEXITCODE -ne 0) { throw ("DISM /Get-ImageInfo falló con código {0}" -f $LASTEXITCODE) }
  $pattern = '(?ms)^\s*Index\s*:\s*(\d+).*?^\s*Name\s*:\s*(.+?)\r?$'
  $opt = [System.Text.RegularExpressions.RegexOptions]::Multiline -bor `
         [System.Text.RegularExpressions.RegexOptions]::Singleline -bor `
         [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  $m = [System.Text.RegularExpressions.Regex]::Matches($dismInfo, $pattern, $opt)
  $entries = foreach ($match in $m) { [pscustomobject]@{ Index=[int]$match.Groups[1].Value; Name=$match.Groups[2].Value.Trim() } }
  if (-not $entries) { throw "No se pudieron parsear índices de la imagen." }
  $best = $entries | Where-Object { $_.Name -match '(?i)Standard' -and ($_.Name -match '(?i)Desktop\s*Experience|Experiencia') } | Select-Object -First 1
  if (-not $best) { $best = $entries | Where-Object { $_.Name -match '(?i)Desktop\s*Experience|Experiencia' } | Select-Object -First 1 }
  if (-not $best) { $best = $entries | Select-Object -First 1 }
  $index = [int]$best.Index; $nameSel = $best.Name
}
Write-Host ("    Índice elegido: {0} | Nombre: {1}" -f $index, $nameSel)

# Rutas temporales únicas
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$MountDir = Join-Path $env:TEMP ("WimMount_{0}" -f $ts)
$ExtractDir = Join-Path $env:TEMP ("ExtractOS_{0}" -f $ts)
$MountedDefault = $null
$WindowsRootForDism = $null

Write-Host "==> Paso 3: intentar montar imagen en SOLO LECTURA..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $MountDir -Force | Out-Null
$mountedOk = $false
try {
  dism /Mount-Image /ImageFile:$src /Index:$index /MountDir:$MountDir /ReadOnly
  if ($LASTEXITCODE -eq 0) { $mountedOk = $true }
} catch { }

if ($mountedOk) {
  $MountedDefault = Join-Path $MountDir 'Users\Default'
  $WindowsRootForDism = Join-Path $MountDir 'Windows'
  if (-not (Test-Path $MountedDefault)) { throw ("No existe {0} en la imagen montada." -f $MountedDefault) }
  Write-Host "    Montaje OK."
} else {
  Write-Warning "    El montaje ha fallado. Cambio a plan B: APPLY-IMAGE a un directorio temporal."
  New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null
  dism /Apply-Image /ImageFile:$src /Index:$index /ApplyDir:$ExtractDir
  if ($LASTEXITCODE -ne 0) { throw ("DISM /Apply-Image falló con código {0}" -f $LASTEXITCODE) }
  $MountedDefault   = Join-Path $ExtractDir 'Users\Default'
  $WindowsRootForDism = Join-Path $ExtractDir 'Windows'
  if (-not (Test-Path $MountedDefault))   { throw ("No existe {0} en la extracción." -f $MountedDefault) }
  if (-not (Test-Path $WindowsRootForDism)) { throw ("No existe {0} en la extracción." -f $WindowsRootForDism) }
}

Write-Host "==> Paso 4: respaldar (si existe) y reemplazar C:\Users\Default..." -ForegroundColor Cyan
$TargetDefault = 'C:\Users\Default'
if (Test-Path $TargetDefault) {
  Write-Host ("    Tomando propiedad y permisos sobre {0} ..." -f $TargetDefault)
  cmd /c 'takeown /F "C:\Users\Default" /R /A /D S' | Out-Null
  icacls $TargetDefault /grant "*S-1-5-32-544:(F)" /T | Out-Null
  $backup = "C:\Users\Default.BAD.$ts"
  Write-Host ("    Renombrando a {0} ..." -f $backup)
  Rename-Item $TargetDefault $backup -ErrorAction Stop
}

Write-Host "    Copiando Default limpio (robocopy /B)..." -ForegroundColor Yellow
robocopy $MountedDefault $TargetDefault /MIR /XJ /COPYALL /R:1 /W:1 /B | Out-Null
$rc = $LASTEXITCODE
if ($rc -gt 7) { throw ("Robocopy devolvió código {0} (error)." -f $rc) }

Write-Host "==> Paso 5: ACLs canónicas en C:\Users\Default..." -ForegroundColor Cyan
icacls $TargetDefault /inheritance:e | Out-Null
# Algunos subpaths especiales pueden denegar reset; es benigno.
cmd /c "icacls `"$TargetDefault`" /reset /T /C" | Out-Null
cmd /c "icacls `"$TargetDefault`" /grant:r *S-1-5-18:(OI)(CI)(F) *S-1-5-32-544:(OI)(CI)(F) *S-1-5-32-545:(OI)(CI)(RX) /T /C" | Out-Null

Write-Host "==> Paso 6: asegurar servicios del shell..." -ForegroundColor Cyan
$svcNames = @('StateRepository','AppReadiness','ProfSvc')
$services = @( Get-Service -Name $svcNames -ErrorAction SilentlyContinue )
foreach ($svc in $services) {
  try { Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction Stop } catch { }
  try { $svc.Refresh(); if ($svc.Status -ne 'Running') { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue } } catch { }
}

Write-Host "==> Paso 7: DISM + SFC (usando SIEMPRE el DVD como Source; fallback WU si fuera necesario)..." -ForegroundColor Cyan
$rcDism = Invoke-DismRepairOffline -WindowsRoot $WindowsRootForDism
if ($rcDism -ne 0) {
  Write-Warning ("DISM offline devolvió código {0}. Intentando fallback con Windows Update (bypass WSUS temporal)..." -f $rcDism)
  $rcDism = Invoke-DismRepairWithWUBypass
  if ($rcDism -ne 0) { Write-Warning ("DISM con WU devolvió código {0}. Revisa C:\Windows\Logs\DISM\dism.log" -f $rcDism) }
}
sfc /scannow

Write-Host "==> Paso 8: Re-registrar componentes del shell presentes..." -ForegroundColor Cyan
# En Server 2019 suele existir solo ShellExperienceHost. Registramos lo que haya.
$sys = Join-Path $env:windir 'SystemApps'
Get-ChildItem $sys -Directory | Where-Object { $_.Name -like 'Microsoft.Windows.*ExperienceHost*' } |
  ForEach-Object {
    $m = Join-Path $_.FullName 'AppxManifest.xml'
    if (Test-Path $m) {
      try { Add-AppxPackage -DisableDevelopmentMode -Register $m }
      catch { Write-Warning ("Re-registro {0}: {1}" -f $_.Name, $_.Exception.Message) }
    }
  }
Start-Service StateRepository,AppReadiness -ErrorAction SilentlyContinue

Write-Host "==> Paso 9: Verificaciones" -ForegroundColor Cyan
# 9.1 NTUSER.DAT
$ntuser = Join-Path $TargetDefault 'NTUSER.DAT'
if (-not (Test-Path $ntuser)) { Write-Warning ("Falta NTUSER.DAT en {0}" -f $TargetDefault) }
else { $len = (Get-Item $ntuser).Length; Write-Host ("    NTUSER.DAT tamaño: {0} KB" -f [math]::Round($len/1KB,0)) }

# 9.2 ACLs
Write-Host "    ACLs actuales en $($TargetDefault):"; icacls $TargetDefault

# 9.3 Start Layout por GPO (si existiera, podría romper Inicio)
Write-Host "    Comprobando políticas de Start Layout..."
$keys = @(
  'HKCU\Software\Policies\Microsoft\Windows\Explorer',
  'HKLM\Software\Policies\Microsoft\Windows\Explorer'
)
foreach ($k in $keys) {
  foreach ($v in 'StartLayoutFile','LockedStartLayout') {
    try { reg query $k /v $v | Out-Null; Write-Host ("      {0}\{1} DEFINIDO" -f $k,$v) }
    catch { }
  }
}

# 9.4 Paquetes aprovisionados e instalados
Write-Host "    Comprobando paquetes aprovisionados del Start/Shell..."
Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match 'ShellExperienceHost|StartMenuExperienceHost' } |
  Select-Object DisplayName, PackageName | Format-Table -AutoSize

Write-Host "    Comprobando paquetes instalados (AllUsers)..."
$names = 'Microsoft.Windows.ShellExperienceHost','Microsoft.Windows.StartMenuExperienceHost'
$apps  = foreach ($n in $names) { Get-AppxPackage -AllUsers -Name $n -ErrorAction SilentlyContinue }
$apps | Select-Object Name, Status, InstallLocation | Format-Table -AutoSize

# 9.5 Eventos del servicio de perfiles
Write-Host "    Últimos eventos 1508/1509/1511/1515/1530 (Application -> User Profile Service)"
$ids = 1508,1509,1511,1515,1530
Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=$ids } -MaxEvents 20 |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
  Format-Table -Wrap

# 9.6 (Opcional) usuario de prueba
if ($CreateTestUser) {
  if (-not $TestUserPassword) {
    $TestUserPassword = -join ((33..126) | Get-Random -Count 18 | ForEach-Object {[char]$_})
  }
  Write-Host ("    Creando usuario local de prueba: {0} ..." -f $TestUserName)
  net user $TestUserName $TestUserPassword /add | Out-Null
  Write-Host ("    Usuario '{0}' creado. Contraseña: {1}" -f $TestUserName, $TestUserPassword)
  Write-Host "    Inicia sesión con ese usuario para validar creación de perfil e Inicio."
}

Write-Host "==> Paso 10: desmontar/limpiar temporales..." -ForegroundColor Cyan
try { dism /Unmount-Image /MountDir:$MountDir /Discard | Out-Null } catch { }
try { Remove-Item $MountDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
try { Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }

try { Stop-Transcript | Out-Null } catch {}

Write-Host "`n=== COMPLETADO ===" -ForegroundColor Green
if ($Global:TranscriptPath) { Write-Host ("Log: {0}" -f $Global:TranscriptPath) }
Write-Host "Prueba con un usuario NUEVO (o ejecuta con -CreateTestUser) y verifica el Inicio."
