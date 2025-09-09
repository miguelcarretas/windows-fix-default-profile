<# 
  Fix-DefaultProfile.ps1 (v1.2)
  Recompone C:\Users\Default desde el DVD (install.wim/esd) y repara Start en usuarios nuevos.
  - Paso 2 robusto: usa Get-WindowsImage; fallback a DISM /English + regex segura.
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

Write-Host "==> Paso 0: limpiar montajes DISM y preparar punto de montaje..." -ForegroundColor Cyan
try { dism /Get-MountedImageInfo | Out-Null; dism /Cleanup-Mountpoints | Out-Null } catch { }

$MountDir = 'C:\WimMount'
if (Test-Path $MountDir) { try { Remove-Item $MountDir -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
New-Item -ItemType Directory -Path $MountDir -Force | Out-Null
icacls $MountDir /grant "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /T | Out-Null

Write-Host "==> Paso 1: detectar DVD y origen..." -ForegroundColor Cyan
$dvd = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=5" | Select-Object -First 1).DeviceID
if (-not $dvd) { throw "No se detectó unidad de DVD montada. Monta el medio e inténtalo de nuevo." }
$src = @("$dvd\sources\install.wim","$dvd\sources\install.esd") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $src) { throw ("No se encontró install.wim/esd en {0}\sources" -f $dvd) }
Write-Host ("    DVD: {0} | Origen: {1}" -f $dvd, $src)

Write-Host "==> Paso 2: elegir índice de la edición adecuada..." -ForegroundColor Cyan
$index = $null; $nameSel = $null

# Opción 1: cmdlets nativos (más fiable)
try {
  Import-Module Dism -ErrorAction SilentlyContinue | Out-Null
  $images = Get-WindowsImage -ImagePath $src -ErrorAction Stop
  if ($images) {
    $best = $images | Where-Object { $_.ImageName -match '(?i)Standard' -and ($_.ImageName -match '(?i)Desktop\s*Experience|Experiencia') } | Select-Object -First 1
    if (-not $best) { $best = $images | Where-Object { $_.ImageName -match '(?i)Desktop\s*Experience|Experiencia' } | Select-Object -First 1 }
    if (-not $best) { $best = $images | Select-Object -First 1 }
    $index = [int]$best.ImageIndex
    $nameSel = $best.ImageName
  }
} catch { }

# Opción 2 (fallback): DISM en inglés + regex robusta
if (-not $index) {
  $dismInfo = (dism /Get-ImageInfo /ImageFile:$src /English) -join "`n"
  if ($LASTEXITCODE -ne 0) { throw ("DISM /Get-ImageInfo falló con código {0}" -f $LASTEXITCODE) }

  $pattern = '(?ms)^\s*Index\s*:\s*(\d+).*?^\s*Name\s*:\s*(.+?)\r?$'
  $opt = [System.Text.RegularExpressions.RegexOptions]::Multiline -bor `
         [System.Text.RegularExpressions.RegexOptions]::Singleline -bor `
         [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  $m = [System.Text.RegularExpressions.Regex]::Matches($dismInfo, $pattern, $opt)

  $entries = @()
  foreach ($match in $m) {
    $entries += [pscustomobject]@{
      Index = [int]$match.Groups[1].Value
      Name  = $match.Groups[2].Value.Trim()
    }
  }
  if (-not $entries) { throw "No se pudieron parsear índices de la imagen." }

  $best = $entries | Where-Object { $_.Name -match '(?i)Standard' -and ($_.Name -match '(?i)Desktop\s*Experience|Experiencia') } | Select-Object -First 1
  if (-not $best) { $best = $entries | Where-Object { $_.Name -match '(?i)Desktop\s*Experience|Experiencia' } | Select-Object -First 1 }
  if (-not $best) { $best = $entries | Select-Object -First 1 }
  $index = [int]$best.Index
  $nameSel = $best.Name
}

Write-Host ("    Índice elegido: {0} | Nombre: {1}" -f $index, $nameSel)

Write-Host "==> Paso 3: montar imagen en SOLO LECTURA..." -ForegroundColor Cyan
dism /Mount-Image /ImageFile:$src /Index:$index /MountDir:$MountDir /ReadOnly
if ($LASTEXITCODE -ne 0) { throw ("DISM /Mount-Image falló con código {0}" -f $LASTEXITCODE) }

$MountedDefault = Join-Path $MountDir 'Users\Default'
if (-not (Test-Path $MountedDefault)) { throw ("No existe {0} en la imagen montada." -f $MountedDefault) }

Write-Host "==> Paso 4: respaldar (si existe) y reemplazar C:\Users\Default..." -ForegroundColor Cyan
$TargetDefault = 'C:\Users\Default'
if (Test-Path $TargetDefault) {
  Write-Host ("    Tomando propiedad y permisos sobre {0} ..." -f $TargetDefault)
  cmd /c 'takeown /F "C:\Users\Default" /R /A /D S' | Out-Null
  icacls $TargetDefault /grant "*S-1-5-32-544:(F)" /T | Out-Null
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $backup = "C:\Users\Default.BAD.$stamp"
  Write-Host ("    Renombrando a {0} ..." -f $backup)
  Rename-Item $TargetDefault $backup -ErrorAction Stop
}

Write-Host "    Copiando Default limpio (robocopy /B)..." -ForegroundColor Yellow
robocopy $MountedDefault $TargetDefault /MIR /XJ /COPYALL /R:1 /W:1 /B | Out-Null
$rc = $LASTEXITCODE
if ($rc -gt 7) { throw ("Robocopy devolvió código {0} (error)." -f $rc) }

Write-Host "==> Paso 5: ACLs canónicas en C:\Users\Default..." -ForegroundColor Cyan
icacls $TargetDefault /inheritance:e | Out-Null
icacls $TargetDefault /reset /T /C | Out-Null
icacls $TargetDefault /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" "*S-1-5-32-545:(OI)(CI)(RX)" /T /C | Out-Null

Write-Host "==> Paso 6: asegurar servicios del shell..." -ForegroundColor Cyan
$svcNames = 'StateRepository','AppReadiness','ProfSvc'
Get-Service $svcNames -ErrorAction SilentlyContinue | ForEach-Object {
  try {
    if ($_.StartType -ne 'Automatic') { Set-Service $_.Name -StartupType Automatic }
    if ($_.Status -ne 'Running') { Start-Service $_.Name -ErrorAction SilentlyContinue }
  } catch { Write-Warning ("Servicio {0}: {1}" -f $_.Name, $_.Exception.Message) }
}

Write-Host "==> Paso 7: DISM + SFC..." -ForegroundColor Cyan
DISM /Online /Cleanup-Image /RestoreHealth
if ($LASTEXITCODE -ne 0) { Write-Warning ("DISM /RestoreHealth devolvió {0}" -f $LASTEXITCODE) }
sfc /scannow

Write-Host "==> Paso 8: Re-registrar ShellExperienceHost y StartMenuExperienceHost..." -ForegroundColor Cyan
$pkgs = 'Microsoft.Windows.ShellExperienceHost','Microsoft.Windows.StartMenuExperienceHost'
foreach ($p in $pkgs) {
  try {
    Get-AppxPackage -AllUsers $p | ForEach-Object {
      Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
    }
  } catch { Write-Warning ("Re-registro {0}: {1}" -f $p, $_.Exception.Message) }
}

Write-Host "==> Paso 9: Verificaciones" -ForegroundColor Cyan

# 9.1 Contenido básico
$ntuser = Join-Path $TargetDefault 'NTUSER.DAT'
if (-not (Test-Path $ntuser)) { Write-Warning ("Falta NTUSER.DAT en {0}" -f $TargetDefault) }
else {
  $len = (Get-Item $ntuser).Length
  Write-Host ("    NTUSER.DAT tamaño: {0} KB" -f [math]::Round($len/1KB,0))
}

# 9.2 ACLs esperadas
Write-Host "    ACLs actuales en $($TargetDefault):"
icacls $TargetDefault

# 9.3 Paquetes aprovisionados e instalados del Start/Shell
Write-Host "    Comprobando paquetes aprovisionados del Start/Shell..."
Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match 'ShellExperienceHost|StartMenuExperienceHost' } |
  Select-Object DisplayName, PackageName | Format-Table -AutoSize

Write-Host "    Comprobando paquetes instalados (AllUsers)..."
Get-AppxPackage -AllUsers Microsoft.Windows.ShellExperienceHost,Microsoft.Windows.StartMenuExperienceHost |
  Select-Object Name, Status, InstallLocation | Format-Table -AutoSize

# 9.4 Eventos recientes del servicio de perfiles
Write-Host "    Últimos eventos 1508/1509/1511/1515/1530 (Application -> User Profile Service)"
$ids = 1508,1509,1511,1515,1530
Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=$ids } -MaxEvents 20 |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
  Format-Table -Wrap

# 9.5 (Opcional) crear usuario de prueba
if ($CreateTestUser) {
  if (-not $TestUserPassword) {
    $TestUserPassword = -join ((33..126) | Get-Random -Count 18 | ForEach-Object {[char]$_})
  }
  Write-Host ("    Creando usuario local de prueba: {0} ..." -f $TestUserName)
  net user $TestUserName $TestUserPassword /add | Out-Null
  Write-Host ("    Usuario '{0}' creado. Contraseña: {1}" -f $TestUserName, $TestUserPassword)
  Write-Host "    Inicia sesión con ese usuario para validar creación de perfil e Inicio."
}

Write-Host "==> Paso 10: desmontar imagen y limpiar..." -ForegroundColor Cyan
try { dism /Unmount-Image /MountDir:$MountDir /Discard } catch { Write-Warning ("Error al desmontar: {0}" -f $_.Exception.Message) }
try { Remove-Item $MountDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "=== COMPLETADO ===" -ForegroundColor Green
if ($Global:TranscriptPath) { Write-Host ("Log: {0}" -f $Global:TranscriptPath) }
Write-Host "Prueba con un usuario NUEVO (o ejecuta con -CreateTestUser) y verifica el Inicio."
