# ad-printers.ps1 — ADR-0023: impresoras publicadas en Active Directory.
#
# Lo lanza privsvc (Ipc\AdPrinters.cs) como SYSTEM con `-File`, así que consulta
# AD con la CUENTA DE MÁQUINA del equipo. Validado en campo el 2026-09-15: SYSTEM
# en MSIG-WSUS leyó 21 objetos printQueue en 314 ms.
#
# READ ONLY. No escribe en AD. Sólo escribe el JSON de resultado en -OutputPath.
#
# Contrato de salida (lo interpreta el backend, modules/ad-printers/ad-printers-logic.ts):
#   { collector, partOfDomain, domain, dcUsed, queryMs, queues: [...], error }
# ⚠️ Un fallo se DECLARA en `error`, nunca como lista vacía: una lista vacía
# diría "el dominio no publica impresoras". Y un equipo fuera de dominio lleva
# partOfDomain=false, que el backend trata como fallo, no como cero.
#
# ⚠️ Nombres de variable: PowerShell no distingue mayúsculas. En el spike, `$r`
# del bucle ERA `$R` (el informe) y lo sobrescribió entero. Aquí el informe es
# `$Report` y el bucle usa `$hit`; no reutilizar esos nombres con otra caja.
#
# Funciones con prefijo Adp: un alias integrado de PowerShell gana a una función
# con su mismo nombre (lección del colector de ASP).
#
# Sin RSAT: `System.DirectoryServices` viene con Windows; `Get-ADObject` no
# existe en una estación.

param(
  [Parameter(Mandatory = $true)][string]$OutputPath,
  [int]$BudgetMs = 100000
)

$ErrorActionPreference = 'Stop'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$MaxQueues = 5000

$Report = [ordered]@{
  collector    = 'ad-printers/1'
  partOfDomain = $null
  domain       = $null
  dcUsed       = $null
  queryMs      = $null
  queues       = @()
  error        = $null
}

function AdpWriteReport {
  $json = $Report | ConvertTo-Json -Depth 6 -Compress
  [System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function AdpFirstValue($props, [string]$name) {
  if ($props[$name].Count -gt 0) { return $props[$name][0] }
  return $null
}

try {
  $computer = Get-CimInstance -ClassName Win32_ComputerSystem
  $Report.partOfDomain = [bool]$computer.PartOfDomain
  if (-not $computer.PartOfDomain) {
    AdpWriteReport
    exit 0
  }
  $Report.domain = [string]$computer.Domain

  $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($computer.Domain)/RootDSE")
  $namingContext = [string]$rootDse.defaultNamingContext.Value
  $Report.dcUsed = [string]$rootDse.dnsHostName.Value

  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($computer.Domain)/$namingContext")
  $searcher.Filter = '(objectCategory=printQueue)'
  $searcher.PageSize = 500
  # El presupuesto que dio privsvc, menos margen para escribir la salida.
  $limit = [TimeSpan]::FromMilliseconds([Math]::Max(5000, $BudgetMs - 5000))
  $searcher.ServerTimeLimit = $limit
  $searcher.ClientTimeout = $limit
  $attributes = @('printername', 'servername', 'shortservername', 'uncname', 'printsharename', 'drivername',
                  'location', 'description', 'portname', 'printcolor', 'printduplexsupported', 'whenchanged')
  $searcher.PropertiesToLoad.AddRange([string[]]$attributes) | Out-Null

  $found = New-Object System.Collections.Generic.List[object]
  foreach ($hit in $searcher.FindAll()) {
    if ($found.Count -ge $MaxQueues) { break }
    $props = $hit.Properties
    $when = AdpFirstValue $props 'whenchanged'
    $found.Add([ordered]@{
      printerName     = [string](AdpFirstValue $props 'printername')
      serverName      = [string](AdpFirstValue $props 'servername')
      shortServerName = [string](AdpFirstValue $props 'shortservername')
      uncName         = [string](AdpFirstValue $props 'uncname')
      shareName       = [string](AdpFirstValue $props 'printsharename')
      driverName      = [string](AdpFirstValue $props 'drivername')
      location        = [string](AdpFirstValue $props 'location')
      description     = [string](AdpFirstValue $props 'description')
      # Multivalor: una cola con varios puertos (printer pooling).
      portNames       = @($props['portname'] | ForEach-Object { [string]$_ })
      color           = AdpFirstValue $props 'printcolor'
      duplex          = AdpFirstValue $props 'printduplexsupported'
      whenChanged     = if ($when -is [DateTime]) { $when.ToUniversalTime().ToString('o') } else { $null }
    })
  }
  $Report.queues = $found.ToArray()
  $Report.queryMs = $stopwatch.ElapsedMilliseconds
} catch {
  $Report.error = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
}

AdpWriteReport
