# ad-computers.ps1 — Cobertura: los objetos de equipo que hay en Active Directory.
#
# Lo lanza privsvc (Ipc\AdComputers.cs) como SYSTEM con `-File`, así que consulta
# AD con la CUENTA DE MÁQUINA del equipo, sin credenciales de nadie.
#
# READ ONLY. No escribe en AD. Sólo escribe el JSON de resultado en -OutputPath.
#
# Contrato de salida (lo interpreta el backend, modules/discovery/discovery-logic.ts):
#   { collector, partOfDomain, domain, dcUsed, queryMs, computers: [...], truncated, error }
# ⚠️ Un fallo se DECLARA en `error`, nunca como lista vacía: una lista vacía
# diría "en este dominio no hay equipos". Fuera de dominio va partOfDomain=false,
# que el backend trata como fallo, no como cero.
#
# ── Las dos fechas ───────────────────────────────────────────────────
#
# `pwdLastSet` es la señal fuerte: una máquina unida al dominio rota su
# contraseña sola cada 30 días, así que si la rotó está viva. `lastLogonTimestamp`
# se replica entre controladores con hasta 14 días de retraso, y por eso NO se
# manda sola: las dos viajan y el backend decide con la más reciente.
#
# Ambas son FILETIME de 64 bits: 0 (y el 1601 que sale de convertirlo) significa
# «nunca», no una fecha antiquísima.
#
# ⚠️ Nombres de variable: PowerShell no distingue mayúsculas (lección del spike
# de ad-printers.ps1, donde `$r` pisó el informe `$R`). El informe es `$Report` y
# el bucle usa `$hit`.
#
# Funciones con prefijo Adc: un alias integrado gana a una función con su nombre.
#
# Sin RSAT: `System.DirectoryServices` viene con Windows; `Get-ADComputer` no
# existe en una estación.

param(
  [Parameter(Mandatory = $true)][string]$OutputPath,
  [int]$BudgetMs = 100000,
  [int]$MaxComputers = 10000
)

$ErrorActionPreference = 'Stop'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$Report = [ordered]@{
  collector    = 'ad-computers/1'
  partOfDomain = $null
  domain       = $null
  dcUsed       = $null
  queryMs      = $null
  computers    = @()
  truncated    = $false
  error        = $null
}

function AdcWriteReport {
  $json = $Report | ConvertTo-Json -Depth 5 -Compress
  [System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function AdcFirstValue($props, [string]$name) {
  if ($props[$name].Count -gt 0) { return $props[$name][0] }
  return $null
}

# FILETIME → ISO 8601, o $null si es «nunca» o está fuera de rango.
function AdcFileTime($value) {
  if ($null -eq $value) { return $null }
  try {
    $ticks = [int64]$value
  } catch {
    return $null
  }
  if ($ticks -le 0 -or $ticks -ge 2650467743999999999) { return $null }
  try {
    return [DateTime]::FromFileTimeUtc($ticks).ToString('o')
  } catch {
    return $null
  }
}

try {
  $computer = Get-CimInstance -ClassName Win32_ComputerSystem
  $Report.partOfDomain = [bool]$computer.PartOfDomain
  if (-not $computer.PartOfDomain) {
    AdcWriteReport
    exit 0
  }
  $Report.domain = [string]$computer.Domain

  $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($computer.Domain)/RootDSE")
  $namingContext = [string]$rootDse.defaultNamingContext.Value
  $Report.dcUsed = [string]$rootDse.dnsHostName.Value

  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($computer.Domain)/$namingContext")
  $searcher.Filter = '(objectCategory=computer)'
  $searcher.PageSize = 1000
  # El presupuesto que dio privsvc, menos margen para escribir la salida.
  $limit = [TimeSpan]::FromMilliseconds([Math]::Max(5000, $BudgetMs - 5000))
  $searcher.ServerTimeLimit = $limit
  $searcher.ClientTimeout = $limit
  $attributes = @('name', 'dnshostname', 'objectguid', 'operatingsystem', 'operatingsystemversion',
                  'lastlogontimestamp', 'pwdlastset', 'whencreated', 'useraccountcontrol')
  $searcher.PropertiesToLoad.AddRange([string[]]$attributes) | Out-Null

  $found = New-Object System.Collections.Generic.List[object]
  foreach ($hit in $searcher.FindAll()) {
    if ($found.Count -ge $MaxComputers) { $Report.truncated = $true; break }
    $props = $hit.Properties

    # objectGUID llega como byte[]: es la identidad que sobrevive a renombrar
    # el equipo o moverlo de unidad organizativa.
    #
    # ⚠️ Se lee SIN pasar por AdcFirstValue: PowerShell deshace un array al
    # devolverlo desde una función, así que el byte[16] llegaba convertido en 16
    # objetos sueltos y la conversión a GUID no se hacía NUNCA — con AD de
    # verdad la lista habría salido vacía sin un solo error. Lo cazó el test con
    # pwsh (test/plugins/amp/ad-computers-script.test.ts).
    $guidValue = $null
    if ($props['objectguid'].Count -gt 0) { $guidValue = $props['objectguid'][0] }
    $guid = $null
    if ($null -ne $guidValue) {
      try {
        $bytes = [byte[]]$guidValue
        if ($bytes.Length -eq 16) { $guid = (New-Object System.Guid(,$bytes)).ToString() }
      } catch {
        $guid = $null
      }
    }
    if (-not $guid) { continue }

    $created = AdcFirstValue $props 'whencreated'
    $found.Add([ordered]@{
      objectGuid              = $guid
      name                    = [string](AdcFirstValue $props 'name')
      dnsHostName             = [string](AdcFirstValue $props 'dnshostname')
      operatingSystem         = [string](AdcFirstValue $props 'operatingsystem')
      operatingSystemVersion  = [string](AdcFirstValue $props 'operatingsystemversion')
      lastLogonUtc            = AdcFileTime (AdcFirstValue $props 'lastlogontimestamp')
      passwordLastSetUtc      = AdcFileTime (AdcFirstValue $props 'pwdlastset')
      whenCreatedUtc          = if ($created -is [DateTime]) { $created.ToUniversalTime().ToString('o') } else { $null }
      userAccountControl      = AdcFirstValue $props 'useraccountcontrol'
    })
  }
  $Report.computers = $found.ToArray()
  $Report.queryMs = $stopwatch.ElapsedMilliseconds
} catch {
  $Report.error = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
}

AdcWriteReport
