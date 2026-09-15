# asp-ad-collector.ps1 — ADR-0022 Assessment Service, colector de Active Directory.
#
# Lo ejecuta el PrivSvc (LocalSystem) en el DC colector:
#   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
#                  -File asp-ad-collector.ps1 -InputPath <in.json> -OutputPath <out.json>
#
# REGLAS DE ESTE FICHERO (las fija la fase 0 del ADR y las comprueba
# test/plugins/asp/asp-collector-script.test.ts):
#   - Se distribuye como FICHERO en disco firmado con Authenticode y se lanza con
#     -File. Nunca -EncodedCommand, Invoke-Expression ni un cargador codificado:
#     AMSI de Defender cortó el spike con ScriptContainedMaliciousContent.
#   - SÓLO LECTURA. Ninguna llamada escribe en AD ni en el registro; lo único que
#     escribe es el JSON de salida que pide el PrivSvc.
#   - Los helpers llevan prefijo Asp: los alias integrados (rv, sl, gc…) ganan a
#     una función del mismo nombre.
#   - Ejecuta TIPOS de consulta cerrados. El catálogo manda datos (DN, filtro,
#     atributos); nada del catálogo se evalúa como código.
#   - Devuelve lo que el directorio dijo, acotado: recuentos y como mucho
#     `evidenceLimit` DN por consulta. El veredicto lo decide el agente en Node.
#   - Un error se devuelve con su HRESULT, no se interpreta aquí:
#     0x8007200A (ERROR_DS_NO_ATTRIBUTE_OR_VALUE) en una lectura de PSO significa
#     "sin derecho de lectura" y el agente lo convierte en not_assessed.

param(
  [Parameter(Mandatory = $true)][string]$InputPath,
  [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$AspClock = [System.Diagnostics.Stopwatch]::StartNew()

# Propiedad opcional de un objeto de ConvertFrom-Json: $null si no viene.
function AspProp($object, [string]$name) {
  if ($null -eq $object) { return $null }
  $p = $object.PSObject.Properties[$name]
  if ($null -eq $p) { return $null }
  return $p.Value
}

function AspHex([int64]$value) {
  return ('0x{0:X8}' -f ([int64]$value -band 0xFFFFFFFFL))
}

function AspErrorInfo($errorRecord) {
  $ex = $errorRecord.Exception
  while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
  $hr = 0
  try { $hr = [int64]$ex.HResult } catch { $hr = 0 }
  if ($ex -is [System.Runtime.InteropServices.COMException]) { $hr = [int64]$ex.ErrorCode }
  $message = [string]$ex.Message
  if ($message.Length -gt 300) { $message = $message.Substring(0, 300) }
  return [ordered]@{ hresult = (AspHex $hr); type = $ex.GetType().Name; message = $message }
}

function AspIsNoSuchObject($errorRecord) {
  $info = AspErrorInfo $errorRecord
  return ($info.hresult -eq '0x80072030')
}

# Valores del directorio a JSON sin perder precisión: los enteros viajan como
# texto (pwdLastSet no cabe en un double) y el agente los convierte.
function AspValue($value) {
  if ($null -eq $value) { return $null }
  if ($value -is [byte[]]) { return $null }
  if ($value -is [datetime]) { return $value.ToUniversalTime().ToString('o') }
  if ($value -is [int] -or $value -is [int64] -or $value -is [uint32] -or $value -is [long]) { return [string]$value }
  if ($value -is [bool]) { return [bool]$value }
  return [string]$value
}

# El DN de un objeto por su SID, escapado para ir DENTRO de un filtro LDAP
# (RFC 4515: ( ) * \ y NUL). Catálogo 1.1.0: la pertenencia real a los grupos
# protegidos (memberOf:1.2.840.113556.1.4.1941:=<DN>) no se puede escribir con
# DN fijos — un grupo movido o renombrado haría pasar por huérfano a un
# administrador —, y adminCount=1 no sirve: en el dominio de la sonda 35 de 58
# eran huérfanos. Un SID que no existe es un error, nunca un filtro vacío.
$AspSidDnCache = @{}
function AspSidDn([string]$sid) {
  if ($AspSidDnCache.ContainsKey($sid)) { return $AspSidDnCache[$sid] }
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = AspEntry "<SID=$sid>"
  $searcher.Filter = '(objectClass=*)'
  $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
  [void]$searcher.PropertiesToLoad.Add('distinguishedname')
  $r = $searcher.FindOne()
  if ($null -eq $r) { throw "sidDn: no object for $sid" }
  $dn = [string]$r.Properties['distinguishedname'][0]
  $AspSidDnCache[$sid] = $dn
  return $dn
}

function AspLdapEscape([string]$value) {
  return $value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function AspExpand([string]$text, $ctx) {
  if ($null -eq $text) { return $null }
  $out = $text.Replace('{domainDn}', $ctx.domainDn).Replace('{configDn}', $ctx.configDn).Replace('{schemaDn}', $ctx.schemaDn)
  $out = $out.Replace('{domainSid}', $ctx.domainSid).Replace('{rootDomainSid}', $ctx.rootDomainSid)
  $out = [regex]::Replace($out, '\{sidDn:(S-1-\d+(?:-\d+)*)\}', {
      param($m)
      return (AspLdapEscape (AspSidDn $m.Groups[1].Value))
    })
  $out = [regex]::Replace($out, '\{fileTimeDaysAgo:(\d{1,4})\}', {
      param($m)
      return [string]([DateTime]::UtcNow.AddDays(-[int]$m.Groups[1].Value).ToFileTimeUtc())
    })
  $out = [regex]::Replace($out, '\{generalizedTimeDaysAgo:(\d{1,4})\}', {
      param($m)
      return ([DateTime]::UtcNow.AddDays(-[int]$m.Groups[1].Value).ToString('yyyyMMddHHmmss') + '.0Z')
    })
  if ($out -match '\{[A-Za-z]') { throw "unknown placeholder in: $text" }
  return $out
}

function AspEntry([string]$dn) {
  return New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
}

function AspScope([string]$scope) {
  switch ($scope) {
    'base' { return [System.DirectoryServices.SearchScope]::Base }
    'onelevel' { return [System.DirectoryServices.SearchScope]::OneLevel }
    default { return [System.DirectoryServices.SearchScope]::Subtree }
  }
}

function AspSidString([byte[]]$bytes) {
  return (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
}

function AspContext() {
  $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
  $domainDn = [string]$root.defaultNamingContext.Value
  $rootDn = [string]$root.rootDomainNamingContext.Value
  $domain = AspEntry $domainDn
  $rootDomain = AspEntry $rootDn
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem
  return [ordered]@{
    domainDn        = $domainDn
    configDn        = [string]$root.configurationNamingContext.Value
    schemaDn        = [string]$root.schemaNamingContext.Value
    domainSid       = (AspSidString ([byte[]]$domain.Properties['objectSid'].Value))
    rootDomainSid   = (AspSidString ([byte[]]$rootDomain.Properties['objectSid'].Value))
    dnsHostName     = [string]$root.dnsHostName.Value
    dnsDomain       = [string]$cs.Domain
    isDomainController = ([int]$cs.DomainRole -ge 4)
    osBuild         = [int][Environment]::OSVersion.Version.Build
    ranAs           = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    psVersion       = [string]$PSVersionTable.PSVersion
  }
}

function AspSearch($query, $ctx, [int]$limit) {
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = AspEntry (AspExpand ([string]$query.base) $ctx)
  $searcher.Filter = AspExpand ([string]$query.filter) $ctx
  $searcher.SearchScope = AspScope ([string](AspProp $query 'scope'))
  $searcher.PageSize = 1000
  [void]$searcher.PropertiesToLoad.Add('distinguishedname')
  $count = 0
  $sample = New-Object System.Collections.Generic.List[string]
  $found = $searcher.FindAll()
  try {
    foreach ($r in $found) {
      $count++
      if ($sample.Count -lt $limit) { $sample.Add([string]$r.Properties['distinguishedname'][0]) }
    }
  } finally {
    $found.Dispose()
  }
  return [ordered]@{ count = $count; sample = $sample.ToArray(); truncated = ($count -gt $sample.Count) }
}

function AspObject($query, $ctx) {
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = AspEntry (AspExpand ([string]$query.dn) $ctx)
  $searcher.Filter = '(objectClass=*)'
  $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
  foreach ($a in $query.attributes) { [void]$searcher.PropertiesToLoad.Add([string]$a) }
  try {
    $r = $searcher.FindOne()
  } catch {
    if (AspIsNoSuchObject $_) { return [ordered]@{ found = $false } }
    throw
  }
  if ($null -eq $r) { return [ordered]@{ found = $false } }
  $attrs = [ordered]@{}
  foreach ($a in $query.attributes) {
    $key = ([string]$a).ToLowerInvariant()
    if ($r.Properties.Contains($key) -and $r.Properties[$key].Count -gt 0) {
      if ($r.Properties[$key].Count -eq 1) {
        $attrs[[string]$a] = AspValue $r.Properties[$key][0]
      } else {
        $attrs[[string]$a] = @($r.Properties[$key] | Select-Object -First 50 | ForEach-Object { AspValue $_ })
      }
    }
  }
  return [ordered]@{ found = $true; attributes = $attrs }
}

function AspRootDse($query) {
  $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
  $attrs = [ordered]@{}
  foreach ($a in $query.attributes) {
    $v = $root.Properties[[string]$a].Value
    if ($null -ne $v) { $attrs[[string]$a] = AspValue $v }
  }
  return [ordered]@{ found = $true; attributes = $attrs }
}

function AspGroupMembers($query, $ctx, [int]$limit) {
  $exclude = @{}
  foreach ($s in @(AspProp $query 'excludeSids')) { if ($s) { $exclude[(AspExpand ([string]$s) $ctx)] = $true } }
  $members = @{}
  $anyFound = $false
  foreach ($g in $query.groups) {
    $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $groupSearcher.SearchRoot = AspEntry (AspExpand ([string]$g) $ctx)
    $groupSearcher.Filter = '(objectClass=group)'
    $groupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
    [void]$groupSearcher.PropertiesToLoad.Add('distinguishedname')
    try {
      $group = $groupSearcher.FindOne()
    } catch {
      if (AspIsNoSuchObject $_) { continue }
      throw
    }
    if ($null -eq $group) { continue }
    $anyFound = $true
    $groupDn = [string]$group.Properties['distinguishedname'][0]
    $escaped = $groupDn.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29').Replace('*', '\2a')
    $rule = if ([bool](AspProp $query 'recursive')) { 'memberOf:1.2.840.113556.1.4.1941:' } else { 'memberOf' }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = AspEntry $ctx.domainDn
    $searcher.Filter = "(&(!(objectClass=group))($rule=$escaped))"
    $searcher.PageSize = 1000
    [void]$searcher.PropertiesToLoad.Add('distinguishedname')
    [void]$searcher.PropertiesToLoad.Add('objectsid')
    $found = $searcher.FindAll()
    try {
      foreach ($r in $found) {
        $sid = $null
        if ($r.Properties['objectsid'].Count -gt 0) { $sid = AspSidString ([byte[]]$r.Properties['objectsid'][0]) }
        if ($sid -and $exclude.ContainsKey($sid)) { continue }
        $members[[string]$r.Properties['distinguishedname'][0]] = $true
      }
    } finally {
      $found.Dispose()
    }
  }
  if (-not $anyFound) { return [ordered]@{ found = $false } }
  $all = @($members.Keys | Sort-Object)
  return [ordered]@{ found = $true; count = $all.Count; sample = @($all | Select-Object -First $limit); truncated = ($all.Count -gt $limit) }
}

# ¿Concede este ACE alguno de los derechos pedidos sobre ESTE objeto?
# Smoke en MSIG-DOMAIN01 (14-sep): con `($rights -band $wanted) -ne 0` salían
# GenericRead, ReadProperty y Self como trustees de DCSync. GenericAll (0xF01FF)
# y GenericWrite (0x20028) son MÁSCARAS que incluyen bits de lectura: el ACE
# tiene que llevar la máscara ENTERA. Un ACE InheritOnly no aplica al objeto.
# Enteros y no el enum: se prueba con pwsh fuera de Windows.
# `$writeProps`: GUID de atributos (o conjuntos de propiedades) cuya escritura
# es peligrosa por sí sola (member, msDS-KeyCredentialLink, …). Cuenta un
# WriteProperty o un Self (escritura validada) sobre ese GUID, o sin ObjectType
# (que es sobre todos).
function AspAceHit([int]$rights, [string]$objectType, [bool]$inheritOnly, [string[]]$wanted, $extended, $writeProps) {
  if ($inheritOnly) { return $false }
  foreach ($name in $wanted) {
    $mask = switch ($name) {
      'GenericAll' { 0xF01FF }
      'GenericWrite' { 0x20028 }
      'WriteDacl' { 0x40000 }
      'WriteOwner' { 0x80000 }
      'WriteProperty' { 0x20 }
      'ExtendedRight' { 0x100 }
      default { throw "unknown right: $name" }
    }
    if (($rights -band $mask) -eq $mask) { return $true }
  }
  if ($null -ne $writeProps -and $writeProps.Count -gt 0 -and ($rights -band 0x28) -ne 0) {
    $wtype = $objectType.ToLowerInvariant()
    if (($wtype -eq '00000000-0000-0000-0000-000000000000') -or $writeProps.ContainsKey($wtype)) { return $true }
  }
  if ($null -ne $extended -and $extended.Count -gt 0 -and ($rights -band 0x100) -ne 0) {
    # Un ExtendedRight sin ObjectType concede TODOS los derechos extendidos.
    $type = $objectType.ToLowerInvariant()
    return ($type -eq '00000000-0000-0000-0000-000000000000') -or $extended.ContainsKey($type)
  }
  return $false
}
function AspAcl($query, $ctx, [int]$limit) {
  # Primera corrida real (14-sep, MSIG-DOMAIN01): leer el DACL con
  # $entry.Options / $entry.ObjectSecurity falló con 0x80131501. PowerShell
  # adapta DirectoryEntry y sus propiedades .NET compiten con los atributos
  # LDAP. Se lee nTSecurityDescriptor con DirectorySearcher, igual que
  # AspObject, y se construye el descriptor a partir de los bytes.
  $dn = AspExpand ([string]$query.dn) $ctx
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = AspEntry $dn
  $searcher.Filter = '(objectClass=*)'
  $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
  $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
  [void]$searcher.PropertiesToLoad.Add('ntsecuritydescriptor')
  $r = $searcher.FindOne()
  if ($null -eq $r) { throw "object not found: $dn" }
  if (-not $r.Properties.Contains('ntsecuritydescriptor') -or $r.Properties['ntsecuritydescriptor'].Count -eq 0) {
    throw "nTSecurityDescriptor not returned for $dn"
  }
  $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
  $sd.SetSecurityDescriptorBinaryForm([byte[]]$r.Properties['ntsecuritydescriptor'][0])

  $exclude = @{}
  foreach ($s in @(AspProp $query 'excludeSids')) { if ($s) { $exclude[(AspExpand ([string]$s) $ctx)] = $true } }
  $wanted = @(AspProp $query 'rights' | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $extended = @{}
  foreach ($guid in @(AspProp $query 'extendedRights')) { if ($guid) { $extended[([string]$guid).ToLowerInvariant()] = $true } }
  $writeProps = @{}
  foreach ($guid in @(AspProp $query 'writeProperties')) { if ($guid) { $writeProps[([string]$guid).ToLowerInvariant()] = $true } }
  $inheritOnly = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly

  $trustees = @{}
  foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = [string]$ace.IdentityReference.Value
    if ($exclude.ContainsKey($sid)) { continue }
    $hit = AspAceHit ([int]$ace.ActiveDirectoryRights) ([string]$ace.ObjectType) ((([int]$ace.PropagationFlags) -band $inheritOnly) -ne 0) $wanted $extended $writeProps
    if (-not $hit) { continue }
    if (-not $trustees.ContainsKey($sid)) {
      $name = $null
      try { $name = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $null }
      $trustees[$sid] = [ordered]@{ sid = $sid; name = $name; rights = [string]$ace.ActiveDirectoryRights; objectType = [string]$ace.ObjectType }
    }
  }
  $all = @($trustees.Values)
  return [ordered]@{ count = $all.Count; sample = @($all | Select-Object -First $limit); truncated = ($all.Count -gt $limit) }
}
# ACL sobre un CONJUNTO de objetos (ADR-0022, catálogo 1.1.0): quién puede
# resetear contraseñas de cuentas privilegiadas, cambiar miembros de grupos
# privilegiados, o controlar objetos de DC y GPO. Una sola búsqueda paginada con
# SecurityMasks = Dacl; el recuento es de TRUSTEES, cada uno con cuántos objetos
# alcanza y un DN de ejemplo.
#
# ⚠️ Nunca un pass con datos a medias: si un objeto llega sin descriptor, o hay
# más objetos que `maxObjects`, la consulta FALLA (not_assessed con el motivo)
# en vez de devolver un recuento que omite lo que no miró.
function AspAclSearch($query, $ctx, [int]$limit) {
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = AspEntry (AspExpand ([string]$query.base) $ctx)
  $searcher.Filter = AspExpand ([string]$query.filter) $ctx
  $searcher.SearchScope = AspScope ([string](AspProp $query 'scope'))
  $searcher.PageSize = 500
  $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
  [void]$searcher.PropertiesToLoad.Add('distinguishedname')
  [void]$searcher.PropertiesToLoad.Add('ntsecuritydescriptor')
  $maxObjects = 2000
  $requestedMax = AspProp $query 'maxObjects'
  if ($null -ne $requestedMax) { $maxObjects = [int]$requestedMax }

  $exclude = @{}
  foreach ($s in @(AspProp $query 'excludeSids')) { if ($s) { $exclude[(AspExpand ([string]$s) $ctx)] = $true } }
  $wanted = @(AspProp $query 'rights' | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $extended = @{}
  foreach ($guid in @(AspProp $query 'extendedRights')) { if ($guid) { $extended[([string]$guid).ToLowerInvariant()] = $true } }
  $writeProps = @{}
  foreach ($guid in @(AspProp $query 'writeProperties')) { if ($guid) { $writeProps[([string]$guid).ToLowerInvariant()] = $true } }
  $inheritOnly = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly

  $trustees = @{}
  $scanned = 0
  foreach ($r in $searcher.FindAll()) {
    $scanned++
    if ($scanned -gt $maxObjects) { throw "acl_search_object_limit: more than $maxObjects objects match" }
    $dn = [string]$r.Properties['distinguishedname'][0]
    if (-not $r.Properties.Contains('ntsecuritydescriptor') -or $r.Properties['ntsecuritydescriptor'].Count -eq 0) {
      throw "nTSecurityDescriptor not returned for $dn"
    }
    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm([byte[]]$r.Properties['ntsecuritydescriptor'][0])
    $seenHere = @{}
    foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
      if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
      $sid = [string]$ace.IdentityReference.Value
      if ($exclude.ContainsKey($sid)) { continue }
      $hit = AspAceHit ([int]$ace.ActiveDirectoryRights) ([string]$ace.ObjectType) ((([int]$ace.PropagationFlags) -band $inheritOnly) -ne 0) $wanted $extended $writeProps
      if (-not $hit) { continue }
      if (-not $trustees.ContainsKey($sid)) {
        $name = $null
        try { $name = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $null }
        $trustees[$sid] = [ordered]@{ sid = $sid; name = $name; rights = [string]$ace.ActiveDirectoryRights; objectType = [string]$ace.ObjectType; objects = 0; exampleDn = $dn }
      }
      if (-not $seenHere.ContainsKey($sid)) {
        $seenHere[$sid] = $true
        $trustees[$sid].objects++
      }
    }
  }
  $all = @($trustees.Values | Sort-Object -Property @{ Expression = { $_.objects }; Descending = $true })
  return [ordered]@{ count = $all.Count; sample = @($all | Select-Object -First $limit); truncated = ($all.Count -gt $limit); objectsScanned = $scanned }
}
function AspSysvolFiles($query, $ctx, [int]$limit) {
  $policies = "\\$($ctx.dnsHostName)\SYSVOL\$($ctx.dnsDomain)\Policies"
  # -Path y no -LiteralPath: -Include se ignora con -LiteralPath en 5.1. Las
  # llaves de los GUID de las GPO no son comodines para PowerShell.
  $files = @(Get-ChildItem -Path $policies -Recurse -File -Include @($query.patterns) -ErrorAction SilentlyContinue | Select-Object -First 5000)
  $hits = New-Object System.Collections.Generic.List[string]
  $count = 0
  foreach ($f in $files) {
    if ($f.Length -gt 1MB) { continue }
    if (Select-String -LiteralPath $f.FullName -Pattern ([string]$query.contains) -Quiet -ErrorAction SilentlyContinue) {
      $count++
      if ($hits.Count -lt $limit) {
        $rel = [string]$f.FullName
        $at = $rel.IndexOf('\Policies\', [System.StringComparison]::OrdinalIgnoreCase)
        if ($at -ge 0) { $rel = $rel.Substring($at + 10) }
        $hits.Add($rel)
      }
    }
  }
  return [ordered]@{ count = $count; sample = $hits.ToArray(); filesScanned = $files.Count; truncated = ($count -gt $hits.Count) }
}

function AspRegistry($query) {
  $path = [string]$query.path
  if (-not $path.StartsWith('HKLM\')) { throw 'only HKLM is allowed' }
  $full = 'Registry::HKEY_LOCAL_MACHINE\' + $path.Substring(5)
  $name = [string]$query.name
  if (-not (Test-Path -LiteralPath $full)) { return [ordered]@{ present = $false; value = $null } }
  $item = Get-ItemProperty -LiteralPath $full -ErrorAction Stop
  $prop = $item.PSObject.Properties[$name]
  if ($null -eq $prop) { return [ordered]@{ present = $false; value = $null } }
  $v = $prop.Value
  if ($v -is [int] -or $v -is [int64] -or $v -is [uint32]) { return [ordered]@{ present = $true; value = [int64]$v } }
  return [ordered]@{ present = $true; value = [string]$v }
}

# ── Principal ────────────────────────────────────────────────────────────────

$request = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
$limit = [int]$request.evidenceLimit
if ($limit -lt 1 -or $limit -gt 200) { $limit = 200 }
$budgetMs = [int64]$request.budgetMs
if ($budgetMs -lt 1000) { $budgetMs = 1000 }

$output = [ordered]@{ collector = $null; results = [ordered]@{}; totalMs = 0; contextError = $null }

try {
  $ctx = AspContext
  $output.collector = [ordered]@{
    host = $env:COMPUTERNAME
    ranAs = $ctx.ranAs
    dnsHostName = $ctx.dnsHostName
    dnsDomain = $ctx.dnsDomain
    domainDn = $ctx.domainDn
    isDomainController = $ctx.isDomainController
    osBuild = $ctx.osBuild
    psVersion = $ctx.psVersion
  }
} catch {
  $ctx = $null
  $output.contextError = AspErrorInfo $_
}

foreach ($item in $request.queries) {
  $id = [string]$item.id
  $q = $item.query
  $clock = [System.Diagnostics.Stopwatch]::StartNew()
  if ($AspClock.ElapsedMilliseconds -ge $budgetMs) {
    $output.results[$id] = [ordered]@{ ok = $false; error = [ordered]@{ hresult = $null; type = 'budget_exceeded'; message = 'batch budget exceeded before this query ran' }; ms = 0 }
    continue
  }
  if ($null -eq $ctx -and [string]$q.kind -ne 'registry') {
    $output.results[$id] = [ordered]@{ ok = $false; error = $output.contextError; ms = 0 }
    continue
  }
  try {
    $data = switch ([string]$q.kind) {
      'ldap_search' { AspSearch $q $ctx $limit }
      'ldap_object' { AspObject $q $ctx }
      'group_members' { AspGroupMembers $q $ctx $limit }
      'acl' { AspAcl $q $ctx $limit }
      'acl_search' { AspAclSearch $q $ctx $limit }
      'rootdse' { AspRootDse $q }
      'sysvol_files' { AspSysvolFiles $q $ctx $limit }
      'registry' { AspRegistry $q }
      default { throw "unsupported query kind: $([string]$q.kind)" }
    }
    $output.results[$id] = [ordered]@{ ok = $true; data = $data; ms = $clock.ElapsedMilliseconds }
  } catch {
    $output.results[$id] = [ordered]@{ ok = $false; error = (AspErrorInfo $_); ms = $clock.ElapsedMilliseconds }
  }
}

$output.totalMs = $AspClock.ElapsedMilliseconds
$json = $output | ConvertTo-Json -Depth 8 -Compress
[System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))
