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
# DUEÑO del descriptor sobre un conjunto de objetos (catálogo 1.2.0, contraste
# con Purple Knight SI000025/SI000050). El owner puede reescribir el DACL entero,
# así que un objeto privilegiado cuyo dueño no es un administrador es una ruta de
# toma de control aunque su DACL esté impecable — y el DACL es lo único que
# miraba `acl_search`.
#
# ⚠️ Mismas garantías que AspAclSearch: un objeto sin descriptor o más de
# `maxObjects` FALLAN la consulta; nunca un pass con datos a medias.
function AspOwnerSearch($query, $ctx, [int]$limit) {
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = AspEntry (AspExpand ([string]$query.base) $ctx)
  $searcher.Filter = AspExpand ([string]$query.filter) $ctx
  $searcher.SearchScope = AspScope ([string](AspProp $query 'scope'))
  $searcher.PageSize = 500
  $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Owner
  [void]$searcher.PropertiesToLoad.Add('distinguishedname')
  [void]$searcher.PropertiesToLoad.Add('ntsecuritydescriptor')
  $maxObjects = 2000
  $requestedMax = AspProp $query 'maxObjects'
  if ($null -ne $requestedMax) { $maxObjects = [int]$requestedMax }

  $allowed = @{}
  foreach ($s in @(AspProp $query 'allowedOwnerSids')) { if ($s) { $allowed[(AspExpand ([string]$s) $ctx)] = $true } }

  $owners = @{}
  $scanned = 0
  foreach ($r in $searcher.FindAll()) {
    $scanned++
    if ($scanned -gt $maxObjects) { throw "owner_search_object_limit: more than $maxObjects objects match" }
    $dn = [string]$r.Properties['distinguishedname'][0]
    if (-not $r.Properties.Contains('ntsecuritydescriptor') -or $r.Properties['ntsecuritydescriptor'].Count -eq 0) {
      throw "nTSecurityDescriptor not returned for $dn"
    }
    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm([byte[]]$r.Properties['ntsecuritydescriptor'][0])
    $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])
    if ($null -eq $owner) { throw "owner not returned for $dn" }
    $sid = [string]$owner.Value
    if ($allowed.ContainsKey($sid)) { continue }
    if (-not $owners.ContainsKey($sid)) {
      $name = $null
      try { $name = $owner.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $null }
      $owners[$sid] = [ordered]@{ sid = $sid; name = $name; objects = 0; exampleDn = $dn }
    }
    $owners[$sid].objects++
  }
  $all = @($owners.Values | Sort-Object -Property @{ Expression = { $_.objects }; Descending = $true })
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

# Plantillas de certificado de ADCS (ESC1/ESC2/ESC3/ESC4), en UNA vuelta de LDAP.
#
# ⚠️ POR QUE UN TIPO PROPIO Y NO UN FILTRO LDAP. El catalogo 1.3.0 hacia esto con
# `ldap_search` y fallo en el DC real por DOS motivos a la vez (24 y 26-sep):
#
#  1) Un filtro LDAP NO PUEDE expresar "y alguien no privilegiado puede
#     inscribirse", porque eso vive en el DACL de la plantilla, no en sus
#     atributos. Sin esa condicion el indicador marcaba plantillas que ninguna CA
#     publica -- y una plantilla que no publica ninguna CA no se puede pedir, o
#     sea que no es explotable: 6 falsos positivos de 7.
#  2) El colector corre como SYSTEM y solo veia 2 de las 38 plantillas. AD
#     responde "el objeto no existe" a lo que no te deja leer, asi que el 0 se
#     leia como `pass`.
#
# El oraculo para (2) es gratis y esta al lado: el atributo `certificateTemplates`
# de cada CA lista las plantillas PUBLICADAS. Si no resolvemos todas las que las
# CA declaran, estamos ciegos y lo decimos -- `unreadable` hace que el evaluador
# saque not_assessed en vez de pass.
#
# Y sin CA en el bosque no hay nada que evaluar: `found = false`, que con
# whenMissing: not_applicable es "no aplica", no "cumple".
function AspAdcsTemplates($query, $ctx, [int]$limit) {
  $ENROLL = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
  $AUTOENROLL = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
  $ALL_GUID = '00000000-0000-0000-0000-000000000000'
  # EKU que permiten AUTENTICARSE como alguien: son las que convierten un
  # certificado en credencial.
  $AUTH_EKU = @{ '1.3.6.1.5.5.7.3.2' = $true; '1.3.6.1.5.2.3.4' = $true; '1.3.6.1.4.1.311.20.2.2' = $true; '2.5.29.37.0' = $true }
  $ANY_OR_AGENT_EKU = @{ '2.5.29.37.0' = $true; '1.3.6.1.4.1.311.20.2.1' = $true }
  $pksDn = "CN=Public Key Services,CN=Services,$($ctx.configDn)"

  $privileged = @{}
  foreach ($sid in @(AspProp $query 'privilegedSids')) { if ($sid) { $privileged[(AspExpand ([string]$sid) $ctx)] = $true } }
  $require = @(AspProp $query 'require' | Where-Object { $_ } | ForEach-Object { [string]$_ })

  # ── Las CA y lo que publican ────────────────────────────────────────────
  $published = @{}
  $caCount = 0
  $caSearcher = New-Object System.DirectoryServices.DirectorySearcher
  $caSearcher.SearchRoot = AspEntry "CN=Enrollment Services,$pksDn"
  $caSearcher.Filter = '(objectClass=pKIEnrollmentService)'
  $caSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
  [void]$caSearcher.PropertiesToLoad.Add('cn')
  [void]$caSearcher.PropertiesToLoad.Add('certificatetemplates')
  try {
    foreach ($ca in $caSearcher.FindAll()) {
      $caCount++
      if ($ca.Properties.Contains('certificatetemplates')) {
        foreach ($t in $ca.Properties['certificatetemplates']) { $published[[string]$t] = $true }
      }
    }
  } catch {
    if (-not (AspIsNoSuchObject $_)) { throw }
  }
  if ($caCount -eq 0) {
    # Sin autoridad de certificacion no hay ADCS que evaluar.
    return [ordered]@{ found = $false; caCount = 0 }
  }

  # ── Las plantillas, con su DACL ─────────────────────────────────────────
  $tplSearcher = New-Object System.DirectoryServices.DirectorySearcher
  $tplSearcher.SearchRoot = AspEntry "CN=Certificate Templates,$pksDn"
  $tplSearcher.Filter = '(objectClass=pKICertificateTemplate)'
  $tplSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
  $tplSearcher.PageSize = 500
  $tplSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
  foreach ($a in @('cn', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'mspki-ra-signature', 'pkiextendedkeyusage', 'mspki-certificate-application-policy', 'ntsecuritydescriptor')) {
    [void]$tplSearcher.PropertiesToLoad.Add($a)
  }
  $inheritOnly = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly
  # ⚠️ SIN 'WriteProperty' a secas. La mascara de WriteProperty es 0x20 y AspAceHit
  # la casa sin mirar el ObjectType, asi que "escribir UNA propiedad" se leeria
  # como "puede reescribir la plantilla". Eso es lo que hizo que ESC4 pasara de 1
  # a 10 en el DC real (27-sep): 4 plantillas por Enterprise Domain Controllers
  # (S-1-5-9), una por Domain Users y una por RAS and IAS Servers, todas con ACE
  # por propiedad concreta de las plantillas predeterminadas. Mismo fallo de
  # mascara parcial que el DCSync del 14-sep.
  #
  # Lo que SI es ESC4: control total, GenericWrite, WriteDacl, WriteOwner, o
  # escritura sobre TODAS las propiedades (ObjectType vacio) -- eso ultimo se
  # comprueba aparte, abajo, porque AspAceHit no sabe exigir "vacio".
  $MODIFY = @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner')
  $ALL_PROPS_WRITE = 0x20
  $hits = New-Object System.Collections.Generic.List[object]
  $count = 0
  $seen = 0
  $resolved = @{}

  foreach ($r in $tplSearcher.FindAll()) {
    $seen++
    $cn = [string]$r.Properties['cn'][0]
    if ($published.ContainsKey($cn)) { $resolved[$cn] = $true }
    $nameFlag = 0; $enrollFlag = 0; $ra = 0
    if ($r.Properties.Contains('mspki-certificate-name-flag')) { $nameFlag = [int]$r.Properties['mspki-certificate-name-flag'][0] }
    if ($r.Properties.Contains('mspki-enrollment-flag')) { $enrollFlag = [int]$r.Properties['mspki-enrollment-flag'][0] }
    if ($r.Properties.Contains('mspki-ra-signature')) { $ra = [int]$r.Properties['mspki-ra-signature'][0] }
    $ekus = @{}
    foreach ($a in @('pkiextendedkeyusage', 'mspki-certificate-application-policy')) {
      if ($r.Properties.Contains($a)) { foreach ($e in $r.Properties[$a]) { $ekus[[string]$e] = $true } }
    }

    $lowEnroll = $null
    $lowEnrollRights = $null
    $lowModify = $null
    $lowModifyRights = $null
    if ($r.Properties.Contains('ntsecuritydescriptor') -and $r.Properties['ntsecuritydescriptor'].Count -gt 0) {
      $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
      $sd.SetSecurityDescriptorBinaryForm([byte[]]$r.Properties['ntsecuritydescriptor'][0])
      foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ((([int]$ace.PropagationFlags) -band $inheritOnly) -ne 0) { continue }
        $sid = [string]$ace.IdentityReference.Value
        if ($privileged.ContainsKey($sid)) { continue }
        $type = ([string]$ace.ObjectType).ToLowerInvariant()
        $rights = [int]$ace.ActiveDirectoryRights
        # Inscribirse es un derecho EXTENDIDO concreto; "todos los extendidos"
        # (ObjectType vacio) tambien lo concede.
        if ((($rights -band 0x100) -ne 0) -and ($type -eq $ENROLL -or $type -eq $AUTOENROLL -or $type -eq $ALL_GUID)) {
          if ($null -eq $lowEnroll) {
            $lowEnroll = $sid
            $lowEnrollRights = $(if ($type -eq $ALL_GUID) { 'all extended rights' } elseif ($type -eq $AUTOENROLL) { 'AutoEnroll' } else { 'Enroll' })
          }
        }
        $modifies = (AspAceHit $rights $type $false $MODIFY @{} @{})
        if (-not $modifies) {
          # Escritura sobre TODAS las propiedades: ObjectType vacio. Una
          # escritura sobre una propiedad concreta NO cuenta.
          $modifies = ((($rights -band $ALL_PROPS_WRITE) -ne 0) -and $type -eq $ALL_GUID)
        }
        if ($modifies -and $null -eq $lowModify) {
          $lowModify = $sid
          # ⚠️ QUE derecho casó, no solo quien. Sin esto no se puede auditar un
          # hallazgo, y de hecho no pude diagnosticar el falso positivo del
          # 27-sep desde el JSON: tuve que deducirlo de los SID.
          $lowModifyRights = [string]$ace.ActiveDirectoryRights
        }
      }
    }

    $flags = @{
      published = $published.ContainsKey($cn)
      enrolleeSuppliesSubject = (($nameFlag -band 0x10001) -ne 0)
      noManagerApproval = (($enrollFlag -band 2) -eq 0)
      noSignatures = ($ra -eq 0)
      # Sin ninguna EKU, el certificado vale para cualquier proposito.
      authEku = ($ekus.Count -eq 0 -or @($ekus.Keys | Where-Object { $AUTH_EKU.ContainsKey($_) }).Count -gt 0)
      anyPurposeOrEnrollmentAgentEku = (@($ekus.Keys | Where-Object { $ANY_OR_AGENT_EKU.ContainsKey($_) }).Count -gt 0)
      lowPrivEnroll = ($null -ne $lowEnroll)
      lowPrivCanModify = ($null -ne $lowModify)
    }
    $all = $true
    foreach ($k in $require) { if (-not $flags[$k]) { $all = $false; break } }
    if (-not $all) { continue }
    $count++

    # A cuantas condiciones de ESC1 esta la plantilla, y cuales le faltan. Un
    # ESC4 no es "alguien tiene permisos de mas": es "alguien esta a N ediciones
    # de poder pedir un certificado como cualquiera".
    $esc1Met = 0
    $esc1Missing = New-Object System.Collections.Generic.List[string]
    foreach ($c in @(
        @{ n = 'enrolleeSuppliesSubject'; v = $flags.enrolleeSuppliesSubject },
        @{ n = 'managerApprovalRequired'; v = $flags.noManagerApproval },
        @{ n = 'signaturesRequired'; v = $flags.noSignatures },
        @{ n = 'authEku'; v = $flags.authEku })) {
      if ($c.v) { $esc1Met++ } else { $esc1Missing.Add([string]$c.n) }
    }
    if ($hits.Count -lt $limit) {
      $hits.Add([ordered]@{
          template = $cn
          published = $flags.published
          grantedTo = $(if ($require -contains 'lowPrivCanModify') { $lowModify } else { $lowEnroll })
          grantedRights = $(if ($require -contains 'lowPrivCanModify') { $lowModifyRights } else { $lowEnrollRights })
          nameFlag = $nameFlag
          enrollFlag = $enrollFlag
          raSignature = $ra
          eku = @($ekus.Keys)
          # ⚠️ A CUANTAS condiciones de ESC1 esta la plantilla. Un ESC4 no es
          # "alguien tiene permisos de mas": es "alguien esta a N ediciones de
          # poder pedir un certificado como cualquiera". En MSIG-DOMAIN01
          # (27-sep) PRTG_WebServer cumple 3 de 4 -- sujeto a eleccion, sin
          # aprobacion, sin firmas -- y solo le falta una EKU de autenticacion,
          # que la puede anadir justo quien tiene WriteDacl sobre ella. Sin este
          # dato el hallazgo se lee como administrativo, y no lo es.
          # ⚠️ Se calculan arriba con una lista, NO con @(...) y un pipe en la
          # linea siguiente: PowerShell 5.1 NO PARSEA una linea que empieza por
          # `|`, y 5.1 es la version del DC. pwsh 7 si la parsea, asi que mi
          # comprobacion en el Mac dio verde y el colector murio en produccion
          # (T111, 27-sep: collector_no_output:exit=1).
          esc1ConditionsMet = $esc1Met
          esc1Missing = $esc1Missing.ToArray()
        })
    }
  }

  # El oraculo: lo que las CA dicen que publican contra lo que pudimos resolver.
  $declared = $published.Count
  $resolvedCount = $resolved.Count
  return [ordered]@{
    found = $true
    count = $count
    sample = $hits.ToArray()
    truncated = ($count -gt $hits.Count)
    caCount = $caCount
    objectsScanned = $seen
    publishedDeclared = $declared
    publishedResolved = $resolvedCount
    unreadable = [Math]::Max(0, $declared - $resolvedCount)
  }
}

# Quien puede RECUPERAR la contrasena de un gMSA (catalogo 1.8.0).
#
# Vive en msDS-GroupMSAMembership, que es un descriptor de seguridad guardado en
# un atributo NORMAL: es lo que escribe PrincipalsAllowedToRetrieveManagedPassword.
# Por eso es un tipo propio y no un parametro de acl_search: un colector viejo
# que no conozca este tipo FALLA en voz alta ("unsupported query kind"), mientras
# que uno que ignorase un parametro nuevo de acl_search leeria el
# nTSecurityDescriptor -- el descriptor EQUIVOCADO -- en silencio.
#
# Semantica: CUALQUIER ACE Allow es un recuperador. No se adivina mascara: estar
# en ese descriptor es lo que concede la recuperacion (las vueltas de ESC4 y del
# DCSync del 14-sep fueron por adivinar mascaras). La mascara viaja en la
# evidencia para que se pueda auditar.
#
#   match 'broad' -> el recuperador es un grupo amplio (Domain Users, Domain
#                    Computers, Authenticated Users, Everyone...): cualquiera
#                    de ese grupo obtiene la contrasena.
#   match 'user'  -> el recuperador es una cuenta de USUARIO del dominio que no
#                    es privilegiada (por tokenGroups, pertenencia real). Lo
#                    normal es que recuperen equipos o grupos de equipos.
#
# ⚠️ La ceguera: si ningun gMSA devuelve el atributo, "nadie puede recuperar"
# y "no puedo leer el atributo" son indistinguibles, y un gMSA sin recuperadores
# no sirve para nada. Con uno solo legible, el resto de ausencias son reales (el
# permiso de lectura viene del SD por defecto de la clase).
function AspGmsaRetrievers($query, $ctx, [int]$limit) {
  $match = @(AspProp $query 'match' | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $broad = @{}
  foreach ($s in @(AspProp $query 'broadSids')) { if ($s) { $broad[(AspExpand ([string]$s) $ctx)] = $true } }
  $privileged = @{}
  foreach ($s in @(AspProp $query 'privilegedSids')) { if ($s) { $privileged[(AspExpand ([string]$s) $ctx)] = $true } }
  $maxObjects = 2000
  $requestedMax = AspProp $query 'maxObjects'
  if ($null -ne $requestedMax) { $maxObjects = [int]$requestedMax }

  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = AspEntry $ctx.domainDn
  $searcher.Filter = '(objectClass=msDS-GroupManagedServiceAccount)'
  $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
  $searcher.PageSize = 500
  $searcher.ClientTimeout = New-TimeSpan -Seconds 60
  foreach ($a in @('distinguishedname', 'samaccountname', 'msds-groupmsamembership')) { [void]$searcher.PropertiesToLoad.Add($a) }

  # Clase y privilegio de un SID del dominio, con cache. Solo SIDs del PROPIO
  # dominio: un SID de un dominio de confianza obligaria a salir por la red y
  # puede bloquear (26-sep, diagnostico colgado 10 minutos por traducir SIDs).
  $principalCache = @{}
  $domainPrefix = "$($ctx.domainSid)-"

  $hits = New-Object System.Collections.Generic.List[object]
  # TODOS los gMSA con sus recuperadores, casen o no. El evaluador no la lee
  # (no viaja al backend): existe para validar en un DC que el tipo ve lo que
  # hay, que es justo lo que no hicimos con ESC4.
  $population = New-Object System.Collections.Generic.List[object]
  $count = 0
  $seen = 0
  $withoutAttribute = 0
  $aceCount = 0
  $retrieversSeen = @{}

  $found = $searcher.FindAll()
  try {
    foreach ($r in $found) {
      $seen++
      if ($seen -gt $maxObjects) { throw "gmsa_retrievers_object_limit: more than $maxObjects gMSA" }
      $dn = [string]$r.Properties['distinguishedname'][0]
      $sam = $null
      if ($r.Properties.Contains('samaccountname')) { $sam = [string]$r.Properties['samaccountname'][0] }
      if (-not $r.Properties.Contains('msds-groupmsamembership') -or $r.Properties['msds-groupmsamembership'].Count -eq 0) {
        $withoutAttribute++
        if ($population.Count -lt $limit) { $population.Add([ordered]@{ dn = $dn; account = $sam; attribute = $false }) }
        continue
      }
      # ::new y no New-Object -ArgumentList: con un byte[] como primer argumento,
      # New-Object puede desenrollar el array y buscar un constructor de N bytes.
      $sdBytes = [byte[]]$r.Properties['msds-groupmsamembership'][0]
      $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($sdBytes, 0)
      $allowed = [ordered]@{}
      $denied = @{}
      if ($null -ne $raw.DiscretionaryAcl) {
        foreach ($ace in $raw.DiscretionaryAcl) {
          $aceCount++
          # Contra el enum y no contra un texto: una errata aqui no casaria
          # nunca y daria un pass en silencio; contra el enum, falla al cargar.
          # Un ACE de objeto (AccessAllowedObject) tambien es AccessAllowed.
          $qual = $ace.AceQualifier
          $sid = [string]$ace.SecurityIdentifier.Value
          if ($qual -eq [System.Security.AccessControl.AceQualifier]::AccessDenied) { $denied[$sid] = $true; continue }
          if ($qual -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
          if (-not $allowed.Contains($sid)) { $allowed[$sid] = (AspHex ([int64]$ace.AccessMask)) }
        }
      }

      $matched = New-Object System.Collections.Generic.List[object]
      $all = New-Object System.Collections.Generic.List[object]
      foreach ($sid in $allowed.Keys) {
        if ($denied.ContainsKey($sid)) { continue }
        $retrieversSeen[$sid] = $true
        $why = $null
        $class = $null
        if ($broad.ContainsKey($sid)) {
          $class = 'broad'
          if ($match -contains 'broad') { $why = 'broad' }
        } elseif ($privileged.ContainsKey($sid)) {
          $class = 'privileged'
        } elseif ($sid.StartsWith($domainPrefix)) {
          if (-not $principalCache.ContainsKey($sid)) {
            $info = [ordered]@{ class = 'unresolved'; privileged = $false }
            try {
              $p = New-Object System.DirectoryServices.DirectorySearcher
              $p.SearchRoot = AspEntry "<SID=$sid>"
              $p.Filter = '(objectClass=*)'
              $p.SearchScope = [System.DirectoryServices.SearchScope]::Base
              $p.ClientTimeout = New-TimeSpan -Seconds 10
              [void]$p.PropertiesToLoad.Add('objectclass')
              [void]$p.PropertiesToLoad.Add('tokengroups')
              $pr = $p.FindOne()
              if ($null -ne $pr) {
                $classes = @($pr.Properties['objectclass'] | ForEach-Object { [string]$_ })
                $info.class = 'other'
                if ($classes -contains 'user') { $info.class = 'user' }
                if ($classes -contains 'group') { $info.class = 'group' }
                # computer es subclase de user (y un gMSA, de computer): va ultimo.
                if ($classes -contains 'computer') { $info.class = 'computer' }
                foreach ($tg in $pr.Properties['tokengroups']) {
                  if ($privileged.ContainsKey((AspSidString ([byte[]]$tg)))) { $info.privileged = $true; break }
                }
              }
            } catch {
              $info.class = 'unresolved'
            }
            $principalCache[$sid] = $info
          }
          $class = $principalCache[$sid].class
          if ($principalCache[$sid].privileged) {
            $class = "$class-privileged"
          } elseif ($class -eq 'user' -and ($match -contains 'user')) {
            $why = 'user'
          }
        } elseif ($sid.StartsWith('S-1-5-21-')) {
          # De otro dominio (confianza): no se resuelve, ver arriba.
          $class = 'foreign'
        } else {
          # Integrado o bien conocido (S-1-5-32-..., S-1-5-...) fuera de las listas.
          $class = 'wellknown'
        }
        $entry = [ordered]@{ sid = $sid; class = $class; mask = $allowed[$sid] }
        $all.Add($entry)
        if ($null -ne $why) { $matched.Add([ordered]@{ sid = $sid; why = $why; class = $class; mask = $allowed[$sid] }) }
      }

      if ($population.Count -lt $limit) {
        $population.Add([ordered]@{ dn = $dn; account = $sam; attribute = $true; retrievers = @($all.ToArray() | Select-Object -First 50) })
      }
      if ($matched.Count -eq 0) { continue }
      $count++
      if ($hits.Count -lt $limit) {
        $hits.Add([ordered]@{
            dn = $dn
            account = $sam
            matched = $matched.ToArray()
            # TODOS los recuperadores, no solo los que casan: para decidir si un
            # hallazgo es legitimo hay que ver la lista entera.
            retrievers = @($all.ToArray() | Select-Object -First 50)
          })
      }
    }
  } finally {
    $found.Dispose()
  }

  $readable = $seen - $withoutAttribute
  return [ordered]@{
    found = $true
    count = $count
    sample = $hits.ToArray()
    truncated = ($count -gt $hits.Count)
    objectsScanned = $seen
    withoutAttribute = $withoutAttribute
    aceCount = $aceCount
    retrieversSeen = $retrieversSeen.Count
    population = $population.ToArray()
    unreadable = $(if ($seen -gt 0 -and $readable -eq 0) { $seen } else { 0 })
  }
}

# Metadata de replicacion de AD. Responde "cambio hace poco?", que ningun otro
# tipo de consulta nuestro puede preguntar, y lo hace por LDAP plano: son dos
# atributos CONSTRUIDOS que hay que pedir por nombre.
#
#   scope 'attribute' -> msDS-ReplAttributeMetaData: una entrada por atributo,
#                        con la ultima escritura, su version y el DC de origen.
#   scope 'value'     -> msDS-ReplValueMetaData: una entrada por VALOR de un
#                        atributo enlazado (member), con cuando se anadio y
#                        cuando se borro. Es lo que permite decir "quien entro
#                        en Domain Admins esta semana" sin logs de eventos.
#
# ⚠️ El caso que importa no es el hallazgo: es el SILENCIO. Si el atributo no
# vuelve, "no cambio nada" y "no puedo leer la metadata" son indistinguibles, y
# el segundo se leeria como pass. Por eso cada objeto reporta `readable`, y el
# recuento de ilegibles sube al resultado: el evaluador saca not_assessed, no
# pass. Es la leccion del 26-sep con las plantillas de certificado.
function AspReplMetadata($query, $ctx, [int]$limit) {
  $attrName = if ([string]$query.scope -eq 'value') { 'msDS-ReplValueMetaData' } else { 'msDS-ReplAttributeMetaData' }
  $wanted = @($query.attributes | ForEach-Object { ([string]$_).ToLowerInvariant() })
  $cutoff = [DateTime]::UtcNow.AddDays(-1 * [double][int]$query.withinDays)
  $hits = New-Object System.Collections.Generic.List[object]
  $count = 0
  $scanned = 0
  # ⚠️ Dos ausencias que NO son lo mismo:
  #   notFound   -> el objeto no esta aqui. Enterprise Admins y Schema Admins
  #                 viven en la raiz del bosque, asi que en un dominio hijo no
  #                 existen y eso es NORMAL.
  #   unreadable -> el objeto se lee pero su metadata no vuelve. Eso SI es
  #                 ceguera, y no puede leerse como "sin cambios".
  $notFound = New-Object System.Collections.Generic.List[string]
  $unreadable = New-Object System.Collections.Generic.List[string]
  # ⚠️ CONTROL POSITIVO. `count = 0` con `unreadable = 0` puede ser "no cambio
  # nada" o "no parsee ni una entrada": las dos cosas se leen igual. Estos dos
  # contadores lo separan, y `lastWrite` ademas es informacion util por si sola
  # -- "el DACL de AdminSDHolder se toco por ultima vez en 2019" le dice algo a
  # un auditor, y "0" no.
  $entriesSeen = 0
  $lastWrite = [ordered]@{}

  foreach ($rawDn in @($query.dns)) {
    $dn = AspExpand ([string]$rawDn) $ctx
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = AspEntry $dn
    $searcher.Filter = '(objectClass=*)'
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
    [void]$searcher.PropertiesToLoad.Add($attrName)
    $r = $null
    try {
      $r = $searcher.FindOne()
    } catch {
      if (AspIsNoSuchObject $_) { $notFound.Add([string]$rawDn); continue }
      throw
    }
    if ($null -eq $r) { $notFound.Add([string]$rawDn); continue }
    $scanned++
    $key = $attrName.ToLowerInvariant()
    if (-not $r.Properties.Contains($key) -or $r.Properties[$key].Count -eq 0) {
      # El objeto se lee pero su metadata no viene: NO es "sin cambios".
      $unreadable.Add([string]$rawDn)
      continue
    }
    $parsedHere = 0
    foreach ($xml in $r.Properties[$key]) {
      $node = $null
      try { $node = ([xml]([string]$xml)).DocumentElement } catch { continue }
      if ($null -eq $node) { continue }
      $entriesSeen++
      $parsedHere++
      $name = ([string]$node.pszAttributeName).ToLowerInvariant()
      if ($wanted -notcontains $name) { continue }
      # La escritura mas reciente de este atributo, SIN la ventana: es lo que
      # prueba que la cadena entera (peticion, XML, nombre, fecha) funciona.
      $seenAt = if ([string]$query.scope -eq 'value') {
        $c = AspReplTime $node.ftimeCreated; $d = AspReplTime $node.ftimeDeleted
        if ($null -ne $d -and ($null -eq $c -or $d -gt $c)) { $d } else { $c }
      } else {
        AspReplTime $node.ftimeLastOriginatingChange
      }
      if ($null -ne $seenAt) {
        $key = [string]$node.pszAttributeName
        if (-not $lastWrite.Contains($key) -or ([DateTime]$lastWrite[$key]) -lt $seenAt) {
          $lastWrite[$key] = $seenAt
        }
      }
      if ([string]$query.scope -eq 'value') {
        # ftimeDeleted de un valor vivo es el FILETIME cero (1601-01-01): eso NO
        # es una baja. Distinguirlo es la diferencia entre "entro alguien" y
        # "salio alguien".
        $created = AspReplTime $node.ftimeCreated
        $deleted = AspReplTime $node.ftimeDeleted
        $action = $null
        $when = $null
        if ($null -ne $deleted -and $deleted -gt $cutoff) { $action = 'removed'; $when = $deleted }
        elseif ($null -ne $created -and $created -gt $cutoff) { $action = 'added'; $when = $created }
        if ($null -eq $action) { continue }
        $count++
        if ($hits.Count -lt $limit) {
          $hits.Add([ordered]@{
              attribute = [string]$node.pszAttributeName
              action = $action
              changedAt = $when.ToString('o')
              objectDn = [string]$node.pszObjectDn
              originatingDc = (AspReplDsa $node.pszLastOriginatingDsaDN)
            })
        }
      } else {
        $when = AspReplTime $node.ftimeLastOriginatingChange
        if ($null -eq $when -or $when -le $cutoff) { continue }
        $count++
        if ($hits.Count -lt $limit) {
          $hits.Add([ordered]@{
              attribute = [string]$node.pszAttributeName
              action = 'written'
              changedAt = $when.ToString('o')
              objectDn = $dn
              version = [int]$node.dwVersion
              originatingDc = (AspReplDsa $node.pszLastOriginatingDsaDN)
            })
        }
      }
    }
    # El atributo vino con valores y no se parseo NI UNA entrada: no es "sin
    # cambios", es que la cadena esta rota. Va a `unreadable` para que el
    # evaluador lo saque como not_assessed con el guardia que ya existe, en vez
    # de inventar un caso especial.
    if ($parsedHere -eq 0) { $unreadable.Add([string]$rawDn) }
  }
  return [ordered]@{
    count = $count
    sample = $hits.ToArray()
    truncated = ($count -gt $hits.Count)
    objectsScanned = $scanned
    entriesSeen = $entriesSeen
    lastWrite = (& {
        $o = [ordered]@{}
        foreach ($k in $lastWrite.Keys) { $o[$k] = ([DateTime]$lastWrite[$k]).ToString('o') }
        $o
      })
    notFound = $notFound.Count
    unreadable = $unreadable.Count
    unreadableSample = @($unreadable | Select-Object -First 8)
  }
}

# El FILETIME cero de AD llega como 1601-01-01 o como la cadena vacia: las dos
# significan "nunca", no "hace mucho".
function AspReplTime($raw) {
  $text = [string]$raw
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }
  $parsed = [DateTime]::MinValue
  if (-not [DateTime]::TryParse($text, [ref]$parsed)) { return $null }
  $utc = $parsed.ToUniversalTime()
  if ($utc.Year -le 1601) { return $null }
  return $utc
}

# "CN=NTDS Settings,CN=MSIG-DOMAIN01,CN=Servers,..." -> "MSIG-DOMAIN01". Quien
# escribio importa; el DN entero es ruido en una evidencia.
function AspReplDsa($raw) {
  $parts = ([string]$raw) -split ','
  if ($parts.Count -ge 2) { return ($parts[1] -replace '^CN=', '') }
  return [string]$raw
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
      'owner_search' { AspOwnerSearch $q $ctx $limit }
      'rootdse' { AspRootDse $q }
      'sysvol_files' { AspSysvolFiles $q $ctx $limit }
      'registry' { AspRegistry $q }
      'repl_metadata' { AspReplMetadata $q $ctx $limit }
      'adcs_templates' { AspAdcsTemplates $q $ctx $limit }
      'gmsa_retrievers' { AspGmsaRetrievers $q $ctx $limit }
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
