# test/privsvc/fixtures/wua-fake-harness.ps1
#
# Runs the Windows patch-install script (extracted from PatchManagement.cs)
# against fakes of the three WUA COM objects it touches, and prints what an
# operator would get back. `New-Object` is shadowed so the script's own
# `New-Object -ComObject Microsoft.Update.*` calls land on the fakes.
#
# Scenarios:
#   mixed          KB5066747 never downloads; KB5120708 installs (reboot);
#                  KB5121003 fails to install with 0x80070643
#   reboot-pending WUA reports a reboot pending from an earlier change
#   all-ok         everything downloads and installs
#   search-throws  Search() throws 0x80070422 (Windows Update service disabled)
#   download-throws Download() throws 0x80070070 (disk full)
#   install-throws Install() throws 0x80240016 (another install in progress)
#   installer-busy IUpdateInstaller.IsBusy is true
param([string]$Scenario, [string]$ScriptPath)

# Fakes for the three WUA COM objects the install script touches.
class FakeColl {
  [System.Collections.ArrayList]$items = @()
  [int]$Count = 0
  [void]Add($u) { $this.items.Add($u) | Out-Null; $this.Count = $this.items.Count }
  [object]Item([int]$i) { return $this.items[$i] }
}

function New-FakeUpdate([string]$kb, [string]$title) {
  $u = [pscustomobject]@{
    Title = $title
    KBArticleIDs = @($kb.Replace('KB',''))
    Categories = @([pscustomobject]@{ Name = 'Security Updates' })
    Identity = [pscustomobject]@{ UpdateID = "id-$kb"; RevisionNumber = 1 }
    IsDownloaded = $false
    RebootRequired = $false
    EulaAccepted = $true
  }
  $u | Add-Member -MemberType ScriptMethod -Name AcceptEula -Value { }
  return $u
}

$script:Calls = [System.Collections.ArrayList]@()
$script:Updates = @(
  (New-FakeUpdate 'KB5066747' '.NET cumulative'),
  (New-FakeUpdate 'KB5120708' '.NET 4.8.1 cumulative'),
  (New-FakeUpdate 'KB5121003' 'Windows 11 cumulative')
)

# Scenario knobs
$script:DownloadOk = @{ KB5066747 = $false; KB5120708 = $true; KB5121003 = $true }
$script:InstallCode = @{ KB5120708 = 2; KB5121003 = 4 }   # OperationResultCode
$script:InstallHResult = @{ KB5120708 = 0; KB5121003 = -2147023293 } # 0x80070643
$script:RebootPending = $false
$script:Throw = @{}
$script:Busy = $false
switch ($Scenario) {
  'search-throws' { $script:Throw.Search = -2147023838 }        # 0x80070422
  'download-throws' { $script:Throw.Download = -2147024784 }    # 0x80070070
  'install-throws' { $script:DownloadOk = @{ KB5066747 = $true; KB5120708 = $true; KB5121003 = $true }; $script:Throw.Install = -2145124330 } # 0x80240016
  'installer-busy' { $script:DownloadOk = @{ KB5066747 = $true; KB5120708 = $true; KB5121003 = $true }; $script:Busy = $true }
  'reboot-pending' { $script:DownloadOk = @{ KB5066747 = $true; KB5120708 = $true; KB5121003 = $true }; $script:RebootPending = $true }
  'all-ok' { $script:DownloadOk = @{ KB5066747 = $true; KB5120708 = $true; KB5121003 = $true }; $script:InstallCode = @{ KB5066747 = 2; KB5120708 = 2; KB5121003 = 3 }; $script:InstallHResult = @{} }
}

function New-Downloader {
  $d = [pscustomobject]@{ Updates = $null; perUpdate = @() }
  $d | Add-Member -MemberType ScriptMethod -Name Download -Value {
    $script:Calls.Add('Download') | Out-Null
    if ($script:Throw.Download) { throw [System.Runtime.InteropServices.COMException]::new('Exception from HRESULT', [int]$script:Throw.Download) }
    $this.perUpdate = @()
    for ($i = 0; $i -lt $this.Updates.Count; $i++) {
      $u = $this.Updates.Item($i)
      $kb = 'KB' + $u.KBArticleIDs[0]
      $ok = $script:DownloadOk[$kb]
      $u.IsDownloaded = $ok
      $this.perUpdate += [pscustomobject]@{ HResult = $(if ($ok) { 0 } else { -2145107934 }); ResultCode = $(if ($ok) { 2 } else { 4 }) } # 0x80246022-ish
    }
    $r = [pscustomobject]@{ HResult = $(if ($this.perUpdate.HResult -contains 0 -and $this.perUpdate.Count -eq ($this.perUpdate | ? HResult -eq 0).Count) { 0 } else { -2145107934 }); ResultCode = 3; per = $this.perUpdate }
    $r | Add-Member -MemberType ScriptMethod -Name GetUpdateResult -Value { param($i) return $this.per[$i] }
    return $r
  }
  return $d
}

function New-Installer {
  $inst = [pscustomobject]@{ Updates = $null; RebootRequiredBeforeInstallation = $script:RebootPending; IsBusy = $script:Busy }
  $inst | Add-Member -MemberType ScriptMethod -Name Install -Value {
    $script:Calls.Add('Install:' + (@(0..($this.Updates.Count-1) | % { 'KB' + $this.Updates.Item($_).KBArticleIDs[0] }) -join ',')) | Out-Null
    if ($script:Throw.Install) { throw [System.Runtime.InteropServices.COMException]::new('Exception from HRESULT', [int]$script:Throw.Install) }
    $per = @()
    for ($j = 0; $j -lt $this.Updates.Count; $j++) {
      $kb = 'KB' + $this.Updates.Item($j).KBArticleIDs[0]
      $code = $script:InstallCode[$kb]; if ($null -eq $code) { $code = 0 }
      $hr = $script:InstallHResult[$kb]; if ($null -eq $hr) { $hr = 0 }
      $per += [pscustomobject]@{ ResultCode = $code; HResult = $hr; RebootRequired = ($code -eq 2 -and $kb -eq 'KB5120708') }
    }
    $r = [pscustomobject]@{ HResult = 0; RebootRequired = $false; per = $per }
    $r | Add-Member -MemberType ScriptMethod -Name GetUpdateResult -Value { param($j) return $this.per[$j] }
    return $r
  }
  return $inst
}

$script:Session = [pscustomobject]@{}
$script:Session | Add-Member -MemberType ScriptMethod -Name CreateUpdateSearcher -Value {
  $s = [pscustomobject]@{}
  $s | Add-Member -MemberType ScriptMethod -Name Search -Value {
    param($q)
    if ($script:Throw.Search) { throw [System.Runtime.InteropServices.COMException]::new('Exception from HRESULT', [int]$script:Throw.Search) }
    return [pscustomobject]@{ Updates = $script:Updates }
  }
  return $s
}
$script:Session | Add-Member -MemberType ScriptMethod -Name CreateUpdateDownloader -Value { return (New-Downloader) }
$script:Session | Add-Member -MemberType ScriptMethod -Name CreateUpdateInstaller -Value { return (New-Installer) }

function New-Object {
  param([string]$TypeName, [string]$ComObject, [object[]]$ArgumentList)
  if ($ComObject -eq 'Microsoft.Update.Session') { return $script:Session }
  if ($ComObject -eq 'Microsoft.Update.UpdateColl') { return [FakeColl]::new() }
  Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}

$json = (. $ScriptPath) | Out-String
$obj = $json | ConvertFrom-Json
[pscustomobject]@{
  scenario = $Scenario
  calls = @($script:Calls)
  status = $obj.status
  installedCount = $obj.installedCount
  failedCount = $obj.failedCount
  rebootRequired = $obj.rebootRequired
  fatalStage = $obj.fatalStage
  hresult = $obj.hresult
  results = @($obj.results | % { "$($_.kb) $($_.result) $($_.hresult) $($_.message)" })
} | ConvertTo-Json -Depth 5
