# test/privsvc/fixtures/wua-scan-harness.ps1
#
# Runs the Windows patch-SCAN script (extracted from PatchManagement.cs)
# against fakes of the WUA COM objects it touches and prints status + note.
#
# Scenarios:
#   clean          search returns nothing, catalogue synced 1 day ago → healthy
#   search-throws  Search() throws 0x8024401c (WSUS unreachable), catalogue
#                  synced 1 day ago → must NOT be healthy
param([string]$Scenario, [string]$ScriptPath)

$script:SearchThrows = ($Scenario -eq 'search-throws')

$script:Session = [pscustomobject]@{}
$script:Session | Add-Member -MemberType ScriptMethod -Name CreateUpdateSearcher -Value {
  $s = [pscustomobject]@{ Online = $true }
  $s | Add-Member -MemberType ScriptMethod -Name Search -Value {
    param($q)
    if ($script:SearchThrows) { throw [System.Runtime.InteropServices.COMException]::new('Exception from HRESULT', -2145107940) } # 0x8024401c
    return [pscustomobject]@{ Updates = @() }
  }
  return $s
}

function New-Object {
  param([string]$TypeName, [string]$ComObject, [object[]]$ArgumentList)
  if ($ComObject -eq 'Microsoft.Update.Session') { return $script:Session }
  if ($ComObject -eq 'Microsoft.Update.AutoUpdate') {
    return [pscustomobject]@{ Results = [pscustomobject]@{ LastSearchSuccessDate = (Get-Date).AddDays(-1) } }
  }
  if ($ComObject -eq 'Microsoft.Update.SystemInfo') { return [pscustomobject]@{ RebootRequired = $false } }
  Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}

$obj = ((. $ScriptPath) | Out-String) | ConvertFrom-Json
[pscustomobject]@{ status = $obj.status; note = $obj.note; updateCount = $obj.updateCount } | ConvertTo-Json
