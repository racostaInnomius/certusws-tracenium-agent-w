using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class PatchManagement
{
    public static Task<PrivSvcResponse> HandleScan(PrivSvcRequest req)
    {
        try
        {
            var output = RunPs(@"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search(""IsInstalled=0 and IsHidden=0 and Type='Software'"")
$items = @()
foreach ($update in $result.Updates) {
  $categories = @()
  foreach ($cat in $update.Categories) {
    if ($cat -and $cat.Name) { $categories += [string]$cat.Name }
  }

  $kbs = @()
  foreach ($kb in $update.KBArticleIDs) {
    if ($kb) { $kbs += ('KB' + [string]$kb) }
  }

  $items += [pscustomobject]@{
    updateId = try { [string]$update.Identity.UpdateID } catch { $null }
    revisionNumber = try { [int]$update.Identity.RevisionNumber } catch { $null }
    title = [string]$update.Title
    description = [string]$update.Description
    msrcSeverity = try { [string]$update.MsrcSeverity } catch { $null }
    kbArticleIds = $kbs
    categories = $categories
    isDownloaded = [bool]$update.IsDownloaded
    isMandatory = [bool]$update.IsMandatory
    rebootRequired = [bool]$update.RebootRequired
    eulaAccepted = [bool]$update.EulaAccepted
    supportUrl = try { [string]$update.SupportUrl } catch { $null }
  }
}

$securityItems = @($items | Where-Object {
  ($_.categories -contains 'Security Updates') -or
  ($_.categories -contains 'Critical Updates') -or
  ($_.msrcSeverity -and $_.msrcSeverity -ne '')
})

[pscustomobject]@{
  status = if ($items.Count -gt 0) { 'updates_available' } else { 'healthy' }
  source = 'windows_update_agent'
  scannedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
  updateCount = $items.Count
  securityUpdateCount = $securityItems.Count
  items = $items
} | ConvertTo-Json -Depth 8
");

            if (string.IsNullOrWhiteSpace(output))
            {
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new
                {
                    status = "unknown",
                    source = "windows_update_agent",
                    scannedAtUtc = DateTime.UtcNow.ToString("O"),
                    updateCount = 0,
                    securityUpdateCount = 0,
                    items = Array.Empty<object>()
                }));
            }

            using var doc = JsonDocument.Parse(output);
            var result = JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText());

            return Task.FromResult(PrivSvcResponse.Success(req.Id, result ?? new
            {
                status = "unknown",
                source = "windows_update_agent",
                scannedAtUtc = DateTime.UtcNow.ToString("O"),
                updateCount = 0,
                securityUpdateCount = 0,
                items = Array.Empty<object>()
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "patch_scan_error", ex.Message)
            );
        }
    }

    public static Task<PrivSvcResponse> HandleInstall(PrivSvcRequest req)
    {
        try
        {
            var parameters = req.Params ?? new Dictionary<string, object>();
            var mode = GetString(parameters, "mode")?.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(mode))
            {
                mode = "install";
            }

            if (mode != "install" && mode != "download")
            {
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "patch_install_invalid_mode", "mode must be install or download")
                );
            }

            var kbArticleIds = GetStringArray(parameters, "kbArticleIds");
            var modeJson = JsonSerializer.Serialize(mode);

            var output = RunPs($@"
$mode = {modeJson}
$targetKbs = @({string.Join(",", kbArticleIds.Select(kb => JsonSerializer.Serialize(kb)))})
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$searchResult = $searcher.Search(""IsInstalled=0 and IsHidden=0 and Type='Software'"")
$updates = New-Object -ComObject Microsoft.Update.UpdateColl
$selected = @()

foreach ($update in $searchResult.Updates) {{
  $categories = @()
  foreach ($cat in $update.Categories) {{
    if ($cat -and $cat.Name) {{ $categories += [string]$cat.Name }}
  }}

  $kbs = @()
  foreach ($kb in $update.KBArticleIDs) {{
    if ($kb) {{ $kbs += ('KB' + [string]$kb) }}
  }}

  $matchesKb = ($targetKbs.Count -eq 0)
  if (-not $matchesKb) {{
    foreach ($candidate in $kbs) {{
      if ($targetKbs -contains $candidate) {{
        $matchesKb = $true
        break
      }}
    }}
  }}

  if (-not $matchesKb) {{ continue }}

  if (-not $update.EulaAccepted) {{
    try {{ $update.AcceptEula() }} catch {{}}
  }}

  [void]$updates.Add($update)
  $selected += [pscustomobject]@{{
    updateId = try {{ [string]$update.Identity.UpdateID }} catch {{ $null }}
    revisionNumber = try {{ [int]$update.Identity.RevisionNumber }} catch {{ $null }}
    title = [string]$update.Title
    kbArticleIds = $kbs
    categories = $categories
    isDownloaded = [bool]$update.IsDownloaded
    rebootRequired = [bool]$update.RebootRequired
  }}
}}

if ($updates.Count -eq 0) {{
  [pscustomobject]@{{
    status = 'no_updates'
    mode = $mode
    source = 'windows_update_agent'
    startedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    finishedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    selectedCount = 0
    installedCount = 0
    failedCount = 0
    rebootRequired = $false
    results = @()
    selected = @()
  }} | ConvertTo-Json -Depth 8
  return
}}

$startedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
$results = @()
$rebootRequired = $false
$installedCount = 0
$failedCount = 0
$downloadedCount = 0

if ($mode -eq 'download' -or $mode -eq 'install') {{
  $downloader = $session.CreateUpdateDownloader()
  $downloader.Updates = $updates
  $downloadResult = $downloader.Download()

  for ($i = 0; $i -lt $updates.Count; $i++) {{
    $update = $updates.Item($i)
    $kbs = @()
    foreach ($kb in $update.KBArticleIDs) {{
      if ($kb) {{ $kbs += ('KB' + [string]$kb) }}
    }}

    $downloaded = [bool]$update.IsDownloaded
    if ($downloaded) {{ $downloadedCount++ }}

    $results += [pscustomobject]@{{
      updateId = try {{ [string]$update.Identity.UpdateID }} catch {{ $null }}
      kb = if ($kbs.Count -gt 0) {{ $kbs[0] }} else {{ $null }}
      title = [string]$update.Title
      result = if ($downloaded) {{ 'downloaded' }} else {{ 'failed' }}
      hresult = try {{ ('0x' + [Convert]::ToString([int]$downloadResult.HResult, 16)) }} catch {{ $null }}
      message = if ($downloaded) {{ 'downloaded' }} else {{ 'download_failed' }}
    }}
  }}
}}

if ($mode -eq 'install') {{
  $installer = $session.CreateUpdateInstaller()
  $installer.Updates = $updates
  $installResult = $installer.Install()

  $results = @()
  for ($i = 0; $i -lt $updates.Count; $i++) {{
    $update = $updates.Item($i)
    $updateResult = $installResult.GetUpdateResult($i)
    $kbs = @()
    foreach ($kb in $update.KBArticleIDs) {{
      if ($kb) {{ $kbs += ('KB' + [string]$kb) }}
    }}

    $code = [int]$updateResult.ResultCode
    $mappedResult = switch ($code) {{
      2 {{ 'installed' }}
      3 {{ 'installed' }}
      4 {{ 'failed' }}
      5 {{ 'failed' }}
      default {{ 'skipped' }}
    }}

    if ($mappedResult -eq 'installed') {{ $installedCount++ }} else {{ $failedCount++ }}
    if ([bool]$updateResult.RebootRequired -or [bool]$installResult.RebootRequired) {{ $rebootRequired = $true }}

    $results += [pscustomobject]@{{
      updateId = try {{ [string]$update.Identity.UpdateID }} catch {{ $null }}
      kb = if ($kbs.Count -gt 0) {{ $kbs[0] }} else {{ $null }}
      title = [string]$update.Title
      result = $mappedResult
      hresult = try {{ ('0x' + [Convert]::ToString([int]$updateResult.HResult, 16)) }} catch {{ $null }}
      message = try {{ [string]$updateResult.ResultCode }} catch {{ $null }}
    }}
  }}
}}

$status = if ($mode -eq 'download') {{
  if ($downloadedCount -eq $updates.Count) {{ 'success' }} elseif ($downloadedCount -gt 0) {{ 'partial' }} else {{ 'failed' }}
}} else {{
  if ($failedCount -eq 0) {{ 'success' }} elseif ($installedCount -gt 0) {{ 'partial' }} else {{ 'failed' }}
}}

[pscustomobject]@{{
  status = $status
  mode = $mode
  source = 'windows_update_agent'
  startedAtUtc = $startedAtUtc
  finishedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
  selectedCount = $updates.Count
  installedCount = if ($mode -eq 'download') {{ $downloadedCount }} else {{ $installedCount }}
  failedCount = if ($mode -eq 'download') {{ [Math]::Max($updates.Count - $downloadedCount, 0) }} else {{ $failedCount }}
  rebootRequired = [bool]$rebootRequired
  results = $results
  selected = $selected
}} | ConvertTo-Json -Depth 8
");

            if (string.IsNullOrWhiteSpace(output))
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "patch_install_error", "empty_response"));
            }

            using var doc = JsonDocument.Parse(output);
            var result = JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText());
            return Task.FromResult(PrivSvcResponse.Success(req.Id, result!));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "patch_install_error", ex.Message)
            );
        }
    }

    private static string RunPs(string command)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        var psi = new ProcessStartInfo("powershell",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        if (proc == null) return "";

        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();

        proc.WaitForExit(30000);

        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Console.WriteLine($"[PrivSvc][PatchManagement] PowerShell stderr: {stderr}");
        }

        return stdout;
    }

    private static string? GetString(Dictionary<string, object> obj, string key)
    {
        if (!obj.TryGetValue(key, out var value) || value == null) return null;
        if (value is JsonElement el)
        {
            if (el.ValueKind == JsonValueKind.String) return el.GetString();
            return el.ToString();
        }
        return value.ToString();
    }

    private static List<string> GetStringArray(Dictionary<string, object> obj, string key)
    {
        if (!obj.TryGetValue(key, out var value) || value == null) return new List<string>();

        if (value is JsonElement el)
        {
            if (el.ValueKind == JsonValueKind.Array)
            {
                return el.EnumerateArray()
                    .Where(item => item.ValueKind == JsonValueKind.String)
                    .Select(item => (item.GetString() ?? "").Trim())
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            if (el.ValueKind == JsonValueKind.String)
            {
                var single = (el.GetString() ?? "").Trim();
                return string.IsNullOrWhiteSpace(single)
                    ? new List<string>()
                    : new List<string> { single };
            }
        }

        if (value is IEnumerable<object> enumerable)
        {
            return enumerable
                .Select(item => item?.ToString()?.Trim() ?? "")
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        var text = value.ToString()?.Trim();
        return string.IsNullOrWhiteSpace(text)
            ? new List<string>()
            : new List<string> { text };
    }
}
