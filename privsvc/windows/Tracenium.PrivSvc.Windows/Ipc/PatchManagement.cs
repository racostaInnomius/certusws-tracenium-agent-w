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
}
