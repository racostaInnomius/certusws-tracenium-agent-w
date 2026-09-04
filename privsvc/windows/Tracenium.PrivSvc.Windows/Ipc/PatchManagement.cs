using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class PatchManagement
{
    // Scan timeout: 60s. Windows Update Agent Search() is usually
    // 5-15s on a healthy host; 60s covers a slow WSUS round-trip
    // or a host that hasn't pinged Microsoft in months and needs to
    // refresh the metadata catalog before searching.
    // 150s, raised from 60s on 2026-08-18. Four servers in one tenant hit the
    // 60s ceiling on the very first scan that PowerShell was able to run: a
    // WSUS-backed search on a domain controller routinely needs minutes, not
    // seconds. Kept well under the client's budget because the Windows IPC
    // lane is strictly serial — a scan holding the lane blocks everything
    // behind it, so this is a ceiling, not a target.
    private const int ScanTimeoutMs = 150_000;

    // Install timeout: 90 min. Covers the worst common case (kernel
    // + .NET runtime + servicing-stack update in a single batch,
    // with download from a cold cache). Anything longer is almost
    // always WUA wedged on its own (e.g., Component-Based-Servicing
    // store corruption) and Kill-ing is the safe action — the next
    // scan will surface "this update is still pending" and the
    // operator can investigate locally.
    private const int InstallTimeoutMs = 90 * 60_000;

    public static Task<PrivSvcResponse> HandleScan(PrivSvcRequest req)
    {
        try
        {
            var psResult = RunPs(@"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()

# Search the catalogue Windows already synced instead of going out to
# WSUS on every scan. An online search is a network round trip against
# the update server; on a domain controller with a large catalogue it
# runs for MINUTES. Four servers in one tenant blew a 60s ceiling, then
# a 150s one, doing nothing but waiting on WSUS. Raising the ceiling
# again would only hold the serial IPC lane hostage for longer.
#
# The OS syncs this catalogue on its own AU/WSUS schedule, so a cached
# search returns the same pending set as the last sync -- which is what
# an inventory pass wants, and what other inventory tools use.
$searcher.Online = $false

# When that sync last succeeded. Without it a cached search on a machine
# that has NEVER synced returns zero updates, and zero is exactly what a
# perfectly patched machine returns -- the false-healthy trap this
# plugin has already been caught by twice.
$lastSyncUtc = $(try {
  $au = New-Object -ComObject Microsoft.Update.AutoUpdate
  $d = $au.Results.LastSearchSuccessDate
  if ($d) { $d.ToUniversalTime() } else { $null }
} catch { $null })

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
    updateId = $(try { [string]$update.Identity.UpdateID } catch { $null })
    revisionNumber = $(try { [int]$update.Identity.RevisionNumber } catch { $null })
    title = [string]$update.Title
    description = [string]$update.Description
    msrcSeverity = $(try { [string]$update.MsrcSeverity } catch { $null })
    kbArticleIds = $kbs
    categories = $categories
    isDownloaded = [bool]$update.IsDownloaded
    isMandatory = [bool]$update.IsMandatory
    rebootRequired = [bool]$update.RebootRequired
    eulaAccepted = [bool]$update.EulaAccepted
    supportUrl = $(try { [string]$update.SupportUrl } catch { $null })
  }
}

$securityItems = @($items | Where-Object {
  ($_.categories -contains 'Security Updates') -or
  ($_.categories -contains 'Critical Updates') -or
  ($_.msrcSeverity -and $_.msrcSeverity -ne '')
})

# A cached catalogue older than this is treated as no answer at all.
# Seven days is well past any normal AU/WSUS cadence, so crossing it
# means the machine stopped talking to its update server.
$staleAfterDays = 7
$syncAgeDays = $(if ($lastSyncUtc) {
  ((Get-Date).ToUniversalTime() - $lastSyncUtc).TotalDays
} else { $null })
$catalogUsable = $(if ($syncAgeDays -eq $null) { $false } else { $syncAgeDays -le $staleAfterDays })

# Zero pending updates only means 'healthy' when the catalogue behind
# that zero is trustworthy. Otherwise say 'unknown' and explain why --
# an honest gap beats a green row that nobody will look at again.
$scanStatus = $(if ($items.Count -gt 0) {
  'updates_available'
} elseif ($catalogUsable) {
  'healthy'
} else {
  'unknown'
})

$scanNote = $(if ($catalogUsable) {
  $null
} elseif ($lastSyncUtc) {
  'Windows Update last synced ' + [int]$syncAgeDays + ' days ago; cached catalogue is stale, so a count of 0 is not evidence the machine is patched.'
} else {
  'Windows Update has no record of a successful sync, so the cached catalogue cannot be trusted; a count of 0 is not evidence the machine is patched.'
})

[pscustomobject]@{
  source = 'windows_update_agent'
  scannedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
  updateCount = $items.Count
  securityUpdateCount = $securityItems.Count
  searchMode = 'cached'
  lastSyncUtc = $(if ($lastSyncUtc) { $lastSyncUtc.ToString('o') } else { $null })
  status = $scanStatus
  note = $scanNote
  items = $items
} | ConvertTo-Json -Depth 8
", ScanTimeoutMs);

            // Timeout, kill, OR PowerShell wrote nothing to stdout
            // (defensive — should always have at least the JSON).
            if (psResult.TimedOut)
            {
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "patch_scan_timeout",
                        $"Windows Update scan exceeded {ScanTimeoutMs / 1000}s. " +
                        $"stderr_tail: {Tail(psResult.Stderr, 500)}")
                );
            }

            if (string.IsNullOrWhiteSpace(psResult.Stdout))
            {
                // Treat empty-stdout as "unknown" rather than failure
                // — preserves pre-hardening behavior on the rare case
                // where WUA returns no items AND no errors. Stderr
                // (if any) goes into a soft note for the operator.
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new
                {
                    status = "unknown",
                    source = "windows_update_agent",
                    scannedAtUtc = DateTime.UtcNow.ToString("O"),
                    updateCount = 0,
                    securityUpdateCount = 0,
                    items = Array.Empty<object>(),
                    note = string.IsNullOrWhiteSpace(psResult.Stderr)
                        ? null
                        : $"empty_stdout; stderr_tail: {Tail(psResult.Stderr, 200)}"
                }));
            }

            // Defensive JSON parse — if PowerShell threw mid-script
            // we may get partial JSON or a thrown exception trace
            // instead of ConvertTo-Json output. Return that raw text
            // (truncated) as an error so the agent + backend can see
            // the actual diagnostic instead of "scan failed: Unexpected
            // character at line 1, column 1".
            try
            {
                using var doc = JsonDocument.Parse(psResult.Stdout);
                var result = JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText());
                return Task.FromResult(PrivSvcResponse.Success(req.Id, result!));
            }
            catch (JsonException jex)
            {
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "patch_scan_invalid_json",
                        $"{jex.Message} | exit_code={psResult.ExitCode} | " +
                        $"stdout_head: {Head(psResult.Stdout, 300)} | " +
                        $"stderr_tail: {Tail(psResult.Stderr, 300)}")
                );
            }
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

            var psResult = RunPs($@"
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
    updateId = $(try {{ [string]$update.Identity.UpdateID }} catch {{ $null }})
    revisionNumber = $(try {{ [int]$update.Identity.RevisionNumber }} catch {{ $null }})
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

function Format-HResult($value) {{
  try {{ '0x' + [Convert]::ToString([int]$value, 16) }} catch {{ $null }}
}}

# OperationResultCode, by name. The bare number ('4') was all the operator
# used to get for a failed install.
function Get-ResultCodeName($code) {{
  switch ([int]$code) {{
    0 {{ 'not_started' }}
    1 {{ 'in_progress' }}
    2 {{ 'succeeded' }}
    3 {{ 'succeeded_with_errors' }}
    4 {{ 'failed' }}
    5 {{ 'aborted' }}
    default {{ 'unknown_' + [string]$code }}
  }}
}}

function Get-KbList($update) {{
  $kbs = @()
  foreach ($kb in $update.KBArticleIDs) {{
    if ($kb) {{ $kbs += ('KB' + [string]$kb) }}
  }}
  return ,$kbs
}}

# Per-update verdicts of the DOWNLOAD phase, indexed like $updates. In
# install mode these are the final verdict for anything that did not come
# down, and the install phase only runs on what did.
$downloadVerdicts = @()

if ($mode -eq 'download' -or $mode -eq 'install') {{
  $downloader = $session.CreateUpdateDownloader()
  $downloader.Updates = $updates
  $downloadResult = $downloader.Download()

  for ($i = 0; $i -lt $updates.Count; $i++) {{
    $update = $updates.Item($i)
    $kbs = Get-KbList $update

    $downloaded = [bool]$update.IsDownloaded
    if ($downloaded) {{ $downloadedCount++ }}

    # IDownloadResult.GetUpdateResult(i) carries the per-update HResult
    # and ResultCode; the aggregate HResult is the fallback.
    $perUpdate = $(try {{ $downloadResult.GetUpdateResult($i) }} catch {{ $null }})
    $dlHresult = $(try {{ if ($perUpdate) {{ [int]$perUpdate.HResult }} else {{ [int]$downloadResult.HResult }} }} catch {{ 0 }})
    $dlCode = $(try {{ if ($perUpdate) {{ [int]$perUpdate.ResultCode }} else {{ [int]$downloadResult.ResultCode }} }} catch {{ 0 }})

    $downloadVerdicts += [pscustomobject]@{{
      updateId = $(try {{ [string]$update.Identity.UpdateID }} catch {{ $null }})
      kb = if ($kbs.Count -gt 0) {{ $kbs[0] }} else {{ $null }}
      title = [string]$update.Title
      result = if ($downloaded) {{ 'downloaded' }} else {{ 'failed' }}
      hresult = Format-HResult $dlHresult
      message = if ($downloaded) {{ 'downloaded' }} else {{ 'download_failed:' + (Get-ResultCodeName $dlCode) }}
    }}
  }}

  $results = $downloadVerdicts
}}

if ($mode -eq 'install') {{
  # Until 2026-09-04 this phase threw the download verdicts away and
  # handed EVERY selected update to the installer, downloaded or not. WUA
  # refuses the ones that never came down with 0x80246007
  # (WU_E_DM_NOTDOWNLOADED), which is what the operator saw for KB5066747
  # on DESKTOP-M8GJ0V5 — a true statement that hid the actual failure,
  # whose HRESULT had just been overwritten.
  $results = @()
  $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
  $toInstallIndex = @()

  for ($i = 0; $i -lt $updates.Count; $i++) {{
    if ([bool]$updates.Item($i).IsDownloaded) {{
      [void]$toInstall.Add($updates.Item($i))
      $toInstallIndex += $i
    }} else {{
      $results += $downloadVerdicts[$i]
      $failedCount++
    }}
  }}

  if ($toInstall.Count -gt 0) {{
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $toInstall

    # WUA refuses everything while a reboot is pending. Say so per update
    # instead of letting each one fail with a generic HRESULT.
    $rebootPending = $(try {{ [bool]$installer.RebootRequiredBeforeInstallation }} catch {{ $false }})

    if ($rebootPending) {{
      $rebootRequired = $true
      for ($j = 0; $j -lt $toInstall.Count; $j++) {{
        $update = $toInstall.Item($j)
        $kbs = Get-KbList $update
        $failedCount++
        $results += [pscustomobject]@{{
          updateId = $(try {{ [string]$update.Identity.UpdateID }} catch {{ $null }})
          kb = if ($kbs.Count -gt 0) {{ $kbs[0] }} else {{ $null }}
          title = [string]$update.Title
          result = 'skipped'
          hresult = $null
          message = 'reboot_pending_before_install'
        }}
      }}
    }} else {{
      $installResult = $installer.Install()

      for ($j = 0; $j -lt $toInstall.Count; $j++) {{
        $update = $toInstall.Item($j)
        $updateResult = $installResult.GetUpdateResult($j)
        $kbs = Get-KbList $update

        $code = [int]$updateResult.ResultCode
        $mappedResult = switch ($code) {{
          2 {{ 'installed' }}
          3 {{ 'installed' }}
          4 {{ 'failed' }}
          5 {{ 'failed' }}
          default {{ 'skipped' }}
        }}

        # 'skipped' (not started / still in progress) is not installed, so
        # it counts against the job; what changes is that it now carries
        # the installer's overall HResult instead of a bare number.
        if ($mappedResult -eq 'installed') {{ $installedCount++ }} else {{ $failedCount++ }}
        if ([bool]$updateResult.RebootRequired -or [bool]$installResult.RebootRequired) {{ $rebootRequired = $true }}

        $perHresult = $(try {{ [int]$updateResult.HResult }} catch {{ 0 }})
        if ($mappedResult -eq 'skipped' -and $perHresult -eq 0) {{
          $perHresult = $(try {{ [int]$installResult.HResult }} catch {{ 0 }})
        }}

        $results += [pscustomobject]@{{
          updateId = $(try {{ [string]$update.Identity.UpdateID }} catch {{ $null }})
          kb = if ($kbs.Count -gt 0) {{ $kbs[0] }} else {{ $null }}
          title = [string]$update.Title
          result = $mappedResult
          hresult = Format-HResult $perHresult
          message = Get-ResultCodeName $code
        }}
      }}
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
", InstallTimeoutMs);

            // Timeout: WUA wedged or actually still running past 90
            // min. Either way, we don't have a useful result to ship
            // back. The next scan will surface real state (if updates
            // landed they show as installed; if not they're still in
            // the available list).
            if (psResult.TimedOut)
            {
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "patch_install_timeout",
                        $"Windows Update install exceeded {InstallTimeoutMs / 60_000}min. " +
                        $"Process was killed. stderr_tail: {Tail(psResult.Stderr, 500)}")
                );
            }

            if (string.IsNullOrWhiteSpace(psResult.Stdout))
            {
                // Process exited but emitted no JSON. Possible causes:
                //   - PowerShell crashed before ConvertTo-Json ran
                //   - WUA threw a fatal COM error mid-execution
                //   - The user policy blocks WUA from running
                // Return whatever stderr we captured so the operator
                // sees the actual reason.
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "patch_install_empty_response",
                        $"exit_code={psResult.ExitCode}; " +
                        $"stderr_tail: {Tail(psResult.Stderr, 500)}")
                );
            }

            try
            {
                using var doc = JsonDocument.Parse(psResult.Stdout);
                var result = JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText());
                return Task.FromResult(PrivSvcResponse.Success(req.Id, result!));
            }
            catch (JsonException jex)
            {
                // PowerShell ran to completion but the output is
                // malformed JSON. Almost always a thrown exception
                // ABOVE the ConvertTo-Json call — could be the COM
                // bind failing, AcceptEula throwing, etc. Return
                // the head of stdout (likely the trace) + stderr
                // tail so the operator can diagnose.
                return Task.FromResult(
                    PrivSvcResponse.Fail(req.Id, "patch_install_invalid_json",
                        $"{jex.Message} | exit_code={psResult.ExitCode} | " +
                        $"stdout_head: {Head(psResult.Stdout, 400)} | " +
                        $"stderr_tail: {Tail(psResult.Stderr, 300)}")
                );
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                PrivSvcResponse.Fail(req.Id, "patch_install_error", ex.Message)
            );
        }
    }

    /// <summary>
    /// First N characters of a string, with `…` suffix if truncated.
    /// Used for diagnostic preview of stdout/stderr in error
    /// responses without flooding the IPC channel.
    /// </summary>
    private static string Head(string s, int n)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= n ? s : s.Substring(0, n) + "…";
    }

    /// <summary>
    /// Last N characters of a string, with `…` prefix if truncated.
    /// Most error spew is at the END of stderr (final exception
    /// trace), so tailing is more useful than heading there.
    /// </summary>
    private static string Tail(string s, int n)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= n ? s : "…" + s.Substring(s.Length - n);
    }

    /// <summary>
    /// Result of a PowerShell invocation. Both stdout AND stderr are
    /// captured so callers can propagate errors back to the IPC
    /// client — the previous implementation only logged stderr to
    /// stdout (`Console.WriteLine`), leaving the agent + backend
    /// blind to what went wrong inside the script body.
    /// </summary>
    private sealed record PsResult(string Stdout, string Stderr, int ExitCode, bool TimedOut);

    /// <summary>
    /// Run a PowerShell snippet and return both pipes + exit code +
    /// a timeout flag.
    ///
    /// Hardening (2026-05-20) over the previous version:
    ///
    /// (1) ASYNC PIPE READS via BeginOutput/ErrorReadLine() + a
    ///     ManualResetEvent on each. The old code did `ReadToEnd()`
    ///     on stdout FIRST then stderr — if the script wrote more
    ///     than the OS pipe buffer (~64KB) to stderr while the
    ///     reader was still on stdout, the child blocked on its
    ///     stderr write and we deadlocked. Patch install scripts
    ///     for big Windows Updates can absolutely produce that much
    ///     stderr (verbose logging, COM error spew). Async readers
    ///     drain both pipes concurrently so no deadlock is possible.
    ///
    /// (2) REAL TIMEOUT enforced via WaitForExit(timeoutMs) AFTER
    ///     the reads started. Old code passed `30000` AFTER both
    ///     ReadToEnd calls had already blocked — the timeout was
    ///     therefore unreachable in practice (the reads always
    ///     completed before the WaitForExit ran). New code uses the
    ///     caller-supplied `timeoutMs` and KILLS the process on
    ///     expiry, returning `TimedOut=true` to the caller.
    ///
    /// (3) CALLER-SUPPLIED TIMEOUT. Scan can finish in &lt;30s but
    ///     install is routinely 5-30 min for kernel updates. Old
    ///     code hardcoded 30000ms for both — a real install hit
    ///     the latent ReadToEnd block forever (or until WUA itself
    ///     gave up). Callers now pass an appropriate ceiling:
    ///     HandleScan uses 60_000 (1 min), HandleInstall uses
    ///     90 * 60_000 (90 min — covers even kernel + .NET runtime
    ///     updates with download).
    /// </summary>
    private static PsResult RunPs(string command, int timeoutMs)
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
        if (proc == null) return new PsResult("", "Process.Start returned null", -1, false);

        var stdoutBuilder = new System.Text.StringBuilder();
        var stderrBuilder = new System.Text.StringBuilder();

        // Lock objects so reader callbacks don't race on Append.
        // StringBuilder isn't thread-safe.
        var stdoutLock = new object();
        var stderrLock = new object();

        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data == null) return;
            lock (stdoutLock) { stdoutBuilder.AppendLine(e.Data); }
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null) return;
            lock (stderrLock) { stderrBuilder.AppendLine(e.Data); }
        };

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        bool exited = proc.WaitForExit(timeoutMs);
        if (!exited)
        {
            // Hit the hard timeout. Kill the process so the OS handle
            // and the WUA COM session both release. Capture whatever
            // pipes had buffered before we killed it — useful for
            // diagnostics (partial JSON, last error log line).
            try { proc.Kill(); } catch { /* already gone */ }
            // Wait briefly for the async readers to drain post-kill.
            // Without this the StringBuilders may be empty even if
            // the child had written useful debug lines moments before.
            proc.WaitForExit(2000);

            string stdoutPartial, stderrPartial;
            lock (stdoutLock) { stdoutPartial = stdoutBuilder.ToString(); }
            lock (stderrLock) { stderrPartial = stderrBuilder.ToString(); }

            return new PsResult(stdoutPartial, stderrPartial, -1, true);
        }

        // Process exited cleanly (or with error). Drain readers
        // — they may still be processing the last line.
        proc.WaitForExit();

        string stdout, stderr;
        lock (stdoutLock) { stdout = stdoutBuilder.ToString(); }
        lock (stderrLock) { stderr = stderrBuilder.ToString(); }

        if (!string.IsNullOrWhiteSpace(stderr))
        {
            // Keep the breadcrumb in service logs for grep-ability.
            // The full stderr is ALSO returned to the caller (new in
            // this hardening) so the agent + backend can surface it.
            Console.WriteLine($"[PrivSvc][PatchManagement] PowerShell stderr: {stderr}");
        }

        return new PsResult(stdout, stderr, proc.ExitCode, false);
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
