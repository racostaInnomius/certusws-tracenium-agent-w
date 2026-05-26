# Agent 1.1.20 — Remediation Plan

> **Target build**: `1.1.20`
> **Predecessor**: `1.1.19` (currently in production on partial fleet via self-update)
> **Created**: 2026-05-26
> **Status**: Plan approved, implementation pending
>
> **Goal**: Fix the chronic agent service crashes observed in production fleet AND harden the installer with multi-layer recovery so future bugs don't translate to permanent offline devices.

---

## TL;DR

1. **Root cause bug** in C# PrivSvc `NamedPipeServer` (race between async push and pipe disposal → `ObjectDisposedException` → cascading instability) — gets the proper fix.
2. **3 layers of service recovery** baked into the MSI installer so even unfixed future bugs cannot keep a device offline more than 5 minutes:
   - WinSW multi-step `<onfailure>` backoff + `<resetfailure>`
   - Windows SCM failure recovery via `sc.exe failure` (CustomAction)
   - Scheduled task watchdog (last-resort safety net)
3. **Diagnostic dump** when the agent's own liveness watchdog fires — so next mystery crash gets caught with the smoking gun.

No quick patches via remote scripts. Fix the bug at the source, ship via normal release pipeline. Existing 1.1.19 devices auto-update to 1.1.20 within 24-48 hours.

---

## Context — What Prompted This

### Production symptom

Reported 2026-05-26: a Windows device updated from `1.1.18` to `1.1.19` and reports offline in portal UI. Tray icon shows `1.1.19` installed but agent is not communicating.

### Diagnostic findings

Inspection of the affected Windows machine's Event Log revealed the service had been crashing **chronically**:

```
Event ID 7034 (service terminated unexpectedly):
  17/05  4 times
  18/05  3 times
  21/05  2 times
  23/05  1 time
  24/05  1 time
  25/05  3 times (last one resulted in permanent Stopped state)
```

This is NOT a 1.1.19-introduced bug. The chronic instability predates the update. 1.1.19 update only made it visible because WinSW eventually gave up retrying and left the service `Stopped`.

### Exit codes tell the story

| Exit code | Meaning | Pattern |
|-----------|---------|---------|
| `-1073741510` (0xC000013A) | `STATUS_CONTROL_C_EXIT` — planned stop (uninstall, upgrade) | Occurs only at update boundaries |
| `1` | `process.exit(1)` from Node code (liveness watchdog) | All other crashes |

Most crashes are **the agent's own liveness watchdog suiciding** because the Node event loop became wedged for >5 minutes.

### PrivSvc Event Log — the smoking gun

```
TimeCreated      : 26/05/2026 09:04:34 a.m.
Message          : Async IPC push was not delivered.
                   Unexpected IPC write failure.
                   System.ObjectDisposedException: Cannot access a closed pipe.
                      at System.IO.Pipes.PipeStream.CheckWriteOperations()
                      at System.IO.Pipes.PipeStream.WriteAsync(...)
                      at System.IO.StreamWriter.WriteAsyncInternal(...)
                      at Tracenium.PrivSvc.Windows.Ipc.NamedPipeServer.
                         <>c__DisplayClass7_0.<<HandleClientAsync>g__WriteJsonLineAsync|0>d.MoveNext()
```

This exception repeats every ~5 minutes when there's IPC client activity. It's a classic concurrency race in PrivSvc's named pipe server.

### Confirmed: Node side is OK

`src/priv/privsvc-client-windows.ts` already has:
- Per-method timeouts (`grpc.heartbeat=5s`, default=8s, connect=60s)
- Pending Promises rejected on socket close (no orphaned awaits)
- Automatic reconnection on pipe drop
- EventEmitter-based push subscription with early-message buffering

So the bug is **purely server-side (PrivSvc C#)**.

### Why the Node loop still wedges

Even though Node's IPC client is well-built, when PrivSvc keeps misbehaving (dropping pushes, race-disposing pipes), the agent enters a chronic reconnect/retry state. Some path keeps `tray-status.json` from being written for >5 min, the liveness watchdog interprets that as wedged event loop, and `process.exit(1)` fires. Need diagnostics to pin the exact path — added as part of this build.

---

## Architecture Recap (for context)

The Windows agent has **two cooperating processes**:

```
┌─────────────────────────────────────────────────────────────┐
│ TraceniumAgentCore (Node.js, runs as LocalSystem via WinSW) │
│  • Plugin orchestration (AMP, SCP, PMP)                     │
│  • gRPC client (via PrivSvc bridge)                         │
│  • Liveness watchdog → process.exit(1) if wedged            │
│  • Self-update logic                                        │
└────────────────────────┬────────────────────────────────────┘
                         │ Named Pipe IPC
                         │ \\.\pipe\tracenium.privsvc.v1
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ Tracenium.PrivSvc.Windows (C#/.NET, runs as service)        │
│  • Elevated operations (patch install, SendInput, etc.)     │
│  • Embedded gRPC bridge to grpc.tracenium.com (mTLS)        │
│  • NamedPipeServer: bidirectional IPC with Agent Core       │
└─────────────────────────────────────────────────────────────┘
```

The IPC is bidirectional:
- **Request/Response**: Node calls `priv.call({ method, params })`, PrivSvc returns result
- **Async push**: PrivSvc pushes events (gRPC events, sensor events) via `WriteJsonLineAsync`

The bug is in the second path — the async push path. PrivSvc fires pushes via `Task.Run(...)` without coordinating with client lifetime.

---

## Root Cause Detail

### File: `privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/NamedPipeServer.cs`

**Buggy code** (~lines 97-265 in `HandleClientAsync`):

```csharp
// Local push delegate (~line 156)
Action<object> push = msg =>
{
    _ = Task.Run(async () =>           // Fire-and-forget
    {
        var ok = await WriteJsonLineAsync(msg);
        if (!ok) {
            _logger.LogWarning("Async IPC push was not delivered.");
        }
    }, CancellationToken.None);        // ← never cancels
};

// WriteJsonLineAsync (~line 120-150)
private async Task<bool> WriteJsonLineAsync(object msg) {
    // ...serialize...
    await _writeSemaphore.WaitAsync();
    try {
        await writer.WriteLineAsync(json);
        await writer.FlushAsync();      // ← throws ObjectDisposedException
        return true;
    } catch (IOException ex) {
        // logged, returns false
    }
    // ← NO catch for ObjectDisposedException
    catch (Exception ex) {
        _logger.LogError(ex, "Unexpected IPC write failure.");
        return false;
    }
}

// Finally block at end of HandleClientAsync (~line 263)
finally {
    pipe.Dispose();   // ← can run while a queued push is mid-flight
}
```

**Race scenario:**

| Time | Thread A (client handler) | Thread B (push delegate via Task.Run) |
|------|---------------------------|---------------------------------------|
| t=0 | Reading from pipe | (idle) |
| t=1 | Client disconnects, exits read loop | (idle) |
| t=2 | Enters `finally`, calls `pipe.Dispose()` | GrpcBridge pushes a message → push delegate queued |
| t=3 | Returns | Task.Run starts → calls `WriteJsonLineAsync` |
| t=4 | (gone) | `writer.FlushAsync()` → `ObjectDisposedException` |
| t=5 | (gone) | Falls through to generic catch → logs as ERROR (not Debug) |

**Result**: every disconnect + concurrent push generates a noisy ERROR log entry, and the message is silently dropped (which may or may not matter depending on what was being pushed).

### Why this matters for the wedge

The "dropped push" itself is mostly harmless (these are async events like `grpc.ack`, `grpc.control.policyUpdate`). But the pattern reveals the IPC channel is unreliable. Combined with whatever else is happening in the Node side (still TBD — that's what the diagnostic dump will show us), it conspires to leave tray-status unwritten for >5 minutes.

The diagnostic dump in 1.1.20 will tell us the second half of the chain.

---

## Changes Summary

| # | File | Type | Purpose |
|---|------|------|---------|
| 1 | `privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/NamedPipeServer.cs` | Bug fix | Catch `ObjectDisposedException`; cancel push delegate on disconnect |
| 2 | `src/core/service.ts` + new `src/diag/wedge-dump.ts` | Observability | Dump diagnostics to `wedge-{ts}.json` before `process.exit(1)` |
| 3 | `src/transport/grpc-client.ts` (heartbeat path) | Observability | Ensure `tray-status` is updated even when heartbeat fails |
| 4 | `packaging/windows/core-service/TraceniumAgentCore.xml` | Hardening | Multi-step `<onfailure>` + `<resetfailure>` |
| 5 | `windows/installer/wix/AgentCoreFiles.wxs` | Hardening | CustomAction: `sc.exe failure ...` post-install |
| 6 | `windows/installer/wix/AgentCoreFiles.wxs` (same file) | Hardening | CustomAction: register/unregister TraceniumWatchdog scheduled task |
| 7 | `windows/installer/scripts/register-watchdog.ps1` | New file | Script executed by CustomAction to create the scheduled task |
| 8 | `package.json` + `windows/installer/wix/Product.wxs` | Version | Bump `1.1.19` → `1.1.20` |
| 9 | `privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/NamedPipeServer.cs` (already #1) | Log noise | Demote `Async IPC push was not delivered` from Warning to Debug |

**Total: 6 files modified + 1 new file**

---

## Detailed Changes

### #1 — Fix PrivSvc NamedPipeServer race

**File**: `privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/NamedPipeServer.cs`

**Inside `HandleClientAsync`, at the top of the method** (before the read loop):

```csharp
// Linked cancellation source — cancelled when this client disconnects.
// Used to short-circuit any queued push that hasn't started writing yet.
using var clientCts = CancellationTokenSource.CreateLinkedTokenSource(_serverCt);
var clientDisconnected = new System.Threading.ManualResetEventSlim(false);
```

**Replace the `push` delegate** (~line 156):

```csharp
Action<object> push = msg =>
{
    // Fast path: skip work if client is already disconnecting/disposed.
    if (clientCts.IsCancellationRequested) return;

    var ct = clientCts.Token;
    _ = Task.Run(async () =>
    {
        if (ct.IsCancellationRequested) return;
        var ok = await WriteJsonLineAsync(msg).ConfigureAwait(false);
        if (!ok && !ct.IsCancellationRequested) {
            // Disposed-mid-write is benign and expected during disconnect races.
            // Demoted from Warning to Debug to avoid Event Log spam.
            _logger.LogDebug("Async IPC push was not delivered.");
        }
    }, ct);
};
```

**Replace `WriteJsonLineAsync`** (~lines 120-150):

```csharp
private async Task<bool> WriteJsonLineAsync(object msg)
{
    string json;
    try { json = JsonSerializer.Serialize(msg, _jsonOpts); }
    catch (Exception ex) {
        _logger.LogError(ex, "Failed to serialize push message.");
        return false;
    }

    await _writeSemaphore.WaitAsync().ConfigureAwait(false);
    try
    {
        // Guard before the await — caller may have signaled disconnect.
        if (!pipe.IsConnected) {
            _logger.LogDebug("Push dropped: pipe not connected.");
            return false;
        }

        await writer.WriteLineAsync(json).ConfigureAwait(false);
        await writer.FlushAsync().ConfigureAwait(false);
        return true;
    }
    catch (ObjectDisposedException) {
        // Benign race: pipe disposed between the IsConnected check and write.
        // No need to log as error — happens during normal disconnect flow.
        _logger.LogDebug("Push dropped: pipe was disposed mid-write.");
        return false;
    }
    catch (IOException ex) {
        _logger.LogDebug("Push dropped: I/O error: {Msg}", ex.Message);
        return false;
    }
    catch (Exception ex) {
        // This catches anything genuinely unexpected — keep at Error level.
        _logger.LogError(ex, "Unexpected IPC write failure.");
        return false;
    }
    finally { _writeSemaphore.Release(); }
}
```

**In the `finally` block** at the end of `HandleClientAsync` (~line 260):

```csharp
finally {
    // Signal any in-flight push to bail before touching the pipe.
    try { clientCts.Cancel(); } catch { /* already disposed */ }
    clientDisconnected.Set();
    pipe.Dispose();
}
```

**Verification**: after build, in dev/test environment with PrivSvc running and Agent Core connecting/disconnecting repeatedly:
- Event Viewer → Application: zero `Unexpected IPC write failure` entries
- Event Viewer → Application: zero `Async IPC push was not delivered` (or only when DEBUG_PRIVSVC_LOGS is set)

---

### #2 — Diagnostic dump in Node liveness watchdog

**New file**: `src/diag/wedge-dump.ts`

```typescript
import * as fs from "fs";
import * as path from "path";

interface AgentContext {
  trayStatus?: { getLastWriteMs?: () => number };
  priv?: { getPendingCount?: () => number; getPendingMethods?: () => string[] };
}

interface Logger {
  info?: (msg: string, meta?: unknown) => void;
  error?: (msg: string, meta?: unknown) => void;
}

export async function dumpWedgeState(
  ctx: AgentContext | null | undefined,
  log: Logger,
): Promise<string | null> {
  try {
    const logDir =
      process.platform === "win32"
        ? path.join(
            process.env.ProgramFiles || "C:\\Program Files",
            "Tracenium", "AgentCore", "logs",
          )
        : "/var/log/tracenium";

    fs.mkdirSync(logDir, { recursive: true });

    const wedgeFile = path.join(logDir, `wedge-${Date.now()}.json`);

    // process.report.getReport() is available on Node 12+, returns rich state
    const procAny = process as any;
    const report = procAny.report?.getReport?.() ?? {};

    const lastTrayMs = ctx?.trayStatus?.getLastWriteMs?.() ?? null;
    const data = {
      timestamp: new Date().toISOString(),
      pid: process.pid,
      uptimeSeconds: Math.round(process.uptime()),
      memoryUsage: process.memoryUsage(),

      lastTrayWriteMs: lastTrayMs,
      lastTrayWriteAgoSeconds:
        lastTrayMs !== null ? Math.round((Date.now() - lastTrayMs) / 1000) : null,

      ipc: {
        pendingCount: ctx?.priv?.getPendingCount?.() ?? null,
        pendingMethods: ctx?.priv?.getPendingMethods?.() ?? null,
      },

      // process.report fields — trim heavy/PII-sensitive parts
      processReport: {
        platform: report.platform,
        componentVersions: report.componentVersions,
        javascriptStack: report.javascriptStack,
        nativeStack: Array.isArray(report.nativeStack)
          ? report.nativeStack.slice(0, 30)
          : null,
        libuv: report.libuv,
        // intentionally omitted: workers, environmentVariables (PII risk)
      },
    };

    fs.writeFileSync(wedgeFile, JSON.stringify(data, null, 2), "utf8");
    log.info?.("Wedge diagnostics dumped", { wedgeFile });
    return wedgeFile;
  } catch (err: any) {
    log.error?.("Wedge dump failed", { error: err?.message });
    return null;
  }
}
```

**Modify `src/core/service.ts`** in the liveness watchdog block (~lines 296-338):

```typescript
import { dumpWedgeState } from "../diag/wedge-dump";

// ... inside the watchdog setInterval callback, replace the existing block:
if (staleMs > MAX_STATUS_STALE_MS) {
  logger.error(
    "Liveness watchdog: tray status not updated in " +
      `${Math.round(staleMs / 1000)}s (> ${MAX_STATUS_STALE_MS / 1000}s threshold). ` +
      `Event loop is wedged. Exiting so ${recycler} can recycle the process.`,
  );
  // Best-effort diagnostic dump — never block exit longer than 500ms total.
  dumpWedgeState(currentCtx ?? null, logger)
    .catch(() => {})
    .finally(() => {
      setTimeout(() => process.exit(1), 500).unref();
    });
}
```

**Expose pending requests on the IPC client.** Add to `src/priv/privsvc-client-windows.ts`:

```typescript
public getPendingCount(): number {
  return this.pending.size;
}

public getPendingMethods(): string[] {
  const out: string[] = [];
  for (const entry of this.pending.values() as any) {
    out.push(entry?.method ?? "unknown");
  }
  return out;
}
```

Note: this requires that the `pending` map stores the `method` name on each entry. If not already stored, add it in the `call()` method when populating the map.

---

### #3 — Heartbeat hardening

**File**: `src/transport/grpc-client.ts` (the heartbeat function, ~lines 606-649)

Wrap the IPC call so a heartbeat failure doesn't skip the tray-status update:

```typescript
async function sendHeartbeat(ctx: AgentContext, log: Logger) {
  let ok = false;
  let errorMsg: string | null = null;
  try {
    await ctx.priv.call({
      v: 1,
      id: `hb-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      method: "grpc.heartbeat",
      params: { /* ... */ },
      meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId },
    });
    ok = true;
  } catch (err: any) {
    errorMsg = err?.message ?? String(err);
    log.warn?.("[heartbeat] IPC call failed", { error: errorMsg });
    // Do NOT re-throw — the next tick will retry.
  }

  // CRITICAL: always update tray status, even on failure.
  // This prevents the liveness watchdog from firing because we
  // failed to write tray-status — a heartbeat failure is recoverable,
  // a wedged-event-loop suspicion is not.
  ctx.trayStatus?.markHeartbeat?.({ ok, errorMsg, atUtc: new Date().toISOString() });
}
```

This change is small but eliminates a likely path to wedge false-positives. Need to verify the actual signature of `markHeartbeat` matches; adapt as needed.

---

### #4 — WinSW XML hardening

**File**: `packaging/windows/core-service/TraceniumAgentCore.xml`

**Current state** (last line, broken):

```xml
<onfailure action="restart" delay="5 sec" />
```

**New state**:

```xml
  <!-- ============================================================
       Service Recovery (Layer 1 of 3)
       Multi-step backoff with reset window. After 4 rapid failures,
       backs off to 2 min between restarts. If the service stays up
       for 15 min, the failure counter resets — preventing WinSW
       from "giving up" after long chains of historical failures.
       ============================================================ -->
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <onfailure action="restart" delay="120 sec"/>
  <resetfailure>15 min</resetfailure>
</service>
```

The 4 `<onfailure>` entries are processed in order on each subsequent failure. After the 4th, WinSW continues using the last action.

---

### #5 + #6 — WiX CustomActions for SCM recovery + Watchdog

**File**: `windows/installer/wix/AgentCoreFiles.wxs`

**Why `sc.exe failure` via CustomAction instead of `<util:ServiceConfig>`**: per the historical comment in `PrivSvc.wxs` lines 29-50, `WixToolset.Util.wixext 6.0.0` was found to break the `InstallExecuteSequence` ordering between `MsiInstallServiceConfig` and `StartServices` actions in v1.1.16+. Using `sc.exe` directly avoids this risk entirely.

**Add after the existing `<ServiceInstall>`** (within the same `<Component>` or as a new `<Component>`):

```xml
<!-- ====================================================================
     Service Recovery (Layer 2 of 3)
     Configures Windows SCM to restart TraceniumAgentCore on failure.
     This is independent of WinSW — kicks in if WinSW itself fails or
     gives up. Counter resets daily (86400 seconds).

     Actions: restart/restart/restart with 60s delays.
     ==================================================================== -->
<CustomAction Id="ConfigureAgentCoreRecovery"
              Directory="INSTALLFOLDER"
              ExeCommand='sc.exe failure "TraceniumAgentCore" reset= 86400 actions= restart/60000/restart/60000/restart/120000'
              Execute="deferred"
              Return="ignore"
              Impersonate="no"/>

<!-- ====================================================================
     Watchdog Scheduled Task (Layer 3 of 3) — last-resort safety net
     Runs every 5 min as SYSTEM; ensures the service is Running.
     ==================================================================== -->
<CustomAction Id="RegisterTraceniumWatchdog"
              Directory="INSTALLFOLDER"
              ExeCommand='powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "[#WatchdogScriptFile]"'
              Execute="deferred"
              Return="ignore"
              Impersonate="no"/>

<CustomAction Id="UnregisterTraceniumWatchdog"
              Directory="INSTALLFOLDER"
              ExeCommand='powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Unregister-ScheduledTask -TaskName TraceniumWatchdog -Confirm:$false -ErrorAction SilentlyContinue"'
              Execute="deferred"
              Return="ignore"
              Impersonate="no"/>

<InstallExecuteSequence>
  <!-- Configure recovery + register watchdog after the service is installed but before it starts.
       On reinstall/upgrade, re-apply (idempotent). -->
  <Custom Action="ConfigureAgentCoreRecovery"  After="InstallServices"                  Condition="NOT Installed OR REINSTALL"/>
  <Custom Action="RegisterTraceniumWatchdog"   After="ConfigureAgentCoreRecovery"       Condition="NOT Installed OR REINSTALL"/>

  <!-- Remove watchdog on full uninstall (NOT on upgrade). -->
  <Custom Action="UnregisterTraceniumWatchdog" Before="RemoveExistingProducts"          Condition='REMOVE="ALL"'/>
</InstallExecuteSequence>
```

**Add the watchdog script as a `<File>`** in the AgentCore feature component group:

```xml
<Component Id="WatchdogScriptComponent" Guid="{GENERATE-NEW-GUID-HERE}">
  <File Id="WatchdogScriptFile"
        Source="binaries\AgentCore\scripts\register-watchdog.ps1"
        Name="register-watchdog.ps1"
        KeyPath="yes"/>
</Component>
```

⚠️ **Action**: generate a fresh GUID for `WatchdogScriptComponent` when integrating (e.g., `uuidgen`). Do NOT reuse an existing GUID.

The build script (`build-windows-msi.ps1`) should already pick up `binaries\AgentCore\scripts\*` if the directory is staged. Verify it gets copied during the staging step (line ~109 in that script).

---

### #7 — Watchdog PowerShell script

**New file**: `windows/installer/scripts/register-watchdog.ps1`

```powershell
# Registers the TraceniumWatchdog scheduled task.
# Idempotent — re-running replaces the existing task.
# Called from the MSI as a deferred CustomAction (runs as SYSTEM).

$ErrorActionPreference = "Stop"

$dataDir = "C:\ProgramData\Tracenium\Agent"
$wdScript = Join-Path $dataDir "watchdog.ps1"

# Ensure ProgramData directory exists (the agent will use it for logs)
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

# Watchdog script content — separate file so the scheduled task has a stable path
@'
$ErrorActionPreference = "SilentlyContinue"
$logPath = "C:\ProgramData\Tracenium\Agent\watchdog.log"
$svc = Get-Service -Name "TraceniumAgentCore"
if ($null -eq $svc) {
    Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | service_missing"
    return
}
if ($svc.Status -ne 'Running') {
    Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | restart (was=$($svc.Status))"
    try {
        Start-Service -Name "TraceniumAgentCore" -ErrorAction Stop
        Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | started"
    } catch {
        Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') | start_failed: $($_.Exception.Message)"
    }
}
'@ | Set-Content -Path $wdScript -Encoding UTF8 -Force

# Register the scheduled task (overwrites existing)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$wdScript`""

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

Register-ScheduledTask -TaskName "TraceniumWatchdog" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Restart TraceniumAgentCore if it ends up in Stopped state — last-resort safety net" `
    -Force | Out-Null
```

---

### #8 — Version bump

Search for `1.1.19` across the repo and update each:

```bash
grep -rn --include='*.json' --include='*.wxs' --include='*.wxi' --include='*.ts' --include='*.ps1' \
  '1\.1\.19' . | grep -v node_modules | grep -v dist
```

Known files to update:
- `package.json` line 2: `"version": "1.1.20"`
- `windows/installer/wix/Product.wxs` line 20: `Version="1.1.20"`
- Any `package-lock.json` will update automatically on `npm install`

The build pipeline reads version from `package.json` (see `build-windows-msi.ps1` lines 71-76), so other files may not need explicit changes. Verify via grep.

---

## Implementation Order

Recommended order — preserves the ability to test each layer independently:

| Phase | Steps | Est. time | Validation |
|-------|-------|-----------|------------|
| **A. Bug fix (PrivSvc C#)** | #1 | 30-45 min | Local build, run PrivSvc + agent in test env, verify no `ObjectDisposedException` in Event Log after 100+ disconnect/reconnect cycles |
| **B. Diagnostic dump (Node)** | #2 | 45-60 min | Force a wedge in dev (insert `await new Promise(()=>{})` somewhere) and confirm `wedge-*.json` is written before exit |
| **C. Heartbeat hardening (Node)** | #3 | 15-20 min | Verify tray status keeps updating even when PrivSvc is killed mid-heartbeat |
| **D. Installer hardening (WiX + WinSW)** | #4, #5, #6, #7 | 60-90 min | Build MSI, install on clean Windows VM, verify all 3 layers configured |
| **E. Version bump + final build** | #8 | 15 min | Local MSI build for both x64 and arm64 |
| **F. Release via GitHub Actions** | Tag + push | 5 min + 20 min CI | CI runs, MSIs published to Azure Blob, metadata endpoint updated |

**Total**: ~3-4 hours of dev work + 20 min CI.

---

## Pre-Release Verification

On a fresh Windows VM (x64 and arm64 separately if possible), install the new MSI and verify:

```powershell
# 1. SCM failure recovery configured
sc.exe qfailure TraceniumAgentCore
# Expected output: RESTART_SERVICE x3, RESET_PERIOD=86400

# 2. WinSW XML has multi-step recovery
Select-String -Path "C:\Program Files\Tracenium\AgentCore\TraceniumAgentCore.xml" -Pattern "onfailure"
# Expected: 4 lines of <onfailure>

Select-String -Path "C:\Program Files\Tracenium\AgentCore\TraceniumAgentCore.xml" -Pattern "resetfailure"
# Expected: 1 line of <resetfailure>15 min</resetfailure>

# 3. Watchdog scheduled task registered
Get-ScheduledTask -TaskName TraceniumWatchdog | Format-List State, LastRunTime, NextRunTime
# Expected: State=Ready, NextRunTime in next 5 min

# 4. Simulate Node child crash — WinSW should restart it
Get-Process node -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -like "*Tracenium*" } |
  Stop-Process -Force
Start-Sleep 20
(Get-Service TraceniumAgentCore).Status
# Expected: Running (WinSW recovered)

# 5. Simulate full service stop — SCM recovery should kick in
sc.exe stop TraceniumAgentCore
Start-Sleep 75   # SCM recovery delay is 60s
(Get-Service TraceniumAgentCore).Status
# Expected: Running

# 6. Simulate WinSW dead + SCM exhausted — watchdog scheduled task last resort
# (Harder to test cleanly; verify the task's log shows runs)
Get-Content "C:\ProgramData\Tracenium\Agent\watchdog.log" -Tail 10
# Expected: timestamped entries showing the task ran every 5 min

# 7. PrivSvc IPC quality check — let the service run 30 min, then:
Get-WinEvent -FilterHashtable @{
  LogName='Application'
  ProviderName='Tracenium.PrivSvc.Windows'
  StartTime=(Get-Date).AddMinutes(-30)
} -MaxEvents 50 |
  Where-Object { $_.LevelDisplayName -eq 'Error' } |
  Measure-Object
# Expected: Count=0
```

---

## Post-Release Verification (Production Fleet)

After 1.1.20 rolls out via self-update (24-72 hour rollout window):

**Metrics to monitor for 1 week post-rollout:**

| Metric | Target | How to check |
|--------|--------|--------------|
| Devices with `service_status != Running` for >5 min | 0 | Server-side query on `device_sessions` heartbeat freshness |
| Event Log 7034 (service crashes) | Down to ~0 per day | Sample fleet, check Event Logs |
| `Tracenium.PrivSvc.Windows.Worker` Errors | 0 | Sample fleet, Event Logs |
| `wedge-*.json` files created | If >0, investigate each | Server-side feedback channel? Or instruct support to check on incident |

**If `wedge-*.json` files appear**: that's the diagnostic gold we need. Each file shows:
- The JavaScript stack at the moment of wedge
- Pending IPC requests (method names + count)
- libuv handle state
- Memory pressure

Open an issue with the dump contents and use it to design the fix for 1.1.21.

---

## Open Questions / Future Work (NOT in 1.1.20)

These came up during analysis and should be tracked separately:

1. **Why does the Node event loop wedge?** — The diagnostic dump in 1.1.20 will give us the smoking gun. Fix targeted for 1.1.21.

2. **Backend: missing migrations on tenant DBs** — Separate issues:
   - `column "scp_findings_critical_days" does not exist` in retention service (Control DB)
   - `column c.status does not exist` in SCP projection (tenant DBs)
   - Both should be addressed in backend-side migration plan.

3. **Backend: orphaned tenant 60** — `tenant_db_not_found` for tenant 60. Decide if re-provision or hard-delete.

4. **PrivSvc Linux/macOS counterparts** — Are they susceptible to similar IPC bugs? Audit at next opportunity.

5. **Observability infrastructure** — Pool metrics + IPC pending counters should be exposed periodically via the backend to a metrics dashboard, not only on wedge.

---

## Rollback Plan

If 1.1.20 introduces regressions in the field:

1. **No emergency rollback needed for the installer hardening** — the SCM recovery and watchdog are additive; they don't break existing behavior.
2. **If the C# fix has a regression**: publish 1.1.21 ASAP with the WriteJsonLineAsync change reverted. Devices that already updated to 1.1.20 will pick up 1.1.21 automatically within 24-48 hours.
3. **Manual rollback per device** (last resort): MSI uninstall of 1.1.20 + install of 1.1.19 from a stored MSI. The watchdog scheduled task remains harmless if 1.1.19 is reinstalled (it just keeps restarting the service if it dies).

---

## Cross-Reference Files

When picking this work up in a new session, start by re-reading these key files:

### PrivSvc (C#)
- `privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/NamedPipeServer.cs` — the bug
- `privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GrpcBridge.cs` — pushers (lines 250-301 watchdog, 517-565 PushToAll)
- `privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/IpcGrpcHandlers.cs` — push sink registration (line 133)

### Agent Core (Node/TS)
- `src/priv/privsvc-client-windows.ts` — IPC client (well-built; mostly needs `getPendingCount` helper)
- `src/core/service.ts` lines 296-338 — liveness watchdog
- `src/status/tray-status-store.ts` — tray status writer
- `src/transport/grpc-stream.ts` — gRPC sender loop
- `src/transport/grpc-client.ts` lines 606-649 — heartbeat tick

### Installer (WiX 4)
- `windows/installer/wix/Product.wxs` — package metadata, version
- `windows/installer/wix/AgentCoreFiles.wxs` — service install for Agent Core
- `windows/installer/wix/PrivSvc.wxs` — service install for PrivSvc (note historical util:ServiceConfig comment)
- `windows/installer/build.ps1` — WiX build invocation
- `scripts/build-windows-msi.ps1` — staging + signing pipeline

### Service Wrapper
- `packaging/windows/core-service/TraceniumAgentCore.xml` — WinSW config

### CI / Release
- `.github/workflows/release.yml` — Windows MSI build + Azure Trusted Signing + Azure Blob publish

---

## Notes for Future Sessions

- **The user pattern**: code is reviewed before commits — never auto-commit. Use Edit/Write only; user runs `git commit` themselves.
- **The user is in Spanish (Mexico)**: previous sessions have been Spanish/English bilingual. Match their language.
- **Branch discipline**: there's likely an existing feature branch pattern for the agent repo. Check `git branch -a` before starting work.
- **Code-signing**: don't run any local commands that would require Trusted Signing access. All signing happens in CI only.
