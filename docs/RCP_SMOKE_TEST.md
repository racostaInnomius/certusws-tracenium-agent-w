# RCP end-to-end smoke test

The RCP smoke test has been outstanding since M3.S2. Everything shipped since
then has been validated by unit tests and typechecks only — including code
that **cannot** be executed anywhere but a real Windows endpoint (DXGI desktop
duplication, `SendInput`, the PrivSvc IPC bridge).

This runbook is ordered by risk: the checks most likely to fail, and most
expensive to discover in production, come first.

## What has never run on real hardware

| Change | Why it can't be tested off-device |
|---|---|
| Dirty-rect capture (`ScreenCaptureDxgi.cs`) | DXGI exists only on Windows. The C# compiles on macOS via `EnableWindowsTargeting`, but no line of it has executed. |
| `GetFrameDirtyRects` vtable slot 9 | Slot index is derived from the interface declaration, not observed. |
| `Bitmap.Clone` over the mapped staging texture | Stride handling on a cropped region is untested. |
| Screen-share error propagation | Needs a device that can actually fail (log out, UAC, GPU reset). |
| Upload staging (`O_EXCL｜O_NOFOLLOW`) | `O_NOFOLLOW` is POSIX-only; on Windows the flag is dropped and only the 0700 mkdtemp directory applies. |
| WebSocket RBAC | Needs a non-`admin_master` identity against a live signaling socket. |

## Prerequisites

- Windows 10/11 endpoint with the agent built from `Package-Prepare`, enrolled
  and **online** in the dashboard.
- A tenant policy with `features.remoteShell`, `remoteFile` and `remoteScreen`
  enabled, and `remoteRequireConsent` **off** (it is not implementable yet —
  turning it on refuses every session by design).
- Two dashboard identities: one `admin_master`, one plain tenant `ADMIN`.
- Log tail on the endpoint, in an elevated PowerShell. WinSW's `%BASE%` is the
  `AgentCore` directory, not the install root:

```powershell
Get-Content -Wait -Tail 50 "$env:ProgramFiles\Tracenium\AgentCore\logs\TraceniumAgentCore.out.log"
```

**This is the log that matters for every check below.** Capture failures reach
it with PrivSvc's own error code attached, because the agent forwards the IPC
response verbatim.

The PrivSvc gRPC bridge keeps a separate log, useful only if the IPC channel
itself is misbehaving:

```powershell
Get-Content -Wait -Tail 50 "$env:ProgramData\Tracenium\PrivSvc\logs\grpcbridge-$(Get-Date -f yyyyMMdd).log"
```

Note that `%ProgramData%\Tracenium` is inside the file jail's deny list — that
is deliberate, and Phase 2.3 verifies it.

---

## Phase 1 — Screen share

The highest-risk area. Two of these checks cover bugs that were live in
production until this cycle.

### 1.1 Idle desktop does not kill the session

1. Open a Screen session. Wait for the first frame.
2. **Do not touch the endpoint for 60 seconds.**

**Expect:** the viewer stays on `Live`. The image simply stops updating.

**Regression signature:** viewer flips to `Connection error` within a second or
two. That was the original B1 — DXGI returns `screen_capture_no_frame` on an
idle desktop and it used to be treated as fatal. If it reappears, check that
the agent is not forwarding that code (`[rcp.screen] no new frame` should
appear at debug level and nothing should reach the browser).

### 1.2 Dirty rects are actually engaging

1. With a session live, open Notepad on the endpoint and type continuously for
   ~30 seconds.
2. Watch the agent log for:

```
[rcp.screen] stream stats
```

**Expect** on a typing workload:
- `partialPct` well above 0 — typically 80-95%.
- `avgPartialKb` a small fraction of `avgFullKb` (a text caret region is a few
  KB against ~150-250 KB for 1080p).
- `keyframes` ≈ `windowSec / 4`, i.e. about 2-3 per 10s window.

**If `partialPct` is 0:** the crop decision never fires. Either
`GetFrameDirtyRects` is failing (wrong vtable slot → `TryGetDirtyBounds`
returns false and we silently fall back to full frames — safe, but no win), or
every change is exceeding `DIRTY_MAX_AREA_PERCENT`. Confirm by temporarily
raising the threshold; if partials appear, the metadata is fine and the
threshold is mistuned. If they never appear, it is the P/Invoke.

**If `keyframes` is 0:** stop and investigate before anything else. It means
`forceFull` is not reaching the C#, so a single dropped packet corrupts the
canvas permanently. The known trap here is the JSON boolean arriving as
`"True"` — the comparison in `HandleScreenCapture` is deliberately
case-insensitive.

### 1.3 Partial updates composite correctly

1. Type in one corner of the screen, then move a window in the opposite corner.

**Expect:** no stale rectangles, no torn regions, no drift. Anything that looks
wrong should heal within 4 seconds (one keyframe interval).

**If artifacts persist beyond ~5s:** keyframes are not arriving (see 1.2) or
the browser is resizing the canvas on partials — `canvas.width` assignment
clears it, and that must only happen on a real resolution change.

### 1.4 Frame rate control

1. Move the FPS slider to 15.

**Expect:** `fps: 15` in the next stats line, and the footer's measured `fps`
counter climbs. The slider value must not snap back.

**Regression signature:** the value reverts to 5. That was B2 — the UI used to
echo the agent's own reported rate, so the control was inert.

### 1.5 Terminal condition and live recovery

1. Log the user out of the endpoint (leave the machine on).

**Expect:** viewer shows the "no active interactive desktop" copy — not a
generic connection error.

2. Log back in **without touching the browser**.

**Expect:** the stream resumes on its own within ~5 seconds.

This exercises the terminal-backoff path: the agent keeps polling slowly after
reporting a terminal condition, and the browser returns to `VIEWING` when a
frame arrives.

### 1.6 Transient blip is not fatal

1. Trigger a UAC prompt on the endpoint (run anything elevated).

**Expect:** at most an amber banner over a still-live canvas; the session
survives. The secure desktop causes `DXGI_ERROR_ACCESS_LOST`, which the capture
side recovers from by rebuilding the duplication chain.

### 1.7 Input forwarding still maps correctly

1. Enable **Take control**. Click a specific UI element on the remote.

**Expect:** the click lands where you aimed.

**Why this is in the screen-share phase:** input coordinates are scaled through
`liveSize`, which now must come from the full desktop dimensions rather than
the decoded image. If a partial update ever sets `liveSize` to a region size,
clicks land at wildly wrong positions — and only while partials are in flight,
which makes it look intermittent.

---

## Phase 2 — File transfer confinement

### 2.1 Session opens inside a root

1. Open a Files session.

**Expect:** the panel opens on the first allowed root (`C:\Users` by default),
not `/`. Agent log:

```
[rcp.file] session confined   roots=[...]
```

**If it opens on `/`:** the browser fell back to legacy behaviour after not
getting a `roots` reply within 1.5s — meaning the agent predates the jail.
Verify the deployed agent build.

### 2.2 Escaping the jail is refused

1. Navigate up until the **Up** button greys out.
2. Type or navigate to `C:\Windows\System32\config` if the UI allows it.

**Expect:** amber notice ("outside the locations remote file access is allowed
to reach"), session stays usable. Agent log: `[rcp.file] path refused by jail`
with `code: PATH_OUTSIDE_ROOTS`.

### 2.3 The agent's own credentials stay sealed

1. Navigate to `C:\ProgramData` (an allowed root by default).
2. Attempt to enter `Tracenium\Agent`.

**Expect:** `PATH_DENIED`. This is the one that matters — that directory holds
the device's mTLS private key and enrollment token. A successful download here
means an operator can impersonate the endpoint.

3. Check the audit: the refused attempt must appear as a **failed** transfer.

```sql
SELECT transfer_id, direction, remote_path, status, error_message
FROM remote_file_transfers
ORDER BY created_at DESC LIMIT 5;
```

### 2.4 Normal transfers still work

1. Download a file from the user's Desktop. Upload one back.

**Expect:** both complete; audit rows show `completed`.

### 2.5 Upload staging is private and cleaned up

During an upload, on the endpoint:

```powershell
Get-ChildItem $env:TEMP -Filter "tracenium-rcp-*"
```

**Expect:** exactly one directory while the transfer is in flight, gone after
the session closes. There must be **no** `rcp-upload-*` files loose in `%TEMP%`
— that was the old scheme, and the filename came from browser-supplied input.

---

## Phase 3 — Authorization (M4)

### 3.1 `admin_master` still works

Regression check: it resolves to `OWNER` upstream, so nothing should have
changed for Tracenium staff. Start a session of each type.

### 3.2 A tenant ADMIN can now operate

Sign in as the plain tenant `ADMIN`.

**Expect:** the Remote Control page loads with data, and a shell session opens
**and stays open**.

**Watch specifically for:** session starts (POST succeeds) and then the socket
fails. That would mean the REST gate was widened but the WebSocket upgrade
still rejects — the two enforce the same roles in two places by necessity
(`remote-control.routes.ts` and `RCP_WS_ROLES` in `signaling-ws.ts`). The
symptom is a session id followed by a signaling error, and a `pending` row that
burns a concurrency slot.

### 3.3 A USER is refused

**Expect:** 403 on the page's requests, no session.

---

## Phase 4 — Retention

Both windows default to NULL (disabled), so nothing is deleted until opted in.

1. Set `rcpTranscriptDays` to a small value on a test tenant.
2. Run the retention preview (dry run) and confirm `remote_session_io` reports
   a non-zero candidate count without deleting.
3. Run for real; confirm the rows are gone and the parent `remote_sessions`
   rows **remain** — the ledger outlives the recording by design.

```sql
SELECT
  (SELECT COUNT(*) FROM remote_session_io)      AS io_rows,
  (SELECT COUNT(*) FROM remote_sessions)        AS sessions,
  (SELECT COUNT(*) FROM remote_file_transfers)  AS transfers;
```

---

## Recording the outcome

Note per check: pass / fail / not run, and for 1.2 paste one `stream stats`
line — it is the only quantitative evidence that dirty rects engaged, and it is
worth keeping for comparison after future capture changes.
