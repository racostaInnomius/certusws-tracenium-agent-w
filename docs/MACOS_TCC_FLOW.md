# macOS TCC + Screen Recording — first-run UX

TCC (Transparency, Consent, and Control) is macOS's user-facing permission
gate for things like camera, microphone, screen recording, and accessibility
control. The first time an unsigned-by-Apple binary tries to capture the
screen, the OS pops a dialog the user must approve in System Settings →
Privacy & Security → Screen Recording. There is no programmatic way to
short-circuit this — Apple explicitly designed it to be user-driven.

For the Tracenium agent's rcp.screen helper (`tracenium-screencap`, a
Swift universal binary shipped inside the pkg), the operator's first
attempt at a Screen session on a Mac that has never granted permission
will:

1. Land at the agent.
2. The agent invokes the helper via `execFile`.
3. The helper imports ScreenCaptureKit and asks for a frame.
4. macOS pops the Screen Recording permission dialog AND returns a
   capture failure to the helper.
5. Helper exits non-zero with `tcc_denied` in stderr.
6. PrivSvc returns `{ok: false, error: { code: "tcc_denied" } }` over IPC.
7. AgentCore screen-session pushes `{ op:"error", code:"tcc_denied" }`
   to the operator.
8. Operator UI is supposed to surface this with a "go to System Settings
   and approve" message — track that as a UI gap if it's still the
   generic error string.

The user must approve, then the next session attempt works. The grant is
sticky: the OS remembers it across helper invocations as long as the
binary's code-signing identifier doesn't drift.

## What goes wrong + how to fix it

### "Screen Recording permission denied" persists after the user clicked Allow

Almost always one of these:

1. **Code-sign identifier drifted between builds**. The build script
   signs the helper with `com.certusws.tracenium.screencap`. If we ever
   rename it or re-sign with a different identifier, TCC sees a brand
   new binary and revokes its grant. The user has to re-approve in System
   Settings — they don't get a prompt the second time, they have to
   delete + re-add.
2. **macOS Big Sur / Monterey privacy-restricted user**. Some org
   profiles (managed by Jamf/Intune MDM) deny TCC overrides by policy.
   In that case the user *cannot* approve; you have to push a PPPC
   payload via MDM.

### TCC reset

To force a fresh prompt during dev:
```
tccutil reset ScreenCapture com.certusws.tracenium.screencap
```

(or empty trailing arg = reset all binaries).

### Verify the grant is in place

```
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client,allowed FROM access WHERE service='kTCCServiceScreenCapture';"
```

`allowed=2` means user clicked Allow. `allowed=0` means denied.

## PPPC payload for managed Macs

For fleets behind MDM, ship a Privacy Preferences Policy Control payload
that pre-grants screen recording to the helper. Without this, every Mac
needs an end-user click which doesn't scale.

See `privsvc/macos/helpers/README.md` for the payload XML. The
`CodeRequirement` field must match what `codesign -d -r-` prints for the
built helper — it ties the grant to *our* signed binary, not just the
bundle ID, so a swapped binary doesn't inherit the permission.

## Lifecycle of the helper

The helper is a one-shot — `execFile` per frame, helper exits, no
persistent process. We chose this over a long-lived helper because:

- TCC reads stay simple (one binary, one identifier, no inter-process
  permission propagation)
- A crashed helper doesn't take down the agent
- macOS's helper-process supervision behaves predictably

The cost is process-spawn overhead per frame (~10-30ms). For
screen-share at 5-10 fps this is fine; for high-FPS use cases we'd want
a persistent helper with XPC. Not a current need.

## See also

- `privsvc/macos/helpers/screencap/main.swift` — the helper itself
- `scripts/build-macos-pkg.sh build_screencap_helper()` — build + sign
- `privsvc/macos/src/screen-capture.ts` — the AgentCore-side caller
- `docs/RCP_PLATFORM_MATRIX.md` — overall capability + OS matrix
