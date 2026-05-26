# RCP Design Decisions — v2 (2026-05-21 review)

Status: accepted, M1 Sprint 1 in progress
Supersedes: `RCP_DESIGN_DECISIONS.md` (2026-04-27, "v1")
Scope: `certusws-tracenium-agent-w` aligned with backend `certusws-tracenium` and frontend `certusws-tracenium-ui`

## Why a v2

The v1 doc was architecturally sound but the 10-phase plan stalled before Phase 1 because Phase 1 was scoped as "proto + types + manager skeleton" — no end-to-end deliverable. We also missed several non-architectural-but-critical concerns (multiplexing, operator disconnect, transcript-from-day-1, cross-platform PTY, rate limits).

v2 keeps every architectural decision from v1 and:

1. Compresses the 10 phases into 5 verifiable milestones, each ending in a working demo.
2. Promotes WebRTC from "screen-only" to "all RCP capabilities from day 1" — eliminates a future re-platforming we'd have to do otherwise.
3. Promotes transcript / audit from "follow-up" to Sprint 3 of M1 — non-negotiable for SOC2/HIPAA parity with the SCP module.
4. Fills the gaps v1 didn't address (multiplex, disconnect, cross-platform, rate limits).

If a v1 decision is not mentioned here, it stands unchanged.

## Core decisions kept from v1

All 7 v1 core decisions stand:

1. RCP is not a `job`.
2. Shell is the first deliverable.
3. WebRTC for screen — **expanded in v2 to: WebRTC for ALL data, see v2 decisions §1**.
4. No inbound listener on the endpoint.
5. Backend is the control and audit plane.
6. Capabilities must be explicit.
7. Policy is the source of enablement.

## v2 decisions (new or revised)

### 1. WebRTC for all RCP transport, not just screen

**Original (v1):** gRPC for shell + file; WebRTC for screen.
**Revised (v2):** WebRTC peer connection + data channels for shell I/O and file transfer, WebRTC video track for screen. Single transport for the whole RCP family.

Rationale:
- Builds the WebRTC infrastructure once instead of twice (M5/M6 in v1 would have had to re-platform shell or maintain two transports forever).
- Direct browser ↔ agent path eliminates the backend hop on every keystroke. Round-trip latency drops from ~100 ms to ~30-50 ms.
- Backend no longer carries shell I/O bandwidth — only signaling + audit.
- File transfer benefits hugely: multi-MB transfers don't burden the backend gRPC stream.
- DataChannel and DTLS already provide encryption + flow control. No additional crypto plumbing.

Costs accepted:
- TURN server required from day 1 (v1 didn't need this until M5).
- WebRTC lib in Node.js (the agent side) is less mature than browser-side. Selected `node-datachannel` over `@roamhq/wrtc` (no Chromium prebuilts, ~3 MB vs ~80 MB).
- Slightly more complex than a single gRPC stream (offer/answer/ICE negotiation).

### 2. Three-tier transport model

```
  Browser  ⟷ WebSocket ⟷  Backend  ⟷ gRPC stream ⟷  Agent
     ⟵─── WebRTC DataChannel (P2P via STUN/TURN) ───⟶
```

- **Browser ↔ backend (WebSocket)**: signaling only (SDP, ICE), session lifecycle, transcript replay queries. Auth via OIDC cookie.
- **Backend ↔ agent (gRPC)**: signaling relay (forwards SDP/ICE between browser and agent), session lifecycle persistence, transcript upload from agent.
- **Browser ↔ agent (WebRTC)**: actual I/O. Backend never sees keystrokes or output in flight.

Audit lives in the gRPC channel: the agent uploads transcript chunks periodically (every ~5 s or ~8 KB). Backend persists in `remote_session_io`.

### 3. TURN server: Cloudflare Calls TURN

- Free tier covers our expected M1-M3 volume (well below 1 TB/month).
- One-line config; credentials minted on demand via Cloudflare API.
- Self-host coturn is the future migration path if we outgrow the free tier or want full control.

### 4. WebSocket for browser ↔ backend signaling

Not gRPC-web, not server-sent events. Plain WebSocket because:
- Bi-directional is required (ICE candidates fly both ways).
- WS terminates on the same Express server as the rest of the REST API — no new ingress, no new auth surface.
- The OIDC cookie travels naturally with the upgrade request.

### 5. WebRTC lib choice: `node-datachannel`

- Pure C++ via N-API, no Chromium dependency.
- ~3 MB unpacked vs `@roamhq/wrtc`'s ~80 MB.
- DataChannel + video track support — covers M1 through M6.
- Active maintenance (libdatachannel upstream).

### 6. Audit transcript format: asciinema v2

- JSON Lines: `[time_seconds, "o" or "i", "data"]` per line.
- Mature web replayers available (asciinema-player, no fork needed).
- Trivial to produce server-side from the chunks the agent uploads.

### 7. Capability namespace: `rcp.*`

Agent advertises leaf capabilities, not a single `rcp` umbrella:

```
"capabilities": ["rcp.shell"]    // M1
"capabilities": ["rcp.shell", "rcp.file"]    // M2
"capabilities": ["rcp.shell", "rcp.file", "rcp.screen"]    // M3
```

Backend gates per leaf in UI. Future M4 wires per-tenant role policy to specific leaves (e.g., a tenant role that can `rcp.shell` but not `rcp.file`).

### 8. Initial RBAC: `admin_master` only

For M1-M3, only OIDC subjects with `global_role === "admin_master"` can open RCP sessions. Backend enforces; UI hides the entire Remote Control surface for other roles.

M4 introduces per-tenant role bindings (e.g., a tenant-scoped "operator" role with `rcp.shell` permission only).

### 9. Session model: tied-to-operator with grace period

Sessions terminate when the operator browser disconnects, with a 60 s grace period to handle network blips. Detached / reconnect-after-restart is M5.

### 10. PTY ownership: AgentCore (user context), PrivSvc escalation in M3

The PTY spawns in the agent process (LocalSystem on Windows, the service account on macOS/Linux). When a future policy flag `allowPrivilegedShell` is enabled, the PTY is spawned by PrivSvc to gain SYSTEM-level rights — but that's M3 minimum.

Cross-platform shell:
- Windows: `cmd.exe` by default; `powershell.exe` selectable via session-open metadata.
- macOS/Linux: `bash` default, fall back to `/bin/sh`.

### 11. Concurrent session limits

- Max 3 concurrent sessions per device.
- Max 10 concurrent sessions per operator.
- Rate limit: 5 session opens per operator per minute.
- All values configurable via `tenant_rcp_settings` (M3); hardcoded defaults in M1.

### 12. Session timeouts

- Idle timeout: 30 minutes (no DataChannel I/O for 30 min → server closes).
- Hard cap: 4 hours regardless of activity.
- Operator disconnect grace: 60 s.

### 13. Local echo in UI

xterm.js handles local echo naturally for typed characters. We rely on this rather than reconciliation against a remote echo, because:
- LAN latency to the agent is irrelevant (we echo client-side immediately).
- xterm's built-in echo matches user mental model of an SSH session.

## Milestone plan

| Milestone | Scope | Sprints | Verifiable end state |
|---|---|---|---|
| **M1.S1** | Proto + backend signaling + agent WebRTC peer skeleton | 1 | Browser-side script opens DataChannel to agent, `open` event fires on both ends |
| **M1.S2** | Shell PTY end-to-end + UI (xterm.js) | 1 | admin_master opens shell on Windows/Linux/macOS device from real UI |
| **M1.S3** | Audit transcript (asciinema v2) + hardening | 1 | Closed session replayable from history, idle timeout enforced |
| **M2** | `rcp.file` upload/download via DataChannel + path restrictions | 1-2 | Operator uploads/downloads file, audit log captures path + bytes |
| **M3** | `rcp.screen` — video track + OS consent | 2-3 | Operator views desktop with user consent prompt on the endpoint |
| **M4** | Multi-tenant RBAC beyond admin_master | 1 | Tenant-scoped operator role gated per `rcp.*` leaf |
| **M5** | Detached sessions + reconnect (tmux-style) | 1-2 | Browser reload mid-session resumes the same shell |

## Concrete Sprint 1 (M1.S1) deliverables

### Backend (`certusws-tracenium`)

- Migration `remote_sessions` (per-tenant table): `session_id PK`, `tenant_id`, `device_id`, `operator_user_id`, `type` (shell), `status` (pending/active/closed/error), `created_at`, `started_at`, `ended_at`, `close_reason`, `transport_role` (offerer/answerer)
- gRPC proto: `RemoteSessionSignaling` bi-di stream + 6 messages
- REST endpoint `POST /api/v1/remote-control/sessions` returns `{sessionId, signalingUrl, turnConfig}`
- WebSocket endpoint `/api/v1/remote-control/signaling/:sessionId` with OIDC + admin_master gate
- Signaling relay service in backend: routes browser↔agent SDP/ICE messages
- Cloudflare TURN credential minting helper

### Agent (`certusws-tracenium-agent-w`)

- Install `node-datachannel`
- `src/plugins/rcp/index.ts` — plugin registration, capability advertisement, policy gate
- `src/plugins/rcp/session-manager.ts` — `Map<sessionId, PeerSession>`
- `src/plugins/rcp/webrtc-peer.ts` — wraps PeerConnection + DataChannel, handles offer/answer/ICE
- gRPC stream handler for `RemoteSessionSignaling` messages
- Policy runtime: wire `policy.features.remoteShell` to capability advertisement

### Out of scope for Sprint 1

- PTY spawn (Sprint 2)
- xterm.js UI (Sprint 2 — placeholder Remote Control page stays as-is)
- Audit transcript persistence (Sprint 3)
- Concurrent session limits enforcement (Sprint 3)
- File / screen (M2/M3)

## Verification harness for Sprint 1

Since the UI doesn't land until Sprint 2, Sprint 1 ends with a CLI verification script (`scripts/rcp-signaling-smoke.js` in the agent repo) that:

1. Mints an OIDC token (admin_master).
2. Calls `POST /api/v1/remote-control/sessions` and gets `{sessionId, turnConfig}`.
3. Opens the WebSocket and acts as the "browser" side.
4. Creates a WebRTC peer via `node-datachannel`, generates an SDP offer.
5. Sends offer via WS, receives answer via WS, exchanges ICE.
6. Asserts the DataChannel `open` event fires within 10 s.
7. Sends "ping", expects "pong" echo from agent (Sprint 1 agent echoes; Sprint 2 replaces with PTY).
8. Closes.

This is the gate for "Sprint 1 done." Manual or CI.

## Security gates that must land in M1 (non-negotiable)

- Backend rejects session-open from any subject without `global_role === "admin_master"`.
- WebSocket upgrade rejects without valid OIDC cookie.
- Signaling relay verifies `session_id` belongs to the requesting operator.
- Agent rejects offer if the gRPC stream's authenticated tenant doesn't match the session's tenant.
- TURN credentials are short-lived (15 min) — minted per session, never long-lived.
- Per-device session cap (3) hardcoded in backend; rate limit (5/min/operator) hardcoded.

## Open questions deferred past M1

- Audit transcript redaction (PII scrubbing): heuristic vs catalog-based?
- Operator-to-operator collision: if A is in a session and B opens one to the same device, do they share or does B get rejected? (Suggest: rejected, with notification "session in use by alice@x".)
- WebRTC certificate pinning: use Tracenium's CA or rely on DTLS self-signed?

These can land in M3 hardening without changing the protocol.
