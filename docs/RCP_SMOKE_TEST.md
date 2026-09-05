# RCP end-to-end smoke test

The RCP smoke test has been outstanding since M3.S2. Everything shipped since
then has been validated by unit tests and typechecks only — including code
that **cannot** be executed anywhere but a real Windows endpoint (DXGI desktop
duplication, `SendInput`, the PrivSvc IPC bridge).

This runbook is ordered by risk: the checks most likely to fail, and most
expensive to discover in production, come first.

**Las tres plataformas, en una pasada** (actualizado 2026-09-04). Las fases
1-4 se escribieron para Windows y ahí siguen; las 5-9 son nuevas y cubren lo
que se ha construido desde entonces —consentimiento, cola de aprobación,
propiedad de sesión, salud, auditoría, tope de subida— que en su mayoría es
independiente del sistema operativo. La tabla del final dice qué hay que
correr en cuál.

⚠️ **Nada de esto se puede marcar hecho sin resultados.** Un runbook con
casillas vacías es un runbook que nadie corrió, y hasta ahora la única
evidencia de que RCP funciona en macOS y Linux son tests unitarios.

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

- **Tres equipos enrolados y online**, uno por sistema: Windows 10/11, macOS
  (14+) y Linux (Ubuntu 22.04/24.04). El agente, en **1.1.60 o superior** —
  la versión importa: `/health/rcp`, el tope de subida anunciado en `roots` y
  el consentimiento con `respondedBy` no existen antes.
- En macOS, el permiso de **Grabación de pantalla** concedido al agente en
  Ajustes → Privacidad y seguridad. Sin él la captura falla con un código
  propio (ver `MACOS_TCC_FLOW.md`) y no es un fallo de RCP.
- A tenant policy with `features.remoteShell`, `remoteFile` and `remoteScreen`
  enabled. `remoteRequireConsent` se prueba en la fase 5, así que empieza
  **apagado** y se enciende ahí.
- **Tres identidades** en el portal: `admin_master`, un `ADMIN` del tenant y
  un `USER` del mismo tenant. La fase 3 las usa; la 6 necesita además un
  segundo `ADMIN` distinto del que pide, porque la autoaprobación está
  prohibida a propósito.
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

⚠️ Desde M4 el gate NO es "solo admin_master": es el rol ADMIN u OWNER **en
el tenant del equipo**. La copia del portal decía lo primero y se corrigió;
si vuelve a aparecer "admin_master-only" en la UI, es una regresión de texto,
no de permisos.

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

## Phase 5 — Consentimiento del usuario (ADR-0012)

La razón por la que el aviso existe es que la persona pueda decir que no. Lo
que hay que comprobar es que ese "no" **llega, se distingue y se guarda**.

Enciende `remoteRequireConsent` en la política del tenant y repite en cada
sistema:

### 5.1 Aceptar

1. Pide una sesión de pantalla contra el equipo.
2. En el equipo aparece el aviso. Acepta.

**Expect:** la sesión abre. En la línea de tiempo del detalle de la sesión
(portal → Remote Control → Sessions → la fila) hay `Session requested` y
`Connected`.

### 5.2 Rechazar

Pide otra y **deniega** en el equipo.

**Expect en el portal:** "The person at the device declined." — con esas
palabras, no un código. **Regresión** si dice "Session ended." o
`consent_denied` en crudo: significa que el visor volvió a tirar el motivo, y
entonces alguien negándose y una red rota se ven igual.

**Expect en la base del tenant:**

```sql
SELECT event, source, actor, detail
  FROM remote_session_events
 WHERE session_id = '<sess>'
 ORDER BY occurred_at;
```

Tiene que haber una fila `consent_denied` **antes** de la `closed`, con
`source = 'agent'` y `actor` a NULL. Si el `consent_denied` no está y solo
aparece dentro del `detail` del `closed`, es la versión anterior del backend.

### 5.3 No contestar

Pide una tercera y deja el aviso sin tocar hasta que caduque.

**Expect:** "Nobody answered on the device." y un evento `consent_timeout`.
Que se distinga del rechazo es el punto: uno se reintenta llamando por
teléfono y el otro no se reintenta.

### 5.4 El agente que no sabe preguntar

Contra un equipo **sin** `rcp.consent` anunciado (un agente viejo, o un
servidor sin sesión de usuario) y con la política exigiendo consentimiento:

**Expect:** la sesión **no abre**, y el mensaje explica que el equipo no puede
preguntar. Falla cerrado a propósito: abrir sin preguntar sería justo lo que
la política prohíbe.

---

## Phase 6 — Cola de aprobación (ADR-0009 fase 2)

Con la matriz de política exigiendo vistobueno para la clase del equipo:

### 6.1 Queda pendiente, no falla

Pide una sesión como `ADMIN`.

**Expect:** el portal dice "Access queued" con un identificador, **no** un
error. Un rechazo aquí haría reintentar en bucle y cada intento dejaría una
petición pendiente nueva.

### 6.2 Nadie se aprueba a sí mismo

Intenta aprobar tu propia petición con la misma identidad.

**Expect:** 409 `SELF_APPROVAL_FORBIDDEN`.

### 6.3 La decisión queda escrita

Aprueba con el **segundo** ADMIN y abre la sesión. Luego:

```sql
SELECT event, actor, actor_ip, detail
  FROM remote_session_events
 WHERE session_id IN ('<requestId>', '<sessionId>')
 ORDER BY occurred_at;
```

**Expect:** `gated` → `approved` (con `actor` = el aprobador y
`detail->>'requestedBy'` = el solicitante) → `requested` → `connected`. Deniega
otra petición y comprueba que deja un `denied`: una tabla donde solo constan
las aprobaciones dice que aquí siempre se dice que sí.

### 6.4 Break-glass (solo OWNER)

Ábrelo y comprueba que la fila `break_glass` sale **en negrita y en rojo** en
la línea de tiempo, y que llegó el correo. No es silenciable por diseño.

---

## Phase 7 — Propiedad de sesión y salud

### 7.1 `/health/rcp` responde sin autenticar

Desde fuera, contra el host REST:

```bash
curl -s https://api.tracenium.com/api/v1/health/rcp | jq
```

**Expect:** 200 con el detalle. **Regresión** si contesta 401: montado detrás
del middleware OIDC, un 401 es indistinguible de un servicio caído, que es
exactamente lo que un health check existe para distinguir.

### 7.2 Un agente no puede tocar la sesión de otro

No hace falta un agente comprometido: basta mirar que la tabla está vacía y
sigue vacía en operación normal.

```sql
SELECT COUNT(*) FROM security_events
 WHERE event_type = 'RCP_SESSION_OWNERSHIP_REJECTED';
```

**Expect:** 0 durante todo el smoke test. Cualquier fila aquí es un agente
actuando sobre una sesión que no es suya — y el detalle dice cuál y de quién.

### 7.3 Las credenciales TURN no están en claro

```sql
SELECT payload::text FROM rcp_signal_queue ORDER BY id DESC LIMIT 5;
```

**Expect:** ningún `turn:` ni credencial dentro del payload de las ofertas.
Desde 2026-09-05 se leen del routing al entregar. Y con `RCP_SECRETS_KEY`
definida **en los dos hosts** (REST y gRPC), `rcp_session_routing.ice_servers_json`
tampoco es legible a simple vista.

⚠️ Si la clave está en un solo lado, la sesión muere con `ice_failed` sin
decir por qué: el agente recibe una configuración ICE ilegible. Esa es la
comprobación real de esta casilla — que las sesiones **abren**.

---

## Phase 8 — Tope de subida y auditoría de ficheros

### 8.1 El fichero grande se rechaza ANTES de subir

Con `remoteControl.maxUploadBytes` puesto en la política (por ejemplo 1 MB),
arrastra un fichero de 5 MB al panel de ficheros.

**Expect:** un mensaje inmediato que dice cuánto acepta el equipo y cuánto
ocupa el fichero, **sin** barra de progreso. La regresión es que la barra
avance y falle al final: eso significa que el rechazo volvió a ocurrir en el
agente, con la sesión de transferencia ya abierta.

**Contra un agente anterior a 1.1.60** (que no anuncia el tope): la subida
debe intentarse igual. No inventamos un límite que el equipo no ha dicho.

### 8.2 El filtro de la auditoría es del servidor

En la pestaña Transfers, con más de 25 transferencias en el histórico, filtra
por `Failed`.

**Expect:** el contador dice "N matching" sobre TODO el histórico y la
paginación vuelve a la página 1. La regresión es una tabla vacía con el filtro
puesto —el filtro aplicándose solo a la página cargada—, que se lee como "no
ha fallado ninguna".

### 8.3 Una transferencia deja rastro ligado a la sesión

Sube y descarga un fichero pequeño.

```sql
SELECT event, detail->>'path', detail->>'bytes'
  FROM remote_session_events
 WHERE session_id = '<sess>' AND event LIKE 'file_%';
```

**Expect:** un `file_upload` y un `file_download`, solo en el estado terminal
(el agente dispara dos eventos por transferencia y aquí solo cuenta el final).

---

## Phase 9 — Pantalla y cierre, por sistema

Esto es lo que cambió en el backend y hay que ver en los tres:

1. Abre una sesión de pantalla y ciérrala desde el portal.
2. Consulta la sesión:

```sql
SELECT status, close_reason, ended_at FROM remote_sessions WHERE session_id = '<sess>';
SELECT event, source FROM remote_session_events WHERE session_id = '<sess>' ORDER BY occurred_at;
```

**Expect:** `close_reason` **NO NULL** (`operator_closed` o
`operator_disconnected`), un `screen_stopped` del agente y un `closed` del
sistema. Hasta el 04-sep toda sesión de pantalla terminaba con `close_reason`
NULL: el audit de pantalla cerraba la fila antes de que llegara el motivo.

---

## Qué correr en cada sistema

| Fase | Windows | macOS | Linux | Nota |
|---|---|---|---|---|
| 1 — Pantalla (dirty rects, DXGI) | ✅ | ⚠️ solo 1.1, 1.5, 1.7 | ⚠️ solo 1.1, 1.5, 1.7 | Los rects sucios y las estadísticas son de DXGI: Windows. |
| 2 — Confinamiento de ficheros | ✅ | ✅ | ✅ | 2.5 (`O_NOFOLLOW`) solo tiene sentido en POSIX. |
| 3 — Autorización | ✅ | — | — | Es del control plane; una vez basta. |
| 4 — Retención | ✅ | — | — | Idem. |
| 5 — Consentimiento | ✅ | ✅ | ✅ | El aviso es nativo por sistema: hay que verlo en los tres. |
| 6 — Aprobación | ✅ | — | — | Control plane. |
| 7 — Propiedad y salud | ✅ | — | — | 7.3 se mira una vez, con sesiones de los tres. |
| 8 — Subida y auditoría | ✅ | ✅ | ✅ | El tope lo anuncia el agente. |
| 9 — Cierre de pantalla | ✅ | ✅ | ✅ | El camino que estaba roto. |

---

## Recording the outcome

Note per check: pass / fail / not run, and for 1.2 paste one `stream stats`
line — it is the only quantitative evidence that dirty rects engaged, and it is
worth keeping for comparison after future capture changes.

Para las fases 5-9, apunta además la **versión del agente** de cada equipo y
pega la salida de las consultas SQL. Una casilla marcada sin la fila que la
respalda no es evidencia: es una intención.

### Resultados

| Fase | Windows | macOS | Linux | Fecha | Notas |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | — | — | | |
| 4 | | — | — | | |
| 5 | | | | | |
| 6 | | — | — | | |
| 7 | | — | — | | |
| 8 | | | | | |
| 9 | | | | | |
