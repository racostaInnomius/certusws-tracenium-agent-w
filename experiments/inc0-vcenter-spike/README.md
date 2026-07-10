# Inc 0 spike — vCenter 8 snapshot + UUID matching

Throwaway PoC for **[ADR-0001: Patch Management Gateway](../../../certusws-tracenium/docs/adr/ADR-0001-patch-management-gateway.md)**.
It retires the two unknowns that gate the whole feature, run against a **real vCenter 8 lab**:

1. **Does snapshot create → (revert) → remove work**, and how fast?
2. **Can we correlate a Tracenium endpoint to its vCenter VM** using the SMBIOS UUID
   the agent already collects (`system.uuid`) — and is the **ESXi byte-swap** needed?
3. Bonus, decided empirically: **does this build expose snapshots over the REST API**,
   or must Inc 1 use SOAP?

No production code. **Zero dependencies** — Node ≥ 18 built-ins only (`https`, `tls`, `crypto`).
Nothing is installed; nothing here is compiled by the agent build (`tsconfig` only includes `src/`).

## Run

```bash
cd experiments/inc0-vcenter-spike
cp .env.example .env          # fill in VC_URL / VC_USER / VC_PASS
set -a; source .env; set +a   # load env
node vcenter-spike.mjs
```

First run tip: leave `TARGET_VM_UUID` empty — the script logs in and **lists every VM
with its `config.uuid` and `config.instanceUuid`**, so you can pick a target and grab the
UUID the agent would report for it. Then set `TARGET_VM_UUID` and run again.

## What it does (in order)

1. TLS connect → prints the server cert **SHA-256** (pin it later via `VC_THUMBPRINT`).
2. SOAP `RetrieveServiceContent` + `Login` against `/sdk` (vSphere Web Services API).
3. `CreateContainerView` + `RetrieveProperties` → inventory of VMs (name/uuid/instanceUuid).
4. **UUID matching**: `FindByUuid` with the raw SMBIOS uuid, the byte-swapped uuid, and
   the instance uuid — and reports **which one hits `config.uuid`**. This is the crux:
   - *raw hits* → Inc 1 matches directly, no swap.
   - *swapped hits* → Inc 1 must byte-swap the first 3 UUID fields before matching.
   - *only instance hits* / *none* → the correlation key needs a rethink (flagged red).
5. **Snapshot lifecycle** on the target VM: `CreateSnapshot_Task` (memory/quiesce configurable)
   → optional `RevertToSnapshot_Task` → `RemoveSnapshot_Task`, each polled to completion with timings.
6. **REST probe**: opens `/api/session`, then `GET /api/vcenter/vm/{moref}/snapshots` and reports
   the HTTP status so we learn whether REST snapshots exist on *this* build.
7. Prints a **SUMMARY** table and a **DECISION GATE** verdict.

## Safety

- `SPIKE_CREATE=true` (default) creates **and removes** a snapshot — non-destructive to VM state.
- `SPIKE_REVERT=true` (default **false**) additionally tests **revert**, which **rolls the VM
  back** to the just-taken snapshot (with `memory=false` this powers the VM off). Only enable
  against a throwaway lab VM.
- Use a least-privilege vSphere service account: **Virtual Machine → Snapshot Management →
  Create/Remove/Revert**, scoped to a test folder. That's exactly the role Inc 1 will require.
- Creds come from env only. `.env` is git-ignored. The script never logs the password.

## Reading the result

The `DECISION GATE` block at the end says:
- whether snapshot create/remove is proven,
- whether UUID correlation is reliable (and if a byte-swap is required),
- whether Inc 1 should use REST or SOAP for snapshots.

Paste that block back and we lock the Inc 1 contract (`vcenter_snapshot` job payload + the
vSphere client choice) accordingly.
