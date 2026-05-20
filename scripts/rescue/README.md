# Rescue scripts for stuck agents

Use these when a device is stuck on an old agent version that won't
self-update through the normal `agent_update` job or auto-update probe
flow. Typical cause: the old version has a bug in its update path that
prevents it from breaking out of its own version (chicken-and-egg).

## Scripts

| File | Target | What it does |
|---|---|---|
| `tracenium-rescue-macos.sh`     | macOS   | Stops daemons, installs new .pkg, verifies no crash loop |
| `tracenium-rescue-windows.ps1`  | Windows | Stops services, uninstalls registered MSI, **hard-deletes** install dir (WiX leftover residuals), adds Defender exclusions, installs new MSI, verifies |

For Linux there's no rescue script needed: `sudo dpkg -i Tracenium-Agent-<v>-x64.deb`
or `sudo rpm -U Tracenium-Agent-<v>-x64.rpm` works cleanly. The Linux
postinstall handles the service restart and the dpkg/rpm tooling
removes the old install bytes before laying down the new ones.

## Deploying to a single device

### macOS
```sh
# Transfer the .pkg + script to the device, then on the device:
scp scripts/rescue/tracenium-rescue-macos.sh \
    build/pkg-out/Tracenium-Agent-1.1.18-arm64.pkg \
    user@mac-host:/tmp/

# SSH in:
ssh user@mac-host
sudo /bin/sh /tmp/tracenium-rescue-macos.sh /tmp/Tracenium-Agent-1.1.18-arm64.pkg
```

### Windows
```powershell
# Transfer .msi + script. From your machine:
# (replace path-to-msi with the actual MSI; replace USER@HOST appropriately)
scp scripts/rescue/tracenium-rescue-windows.ps1 USER@HOST:C:/Temp/
scp build/win-msi/x64/Tracenium-Agent-1.1.18-x64.msi USER@HOST:C:/Temp/

# RDP in, open PowerShell as Administrator:
cd C:\Temp
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\tracenium-rescue-windows.ps1 -MsiPath .\Tracenium-Agent-1.1.18-x64.msi
```

## Deploying to many devices

Three realistic distribution channels:

1. **MDM push** (Jamf Pro / Microsoft Intune / Kandji):
   - Upload the .pkg/.msi as a "package"
   - Upload the rescue script as a "preflight" or "deploy task"
   - Target the stuck devices by their inventory tag
   - MDM handles the rest

2. **RMM** (NinjaOne / Atera / Datto):
   - Same pattern as MDM but for IT-ops tooling
   - Most RMMs have "execute script as admin" + "deploy file" primitives

3. **Manual / IT ticket**:
   - Open a ticket on the user, ask them to run the rescue (with admin
     creds) per the README on this page
   - Document the expected before/after state ("agent version goes from
     1.1.14 → 1.1.18 in the portal within 2 minutes")

## When NOT to use these scripts

These are for **already-stuck** devices that won't auto-update.
For normal release rollouts:
- Backend dispatches `agent_update` job over gRPC stream → agent runs
  its native update flow → device reboots into the new version. No
  script needed.

If a device is at 1.1.18+ and a future release lands (1.1.18, etc.),
the auto-update should work without intervention — the `0655a70`
ubuntu/linux fix and equivalent macOS/Windows fixes in this release
break the chicken-and-egg for good.
