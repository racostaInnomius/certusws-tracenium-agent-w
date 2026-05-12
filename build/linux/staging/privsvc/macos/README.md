# Tracenium PrivSvc macOS

Privileged helper for macOS agents. It exposes the same JSON-line IPC contract used by the Windows PrivSvc over:

```text
/var/run/tracenium/privsvc.sock
```

Implemented methods:

- `ping`
- `identity`
- `crypto.csr.generate`
- `crypto.cert.install`
- `grpc.connect`
- `grpc.facts.send`
- `grpc.facts.chunk`
- `grpc.ack`
- `grpc.close`
- `security.posture` placeholder

The service is intended to run as `root` via `launchd`. Runtime material is stored under:

```text
/Library/Application Support/Tracenium/PrivSvc
```

Build:

```sh
node ../../node_modules/typescript/bin/tsc -p privsvc/macos/tsconfig.json
```

Install flow for packaging:

1. Copy `privsvc/macos/dist` to `/Library/Application Support/Tracenium/PrivSvc/macos/dist`.
2. Copy `launchd/com.certusws.tracenium.privsvc.plist` to `/Library/LaunchDaemons/`.
3. Set plist ownership to `root:wheel` and mode `644`.
4. Bootstrap with `launchctl bootstrap system /Library/LaunchDaemons/com.certusws.tracenium.privsvc.plist`.
