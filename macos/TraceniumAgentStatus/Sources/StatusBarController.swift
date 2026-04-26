import AppKit

final class StatusBarController {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let popover = NSPopover()
    private let reader = StatusSnapshotReader()
    private let contentController = StatusPopoverViewController()
    private var timer: Timer?
    private var lastPresenceState: Bool?
    private var lastConnectivityState: Bool?

    func start() {
        popover.behavior = .transient
        popover.contentViewController = contentController

        if let button = statusItem.button {
            button.title = "Tracenium"
            button.target = self
            button.action = #selector(togglePopover(_:))
        }

        Logger.shared.info("Status bar controller started")

        refresh()

        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        Logger.shared.info("Status bar controller stopped")
    }

    @objc
    private func togglePopover(_ sender: AnyObject?) {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            contentController.render(reader.read())
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    private func refresh() {
        let status = reader.read()
        contentController.render(status)

        let hasSnapshot = status != nil
        if lastPresenceState != hasSnapshot {
            Logger.shared.info(hasSnapshot ? "Snapshot became available" : "Snapshot unavailable")
            lastPresenceState = hasSnapshot
        }

        guard let button = statusItem.button else { return }
        if let status {
            if lastConnectivityState != status.grpc.connected {
                Logger.shared.info(status.grpc.connected ? "Agent connectivity state changed to online" : "Agent connectivity state changed to offline")
                lastConnectivityState = status.grpc.connected
            }
            button.title = status.grpc.connected ? "Tracenium Online" : "Tracenium Offline"
            button.toolTip = "\(status.hostname.isEmpty ? "Tracenium Agent" : status.hostname) · \(status.agentVersion)"
        } else {
            lastConnectivityState = nil
            button.title = "Tracenium Unknown"
            button.toolTip = "No local status snapshot found"
        }
    }
}
