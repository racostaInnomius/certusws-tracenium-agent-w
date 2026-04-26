import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        Logger.shared.info("Agent status app launched")
        statusBarController = StatusBarController()
        statusBarController?.start()
    }

    func applicationWillTerminate(_ notification: Notification) {
        Logger.shared.info("Agent status app terminating")
        statusBarController?.stop()
    }
}
