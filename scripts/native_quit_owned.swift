// SPDX-License-Identifier: GPL-3.0-only
// Request a normal quit of one exact QuickSave process; never force termination.
import AppKit
import Foundation

guard CommandLine.arguments.count == 3,
      let pid = Int32(CommandLine.arguments[2]), pid > 0 else {
    fputs("Usage: native_quit_owned.swift /absolute/quicksave-desktop pid\n", stderr)
    exit(2)
}
let executable = URL(fileURLWithPath:CommandLine.arguments[1]).standardizedFileURL.path
guard let application = NSRunningApplication(processIdentifier:pid),
      application.executableURL?.standardizedFileURL.path == executable else {
    print("The exact prior QuickSave process is no longer running; no quit sent.")
    exit(0)
}
let observer = NSWorkspace.shared.notificationCenter.addObserver(
    forName:NSWorkspace.didTerminateApplicationNotification,object:nil,queue:.main
) { notification in
    guard let stopped = notification.userInfo?[NSWorkspace.applicationUserInfoKey]
            as? NSRunningApplication,
          stopped.processIdentifier == pid else { return }
    print("Prior QuickSave process exited after a normal quit request.")
    exit(0)
}
guard application.terminate() else {
    fputs("QuickSave did not accept normal quit; no force termination attempted.\n",stderr)
    exit(1)
}
if application.isTerminated {
    print("Prior QuickSave process exited.")
    exit(0)
}
// One deadline, not process polling. The app's own active-work/shutdown guard
// remains authoritative; a blocked quit is not permission to kill a worker.
DispatchQueue.main.asyncAfter(deadline:.now()+60) {
    if application.isTerminated {
        print("Prior QuickSave process exited.")
        exit(0)
    }
    fputs("QuickSave has not exited; retained work may need review. No force termination attempted.\n",stderr)
    exit(1)
}
RunLoop.main.run()
