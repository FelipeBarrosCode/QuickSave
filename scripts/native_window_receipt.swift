// SPDX-License-Identifier: GPL-3.0-only
// Event-driven launch/window evidence only. Does not automate consent, read
// application contents, or inspect another application's data or credentials.
import AppKit
import CoreGraphics
import Foundation

guard (2...3).contains(CommandLine.arguments.count) else {
    fputs("Usage: native_window_receipt.swift /absolute/quicksave-desktop [newly-launched-pid]\n",stderr)
    exit(2)
}
let executable = URL(fileURLWithPath:CommandLine.arguments[1]).standardizedFileURL.path
let expectedPID: Int32?
if CommandLine.arguments.count == 3 {
    guard let pid = Int32(CommandLine.arguments[2]), pid > 0 else {
        fputs("Expected launch PID is invalid\n",stderr)
        exit(2)
    }
    expectedPID = pid
} else {
    expectedPID = nil
}
var observations:[NSObjectProtocol] = []
func recordIfVisible() -> Bool {
    guard let application = NSWorkspace.shared.runningApplications.first(where: {
        $0.executableURL?.standardizedFileURL.path == executable && !$0.isTerminated
            && (expectedPID == nil || $0.processIdentifier == expectedPID)
    }) else { return false }
    let windows = (CGWindowListCopyWindowInfo([.optionAll,.excludeDesktopElements],kCGNullWindowID)
        as? [[String:Any]] ?? []).filter {
        ($0[kCGWindowOwnerPID as String] as? Int32) == application.processIdentifier
            && ($0[kCGWindowLayer as String] as? Int) == 0
            && ($0[kCGWindowIsOnscreen as String] as? Bool) == true
    }
    guard !windows.isEmpty else { return false }
    let receipt:[String:Any] = [
        "executable":executable,
        "pid":application.processIdentifier,
        "expectedLaunchPIDMatched":expectedPID != nil,
        "visibleNativeWindows":windows.count,
        "observedAt":ISO8601DateFormatter().string(from:Date()),
        "method":"NSWorkspace launch/activation notifications plus native window-server visibility",
        "proves":"A visible native window, not native dialogs, provider authentication or backup acceptance"
    ]
    if let bytes = try? JSONSerialization.data(withJSONObject:receipt,options:[.prettyPrinted,.sortedKeys]) {
        FileHandle.standardOutput.write(bytes)
        FileHandle.standardOutput.write(Data("\n".utf8))
        exit(0)
    }
    return false
}
for name in [NSWorkspace.didLaunchApplicationNotification,NSWorkspace.didActivateApplicationNotification] {
    observations.append(NSWorkspace.shared.notificationCenter.addObserver(forName:name,object:nil,queue:.main) { _ in
        _ = recordIfVisible()
    })
}
_ = recordIfVisible()
// A single final deadline check handles a window created after activation;
// there is no periodic process/window/file polling.
DispatchQueue.main.asyncAfter(deadline:.now()+180) {
    if !recordIfVisible() {
        fputs("No visible QuickSave native window was observed before the deadline\n",stderr)
        exit(1)
    }
}
RunLoop.main.run()
