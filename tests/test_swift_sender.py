import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("swift") is None, reason="Swift is unavailable")
def test_swift_queue_discards_stale_capture_and_retries_in_order(tmp_path):
    source = (Path(__file__).parents[1] / "aw_watcher_window/macos.swift").read_text()
    models = source[source.index("struct NetworkMessage:"):source.index("let captureConsent:")]
    models += source[source.index("struct Heartbeat:"):source.index("enum HeartbeatError:")]
    models += source[source.index("let researchBrowserApps ="):source.index("let main =")]
    models += source[source.index("func isResearchBrowser("):source.index("// Return the category")]
    sender = source[source.index("final class HeartbeatSender:"):source.index("let heartbeatSender =")]
    harness = tmp_path / "main.swift"
    harness.write_text("import Foundation\n" + models + sender + r'''
let captureConsent: Bool? = true
let policy = CaptureConsent(recording: true, paused_until: nil, window: true, idle: false,
                            browser: true, titles: false, urls: true, paths: false,
                            excluded_apps: ["secret"], excluded_domains: ["excluded.test"],
                            effective_from: "2000-01-01T00:00:00Z")
assert(policy.filter(NetworkMessage(app: "Zen", title: "private"), at: Date()) == nil)
assert(policy.filter(NetworkMessage(app: "secret editor", title: "private"), at: Date()) == nil)
let minimized = policy.filter(NetworkMessage(app: "Chrome", title: "private",
                              url: "https://user:password@example.test/path?secret=yes",
                              incognito: false), at: Date())!
assert(minimized.title == nil && minimized.url == "https://example.test")
func debug(_ message: String) {}
func log(_ message: String) {}
func createBucket() async throws {}

actor Server {
  var blocked = false
  var released = false
  var failed = false
  var accepted: [(Heartbeat, Double)] = []

  func send(_ heartbeat: Heartbeat, _ pulse: Double) async throws {
    if heartbeat.data.title == "blocked" {
      blocked = true
      while !released { try await Task.sleep(nanoseconds: 1_000_000) }
    }
    if heartbeat.data.title == "retry" && !failed {
      failed = true
      throw NSError(domain: "temporary", code: 1)
    }
    accepted.append((heartbeat, pulse))
  }
  func release() { released = true }
}
let server = Server()
func sendHeartbeatSingle(_ heartbeat: Heartbeat, pulsetime: Double) async throws {
  try await server.send(heartbeat, pulsetime)
}
func heartbeat(_ title: String, _ offset: Double) -> Heartbeat {
  Heartbeat(timestamp: Date(timeIntervalSince1970: offset),
            data: NetworkMessage(app: "editor", title: title))
}
func waitFor(_ condition: () async -> Bool) async {
  for _ in 0..<5000 {
    if await condition() { return }
    try! await Task.sleep(nanoseconds: 1_000_000)
  }
  fatalError("queue did not progress")
}
let done = DispatchSemaphore(value: 0)
Task.detached {
  let sender = HeartbeatSender()
  sender.enqueue(heartbeat("first", 1))
  await waitFor { await server.accepted.count == 1 }
  sender.enqueue(heartbeat("blocked", 3))
  sender.enqueue(heartbeat("stale", 5))
  await waitFor { await server.blocked }
  sender.resetCaptureChain()
  sender.enqueue(heartbeat("resumed", 7))
  await server.release()
  await waitFor { await server.accepted.contains { $0.0.data.title == "resumed" } }
  let resumed = await server.accepted.last!
  assert(resumed.0.data.capture_break == true && resumed.1 == 1)
  let discardedStale = await server.accepted.allSatisfy { $0.0.data.title != "stale" }
  assert(discardedStale)
  sender.enqueue(heartbeat("retry", 9))
  sender.enqueue(heartbeat("following", 11))
  await waitFor { await server.accepted.contains { $0.0.data.title == "following" } }
  let titles = await server.accepted.map { $0.0.data.title! }
  assert(titles.firstIndex(of: "retry")! < titles.firstIndex(of: "following")!)
  done.signal()
}
assert(done.wait(timeout: .now() + 15) == .success)
''')
    subprocess.run(["swift", str(harness)], check=True, timeout=30)
