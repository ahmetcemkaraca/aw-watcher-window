import Cocoa
import ScriptingBridge

@objc protocol ChromeTab {
  @objc optional var URL: String { get }
  @objc optional var title: String { get }
}

@objc protocol ChromeWindow {
  @objc optional var activeTab: ChromeTab { get }
  @objc optional var mode: String { get }
}

extension SBObject: ChromeWindow, ChromeTab {}

@objc protocol ChromeProtocol {
  @objc optional func windows() -> [ChromeWindow]
}

extension SBApplication: ChromeProtocol {}

// https://github.com/tingraldi/SwiftScripting/blob/4346eba0f47e806943601f5fb2fe978e2066b310/Frameworks/SafariScripting/SafariScripting/Safari.swift#L37

@objc public protocol SafariDocument {
    @objc optional var name: String { get } // Its name.
    @objc optional var modified: Bool { get } // Has it been modified since the last save?
    @objc optional var file: URL { get } // Its location on disk, if it has one.
    @objc optional var source: String { get } // The HTML source of the web page currently loaded in the document.
    @objc optional var URL: String { get } // The current URL of the document.
    @objc optional var text: String { get } // The text of the web page currently loaded in the document. Modifications to text aren't reflected on the web page.
    @objc optional func setURL(_ URL: String!) // The current URL of the document.
}

@objc public protocol SafariTab {
    @objc optional var source: String { get } // The HTML source of the web page currently loaded in the tab.
    @objc optional var URL: String { get } // The current URL of the tab.
    @objc optional var index: NSNumber { get } // The index of the tab, ordered left to right.
    @objc optional var text: String { get } // The text of the web page currently loaded in the tab. Modifications to text aren't reflected on the web page.
    @objc optional var visible: Bool { get } // Whether the tab is currently visible.
    @objc optional var name: String { get } // The name of the tab.
    @objc optional func setURL(_ URL: String!) // The current URL of the tab.
}

@objc public protocol SafariWindow {
    @objc optional var name: String { get } // The title of the window.
    @objc optional func id() -> Int // The unique identifier of the window.
    @objc optional var index: Int { get } // The index of the window, ordered front to back.
    @objc optional var document: SafariDocument { get } // The document whose contents are displayed in the window.
    @objc optional func tabs() -> SBElementArray
    @objc optional var currentTab: SafariTab { get } // The current tab.
}
extension SBObject: SafariWindow {}

@objc public protocol SafariApplication {
    @objc optional func documents() -> SBElementArray
    @objc optional func windows() -> [SafariWindow]
    @objc optional var name: String { get } // The name of the application.
    @objc optional var frontmost: Bool { get } // Is this the active application?
}
extension SBApplication: SafariApplication {}

// Local credentials stay in memory and never appear in a URL or log message.
final class NoCaptureRedirects: NSObject, URLSessionTaskDelegate {
  func urlSession(_ session: URLSession, task: URLSessionTask,
                  willPerformHTTPRedirection response: HTTPURLResponse,
                  newRequest request: URLRequest,
                  completionHandler: @escaping (URLRequest?) -> Void) {
    completionHandler(nil)
  }
}

actor CaptureHTTP {
  private var token = ProcessInfo.processInfo.environment["PEAKACTIVITY_API_TOKEN"]
  private let refresh = ProcessInfo.processInfo.environment["PEAKACTIVITY_API_REFRESH"]
  private let origin = ProcessInfo.processInfo.environment["PEAKACTIVITY_API_ORIGIN"].flatMap(URL.init(string:))
  private let session: URLSession = {
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 10
    config.httpCookieStorage = nil
    return URLSession(configuration: config, delegate: NoCaptureRedirects(), delegateQueue: nil)
  }()

  private func validToken(_ value: String) -> Bool {
    value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  func upload(_ original: URLRequest, payload: Data) async throws -> HTTPURLResponse {
    var request = original
    if let token = token {
      guard let url = request.url, let origin = origin,
            url.scheme == "http", origin.scheme == "http",
            ["localhost", "127.0.0.1", "::1"].contains(url.host ?? ""),
            ["localhost", "127.0.0.1", "::1"].contains(origin.host ?? ""),
            url.port == origin.port, validToken(token) else {
        throw HeartbeatError.error(msg: "Capture credential origin mismatch")
      }
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    }
    var (_, response) = try await session.upload(for: request, from: payload)
    if (response as? HTTPURLResponse)?.statusCode == 401, token != nil,
       let refresh = refresh, let origin = origin {
      var renewal = URLRequest(url: origin.appendingPathComponent("api/0/session/refresh"))
      renewal.httpMethod = "POST"
      renewal.setValue("application/json", forHTTPHeaderField: "Content-Type")
      let body = try JSONSerialization.data(withJSONObject: ["refresh_token": refresh])
      let (data, renewed) = try await session.upload(for: renewal, from: body)
      if (renewed as? HTTPURLResponse)?.statusCode == 200,
         let result = try JSONSerialization.jsonObject(with: data) as? [String: String],
         let replacement = result["access_token"], validToken(replacement) {
        token = replacement
        request.setValue("Bearer \(replacement)", forHTTPHeaderField: "Authorization")
        (_, response) = try await session.upload(for: request, from: payload)
      }
    }
    guard let http = response as? HTTPURLResponse else {
      throw HeartbeatError.error(msg: "Invalid local server response")
    }
    if let replacement = http.value(forHTTPHeaderField: "X-PeakActivity-Token"), validToken(replacement) {
      token = replacement
    }
    return http
  }
}
let captureHTTP = CaptureHTTP()

// AW-specific structs

struct NetworkMessage: Codable, Equatable {
  var app: String
  var title: String?
  var url: String?
  var incognito: Bool? = nil
  var capture_break: Bool? = nil
}

struct CaptureConsent: Decodable {
  let recording: Bool
  let paused_until: String?
  let window: Bool
  let idle: Bool
  let browser: Bool
  let titles: Bool
  let urls: Bool
  let paths: Bool
  let excluded_apps: [String]
  let excluded_domains: [String]
  let effective_from: String

  static func date(_ text: String) -> Date? {
    let parser = ISO8601DateFormatter()
    parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = parser.date(from: text) { return date }
    parser.formatOptions = [.withInternetDateTime]
    return parser.date(from: text)
  }

  func filter(_ input: NetworkMessage, at time: Date) -> NetworkMessage? {
    guard recording, let effective = Self.date(effective_from), time >= effective else { return nil }
    if let until = paused_until {
      guard let deadline = Self.date(until), Date() >= deadline, time >= deadline else { return nil }
    }
    let app = input.app.lowercased()
    if excluded_apps.contains(where: { app.contains($0) }) { return nil }
    let isBrowser = input.url != nil || ["chrome", "chromium", "firefox", "safari", "brave", "msedge", "microsoft edge", "opera"].contains(where: { app.contains($0) })
    if isBrowser && (!browser || input.incognito != false) { return nil }
    if !isBrowser && !window { return nil }
    if input.incognito == true { return nil }
    var output = input
    if let value = input.url {
      guard var url = URLComponents(string: value), let host = url.host?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")),
            ["http", "https"].contains(url.scheme ?? "") else { return nil }
      if excluded_domains.contains(where: { host == $0 || host.hasSuffix("." + $0) }) { return nil }
      url.host = host; url.user = nil; url.password = nil
      url.path = ""; url.query = nil; url.fragment = nil
      if (url.scheme == "https" && url.port == 443) || (url.scheme == "http" && url.port == 80) { url.port = nil }
      output.url = urls ? url.string : nil
    }
    if !titles { output.title = nil }
    return output
  }
}

let captureConsent: CaptureConsent? = {
  guard ProcessInfo.processInfo.environment["PEAKACTIVITY_CAPTURE"] == "1" else { return nil }
  guard let raw = ProcessInfo.processInfo.environment["PEAKACTIVITY_CAPTURE_POLICY"],
        let bytes = raw.data(using: .utf8),
        let consent = try? JSONDecoder().decode(CaptureConsent.self, from: bytes),
        CaptureConsent.date(consent.effective_from) != nil else {
    fatalError("Native capture requires a valid policy")
  }
  return consent
}()

struct Heartbeat: Codable {
  var timestamp: Date
  var data: NetworkMessage
}

enum HeartbeatError: Error {
  case error(msg: String)
}

struct Bucket: Codable {
  var client: String
  var type: String
  var hostname: String
}

// there's no builtin logging library on macos which has levels & hits stdout, so we build our own simple one
// there a complex open source one, but it makes it harder to compile this simple one-file swift application
let dateFormatter =  DateFormatter();

func logTimestamp() -> String {
  let now = Date()
  dateFormatter.timeZone = TimeZone.current
  dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
  return dateFormatter.string(from: now)
}

// generate log prefix based on level
func logPrefix(_ level: String) -> String {
  return "\(logTimestamp()) [aw-watcher-window-macos] [\(level)]"
}

let logLevel = ProcessInfo.processInfo.environment["LOG_LEVEL"]?.uppercased() ?? "INFO"

func debug(_ msg: String) {
  if (logLevel == "DEBUG") {
    print("\(logPrefix("DEBUG")) \(msg)")
    fflush(stdout)
  }
}

func log(_ msg: String) {
  print("\(logPrefix("INFO")) \(msg)")
  fflush(stdout)
}

func error(_ msg: String) {
  print("\(logPrefix("ERROR")) \(msg)")
  fflush(stdout)
}

// Placeholder values, set in start() from CLI arguments
var baseurl = "http://localhost:5600"
// NOTE: this differs from the hostname we get from Python, here we get `.local`, but in Python we get `.localdomain`
var clientHostname = ProcessInfo.processInfo.hostName
var clientName = "aw-watcher-window"
var bucketName = "\(clientName)_\(clientHostname)"
var excludeTitle = false
var excludeTitlePatterns: [NSRegularExpression] = []
var researchEnabled = false
var researchCategoryMap: [(pattern: String, category: String)] = []

let researchBrowserApps = Set([
  "chrome",
  "google chrome",
  "google chrome canary",
  "google-chrome",
  "google-chrome-beta",
  "google-chrome-unstable",
  "chromium",
  "chromium-browser",
  "brave browser",
  "brave",
  "brave-browser",
  "firefox",
  "firefox developer edition",
  "firefox-esr",
  "safari",
  "edge",
  "microsoft edge",
  "microsoft-edge",
  "microsoft-edge-beta",
  "microsoft-edge-dev",
  "opera",
  "chrome.exe",
  "brave.exe",
  "firefox.exe",
  "msedge.exe",
  "opera.exe",
])

let main = MainThing()
private var oldHeartbeat: Heartbeat?
private var captureEpoch: UInt64 = 0
private let heartbeatStateLock = NSLock()

func heartbeatSnapshot() -> (Heartbeat?, UInt64) {
  heartbeatStateLock.lock()
  defer { heartbeatStateLock.unlock() }
  return (oldHeartbeat, captureEpoch)
}

func resetCaptureChain() {
  heartbeatStateLock.lock()
  defer { heartbeatStateLock.unlock() }
  oldHeartbeat = nil
  captureEpoch &+= 1
}

func rememberHeartbeat(_ heartbeat: Heartbeat, epoch: UInt64) {
  heartbeatStateLock.lock()
  defer { heartbeatStateLock.unlock() }
  guard epoch == captureEpoch, oldHeartbeat == nil || oldHeartbeat!.timestamp <= heartbeat.timestamp else { return }
  var stored = heartbeat
  stored.data.capture_break = nil
  oldHeartbeat = stored
}

let encoder = JSONEncoder()
let formatter = ISO8601DateFormatter()
formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

encoder.dateEncodingStrategy = .custom({ date, encoder in
  var container = encoder.singleValueContainer()
  let dateString = formatter.string(from: date)
  try container.encode(dateString)
})

start()
RunLoop.main.run()

func compileExcludeTitlePattern(_ pattern: String) -> NSRegularExpression {
  do {
    return try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
  } catch let regexError {
    error("Invalid title exclusion pattern")
    exit(1)
  }
}

func parseOptionalArguments(_ arguments: ArraySlice<String>) {
  var index = arguments.startIndex
  while index < arguments.endIndex {
    let argument = arguments[index]

    if argument == "--exclude-title" {
      excludeTitle = true
      index = arguments.index(after: index)
      continue
    }

    if argument == "--exclude-titles" {
      let nextIndex = arguments.index(after: index)
      guard nextIndex < arguments.endIndex else {
        error("Missing value for --exclude-titles")
        exit(1)
      }
      excludeTitlePatterns.append(compileExcludeTitlePattern(arguments[nextIndex]))
      index = arguments.index(after: nextIndex)
      continue
    }

    if argument == "--research" {
      researchEnabled = true
      index = arguments.index(after: index)
      continue
    }

    if argument == "--research-category" {
      let patternIndex = arguments.index(after: index)
      let categoryIndex = patternIndex < arguments.endIndex ? arguments.index(after: patternIndex) : arguments.endIndex
      guard patternIndex < arguments.endIndex, categoryIndex < arguments.endIndex else {
        error("Missing pattern/category values for --research-category")
        exit(1)
      }
      researchCategoryMap.append((pattern: arguments[patternIndex], category: arguments[categoryIndex]))
      index = arguments.index(after: categoryIndex)
      continue
    }

    error("Unknown command-line option")
    exit(1)
  }
}

func titleShouldBeExcluded(_ title: String) -> Bool {
  let range = NSRange(title.startIndex..<title.endIndex, in: title)
  return excludeTitlePatterns.contains { pattern in
    pattern.firstMatch(in: title, options: [], range: range) != nil
  }
}

func isResearchBrowser(_ app: String) -> Bool {
  return researchBrowserApps.contains(app.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
}

func classifyResearch(_ title: String, url: String?) -> String {
  // Try URL first — more reliable than page title, which can change mid-load
  if let url = url, !url.isEmpty {
    for item in researchCategoryMap {
      if url.range(of: item.pattern, options: [.caseInsensitive]) != nil {
        return item.category
      }
    }
  }
  for item in researchCategoryMap {
    if title.range(of: item.pattern, options: [.caseInsensitive]) != nil {
      return item.category
    }
  }
  return "excluded"
}

func applyResearchFilter(_ data: NetworkMessage) -> NetworkMessage {
  if !researchEnabled {
    return data
  }

  if isResearchBrowser(data.app) {
    return NetworkMessage(app: data.app, title: classifyResearch(data.title ?? "", url: data.url), url: nil)
  }

  return NetworkMessage(app: data.app, title: nil, url: nil)
}

func start() {
  // Arguments should be:
  //  - url + port
  //  - bucket_id
  //  - hostname
  //  - client_id
  let arguments = CommandLine.arguments

  // Check that we get the 4 required arguments plus any optional flags
  if arguments.count < 5 {
    print("Usage: aw-watcher-window <url> <bucket> <hostname> <client> [--exclude-title] [--exclude-titles <pattern> ...] [--research] [--research-category <pattern> <category> ...]")
    exit(1)
  }

  baseurl = arguments[1]
  bucketName = arguments[2]
  clientHostname = arguments[3]
  clientName = arguments[4]
  parseOptionalArguments(arguments.dropFirst(5))

  guard checkAccess() else {
    DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
      start()
    }
    return
  }

  createBucket()

  // listen for changes in focused application
  NSWorkspace.shared.notificationCenter.addObserver(
    main,
    selector: #selector(main.focusedAppChanged),
    name: NSWorkspace.didActivateApplicationNotification,
    object: nil
  )

  main.focusedAppChanged()

  // Start the polling timer
  main.pollingTimer = Timer.scheduledTimer(timeInterval: 10.0, target: main, selector: #selector(main.pollActiveWindow), userInfo: nil, repeats: true)
}

// TODO might be better to have the python wrapper create this before launching the swift application
func createBucket() {
  let payload = try! encoder.encode(
    Bucket(client: clientName, type: "currentwindow", hostname: clientHostname))

  let url = URL(string: "\(baseurl)/api/0/buckets/\(bucketName)")!
  Task {
    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = "POST"
    urlRequest.addValue("application/json", forHTTPHeaderField: "Content-Type")
    let response = try await captureHTTP.upload(urlRequest, payload: payload)
    guard (200...299).contains(response.statusCode) else {
      log("Failed to create bucket")
      return
    }
  }
}

func sendHeartbeat(_ incoming: Heartbeat) {
  let (previous, epoch) = heartbeatSnapshot()
  var heartbeat = incoming
  if captureConsent != nil && previous == nil { heartbeat.data.capture_break = true }
  let oldPayloadDifferent = previous != nil && previous!.data != heartbeat.data
  let timeSinceLastHeartbeat = previous != nil ? heartbeat.timestamp.timeIntervalSince(previous!.timestamp) : -1.0

  // if you resize a window a ton of events (subsecond) will be fired
  // we enforce a 1s minimum gap between events to avoid this
  if timeSinceLastHeartbeat != -1.0 && timeSinceLastHeartbeat <= 0.5 {
    debug("skipping heartbeat, last heartbeat was sent 1s ago")
    return
  }

  // TODO running these async could cause weird state issues since the observer stuff can send a log of heartbeats
  //      in a short time under certain circumstances, and we don't want to send them all
  Task {
    guard heartbeatSnapshot().1 == epoch else { return }
    if oldPayloadDifferent {
      debug("sending old heartbeat for merging")

      do {
        // unlike the python aw-client library, we do not enforce a `commit_interval` and instead send the old event (which is not invalid)
        // at the current time with a pulse value equal to the time since this event was originally sent. The aw-server will then merge
        // this new event with the original event, extending the recorded time spent on this particular window/application.

        let refreshedOldHeartbeat = Heartbeat(
          // it is important to refresh the hearbeat using the timestamp where the user stopped working on the previous application
          // more info: https://github.com/ActivityWatch/aw-watcher-window/pull/69
          // we don't *think* this millisecond subtraction is necessary, but it may be:
          // https://github.com/ActivityWatch/aw-watcher-window/pull/69#discussion_r987064282
          timestamp: heartbeat.timestamp - 0.001,
          data: previous!.data
        )

        try await sendHeartbeatSingle(refreshedOldHeartbeat, pulsetime: timeSinceLastHeartbeat + 1)
      } catch {
        log("Failed to send old heartbeat: \(error)")
        return
      }
    }

    guard heartbeatSnapshot().1 == epoch else { return }
    do {
      let since_last_seconds = previous != nil ? heartbeat.timestamp.timeIntervalSince(previous!.timestamp) : 0
      try await sendHeartbeatSingle(heartbeat, pulsetime: since_last_seconds + 1)
    } catch {
      log("Failed to send heartbeat: \(error)")
      return
    }

    rememberHeartbeat(heartbeat, epoch: epoch)
  }
}

func sendHeartbeatSingle(_ heartbeat: Heartbeat, pulsetime: Double) async throws {
  let url = URL(string: "\(baseurl)/api/0/buckets/\(bucketName)/heartbeat?pulsetime=\(pulsetime)")!

  var urlRequest = URLRequest(url: url)
  urlRequest.httpMethod = "POST"
  urlRequest.addValue("application/json", forHTTPHeaderField: "Content-Type")

  let payload = try! encoder.encode(heartbeat)
  let response = try await captureHTTP.upload(urlRequest, payload: payload)

  guard (200...299).contains(response.statusCode) else {
    throw HeartbeatError.error(msg: "Local heartbeat was rejected")
  }

  debug("Heartbeat sent")
}

class MainThing {
  var observer: AXObserver?
  var oldWindow: AXUIElement?
  var pollingTimer: Timer?

  // list of chrome equivalent browsers
  let CHROME_BROWSERS = [
    "Google Chrome",
    "Google Chrome Canary",
    "Chromium",
    "Brave Browser",
  ]

  @objc func pollActiveWindow() {
    debug("Polling active window")

    guard let frontmost = NSWorkspace.shared.frontmostApplication else {
      log("Failed to get frontmost application from polling")
      return
    }

    let pid = frontmost.processIdentifier
    let focusedApp = AXUIElementCreateApplication(pid)

    var focusedWindow: AnyObject?
    AXUIElementCopyAttributeValue(focusedApp, kAXFocusedWindowAttribute as CFString, &focusedWindow)

    if focusedWindow != nil {
      focusedWindowChanged(observer!, window: focusedWindow as! AXUIElement)
    }
  }

  deinit {
    pollingTimer?.invalidate()
  }

  func windowTitleChanged(
    _ axObserver: AXObserver,
    axElement: AXUIElement,
    notification: CFString
  ) {
    guard let frontmost = NSWorkspace.shared.frontmostApplication else {
      log("Failed to get frontmost application from window title notification")
      return
    }

    // calculate now before executing any scripting since that can take some time
    let nowTime = Date.now

    var windowTitle: AnyObject?
    AXUIElementCopyAttributeValue(axElement, kAXTitleAttribute as CFString, &windowTitle)

    let applicationName = frontmost.localizedName ?? frontmost.bundleIdentifier ?? ""
    var data = NetworkMessage(app: applicationName, title: windowTitle as? String ?? "")

    if let consent = captureConsent,
       (CHROME_BROWSERS.contains(applicationName) || applicationName == "Safari") && !consent.browser {
      resetCaptureChain()
      return
    }
    if CHROME_BROWSERS.contains(applicationName) {
      debug("Chrome browser detected, extracting URL and title")

      guard let bundleIdentifier = frontmost.bundleIdentifier else {
        log("Failed to get bundle identifier from frontmost application, which was recognized to be Chrome")
        return
      }
      let chromeObject: ChromeProtocol = SBApplication.init(bundleIdentifier: bundleIdentifier)!

      guard let windows = chromeObject.windows,
            let frontWindow = windows().first else {
        log("Failed to get chrome front window")
        return
      }
      guard let activeTab = frontWindow.activeTab else {
        log("Failed to get chrome active tab")
        return
      }

      if frontWindow.mode == "incognito" {
        resetCaptureChain()
        return
      } else {
        data.incognito = frontWindow.mode == "normal" ? false : nil
        data.url = activeTab.URL

        // the tab title is more accurate and often different than the window title
        // however, in some cases the binary does not have the right permissions to read
        // the title properly and will return a blank string

        if let tabTitle = activeTab.title {
          if(tabTitle != "" && data.title != tabTitle) {
            debug("Browser tab title differs from window title")
            data.title = tabTitle
          }
        }
      }
    } else if frontmost.localizedName == "Safari" {
      debug("Safari browser detected, extracting URL and title")

      guard let bundleIdentifier = frontmost.bundleIdentifier else {
        log("Failed to get bundle identifier from frontmost application, which was recognized to be Safari")
        return
      }
      let safariObject: SafariApplication = SBApplication.init(bundleIdentifier: bundleIdentifier)!

      guard let windows = safariObject.windows,
            let frontWindow = windows().first else {
        log("Failed to get safari front window")
        return
      }
      guard let activeTab = frontWindow.currentTab else {
        log("Failed to get safari active tab")
        return
      }

      // Safari doesn't allow incognito mode to be inspected, so we do not know if we should hide the url
      data.url = activeTab.URL

      // comment above applies here as well
      if let tabTitle = activeTab.name {
        if tabTitle != "" && data.title != tabTitle {
            debug("Browser tab title differs from window title")
          data.title = tabTitle
        }
      }
    }

    if let consent = captureConsent {
      guard let minimized = consent.filter(data, at: nowTime) else { resetCaptureChain(); return }
      data = minimized
    }
    if researchEnabled {
      data = applyResearchFilter(data)
    } else if excludeTitle || titleShouldBeExcluded(data.title ?? "") {
      data.title = "excluded"
    }

    if let consent = captureConsent {
      guard let minimized = consent.filter(data, at: nowTime) else { resetCaptureChain(); return }
      data = minimized
    }
    let heartbeat = Heartbeat(timestamp: nowTime, data: data)
    sendHeartbeat(heartbeat)
  }

  @objc func focusedWindowChanged(_ observer: AXObserver, window: AXUIElement) {
    debug("Focused window changed")

    if oldWindow != nil {
      AXObserverRemoveNotification(observer, oldWindow!, kAXFocusedWindowChangedNotification as CFString)
    }

    let selfPtr = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
    AXObserverAddNotification(observer, window, kAXTitleChangedNotification as CFString, selfPtr)

    windowTitleChanged(
      observer, axElement: window, notification: kAXTitleChangedNotification as CFString)

    oldWindow = window
  }

  @objc func focusedAppChanged() {
    debug("Focused app changed")

    if observer != nil {
      CFRunLoopRemoveSource(
        RunLoop.current.getCFRunLoop(),
        AXObserverGetRunLoopSource(observer!),
        CFRunLoopMode.defaultMode
      )
    }

    guard let frontmost = NSWorkspace.shared.frontmostApplication else {
      log("Failed to get frontmost application from app change notification")
      return
    }

    let pid = frontmost.processIdentifier
    let focusedApp = AXUIElementCreateApplication(pid)

    AXObserverCreate(
      pid,
      {
        (
          _ axObserver: AXObserver,
          axElement: AXUIElement,
          notification: CFString,
          userData: UnsafeMutableRawPointer?
        ) -> Void in
        guard let userData = userData else {
          log("Missing userData")
          return
        }
        let application = Unmanaged<MainThing>.fromOpaque(userData).takeUnretainedValue()
        if notification == kAXFocusedWindowChangedNotification as CFString {
          application.focusedWindowChanged(axObserver, window: axElement)
        } else {
          application.windowTitleChanged(
            axObserver,
            axElement: axElement,
            notification: notification
          )
        }
      }, &observer)

    let selfPtr = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
    AXObserverAddNotification(observer!, focusedApp, kAXFocusedWindowChangedNotification as CFString, selfPtr)

    CFRunLoopAddSource(
      RunLoop.current.getCFRunLoop(),
      AXObserverGetRunLoopSource(observer!),
      CFRunLoopMode.defaultMode
    )

    var focusedWindow: AnyObject?
    AXUIElementCopyAttributeValue(focusedApp, kAXFocusedWindowAttribute as CFString, &focusedWindow)

    if focusedWindow != nil {
      focusedWindowChanged(observer!, window: focusedWindow as! AXUIElement)
    }
  }
}

// TODO I believe this is handled by the python wrapper so it isn't needed here
func checkAccess() -> Bool {
  let checkOptPrompt = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as NSString
  let options = [checkOptPrompt: true]
  let accessEnabled = AXIsProcessTrustedWithOptions(options as CFDictionary?)
  return accessEnabled
}
