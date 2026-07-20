import Cocoa
import FlutterMacOS
import NetworkExtension

/// macOS host-side controller for xVeil's system packet-tunnel extension.
///
/// Rust FFI continues to be loaded by Dart in the host process. The separate
/// PacketTunnel extension links the same FFI as a static library and owns the
/// operating-system packet flow.
public class VeilFlutterPlugin: NSObject, FlutterPlugin {
  private static let vpnChannel = "network.veil.xveil/vpn"
  // The full-tunnel route also captures the host app's overlay sockets. Keep
  // start fail-closed until veil/SOCKS is owned by PacketTunnel rather than by
  // the containing Flutter process.
  private static let hasExtensionOwnedUpstream = false

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: vpnChannel,
      binaryMessenger: registrar.messenger)
    registrar.addMethodCallDelegate(VeilFlutterPlugin(), channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "probe", "status", "confirmRunning":
      vpnStatus(result)
    case "start":
      vpnStart(call.arguments, result: result)
    case "stop", "abort":
      vpnStop(result)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private static var packetTunnelBundleIdentifier: String? {
    Bundle.main.bundleIdentifier.map { "\($0).PacketTunnel" }
  }

  private static func state(_ phase: String, detail: String? = nil) -> [String: Any] {
    var value: [String: Any] = ["phase": phase]
    if let detail { value["detail"] = detail }
    return value
  }

  private static func phase(_ status: NEVPNStatus) -> String {
    switch status {
    case .connected:
      return "running"
    case .connecting, .reasserting:
      return "starting"
    case .disconnecting:
      return "stopping"
    case .invalid, .disconnected:
      return "stopped"
    @unknown default:
      return "error"
    }
  }

  private func finish(_ result: @escaping FlutterResult, _ value: Any?) {
    if Thread.isMainThread {
      result(value)
    } else {
      DispatchQueue.main.async { result(value) }
    }
  }

  private func loadManager(
    completion: @escaping (NETunnelProviderManager?, Error?) -> Void
  ) {
    guard let providerBundleIdentifier = Self.packetTunnelBundleIdentifier else {
      completion(nil, NSError(
        domain: "VeilVPN",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "host bundle identifier is unavailable"]))
      return
    }
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      let manager = managers?.first { candidate in
        (candidate.protocolConfiguration as? NETunnelProviderProtocol)?
          .providerBundleIdentifier == providerBundleIdentifier
      }
      completion(manager, error)
    }
  }

  private func vpnStatus(_ result: @escaping FlutterResult) {
    loadManager { manager, error in
      if let error {
        self.finish(result, Self.state("error", detail: error.localizedDescription))
        return
      }
      guard let manager else {
        self.finish(result, Self.state(
          Self.hasExtensionOwnedUpstream ? "stopped" : "unsupported",
          detail: Self.hasExtensionOwnedUpstream
            ? nil : "Apple VPN awaits an extension-owned veil upstream"))
        return
      }
      let current = Self.phase(manager.connection.status)
      if !Self.hasExtensionOwnedUpstream && current == "stopped" {
        self.finish(result, Self.state(
          "unsupported",
          detail: "Apple VPN awaits an extension-owned veil upstream"))
        return
      }
      self.finish(result, Self.state(current))
    }
  }

  private func vpnStart(_ arguments: Any?, result: @escaping FlutterResult) {
    guard Self.hasExtensionOwnedUpstream else {
      finish(result, Self.state(
        "unsupported",
        detail: "Apple VPN awaits an extension-owned veil upstream"))
      return
    }
    guard let arguments = arguments as? [String: Any],
          let policy = arguments["policy"] as? [String: Any],
          let socks5Listen = arguments["socks5Listen"] as? String,
          !socks5Listen.isEmpty,
          let providerBundleIdentifier = Self.packetTunnelBundleIdentifier
    else {
      finish(result, Self.state("error", detail: "invalid VPN arguments"))
      return
    }

    loadManager { existing, loadError in
      if let loadError {
        self.finish(result, Self.state("error", detail: loadError.localizedDescription))
        return
      }
      let manager = existing ?? NETunnelProviderManager()
      let tunnelProtocol = NETunnelProviderProtocol()
      tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
      tunnelProtocol.serverAddress = "xVeil local SOCKS5"
      var providerConfiguration = policy
      providerConfiguration["socks5Listen"] = socks5Listen
      tunnelProtocol.providerConfiguration = providerConfiguration
      manager.protocolConfiguration = tunnelProtocol
      manager.localizedDescription = "xVeil"
      manager.isEnabled = true
      manager.saveToPreferences { saveError in
        if let saveError {
          self.finish(result, Self.state("error", detail: saveError.localizedDescription))
          return
        }
        manager.loadFromPreferences { reloadError in
          if let reloadError {
            self.finish(result, Self.state("error", detail: reloadError.localizedDescription))
            return
          }
          do {
            try manager.connection.startVPNTunnel()
          } catch {
            self.finish(result, Self.state("error", detail: error.localizedDescription))
            return
          }
          self.wait(
            manager.connection,
            targetRunning: true,
            deadline: .now() + .seconds(12),
            result: result)
        }
      }
    }
  }

  private func vpnStop(_ result: @escaping FlutterResult) {
    loadManager { manager, error in
      if let error {
        self.finish(result, Self.state("error", detail: error.localizedDescription))
        return
      }
      guard let manager else {
        self.finish(result, Self.state("stopped"))
        return
      }
      manager.connection.stopVPNTunnel()
      self.wait(
        manager.connection,
        targetRunning: false,
        deadline: .now() + .seconds(5),
        result: result)
    }
  }

  private func wait(
    _ connection: NEVPNConnection,
    targetRunning: Bool,
    deadline: DispatchTime,
    result: @escaping FlutterResult
  ) {
    let current = Self.phase(connection.status)
    if targetRunning && current == "running" {
      finish(result, Self.state("running"))
      return
    }
    if !targetRunning && current == "stopped" {
      finish(result, Self.state("stopped"))
      return
    }
    if .now() >= deadline {
      finish(result, Self.state(
        "error",
        detail: "VPN did not \(targetRunning ? "start" : "stop") before timeout (\(current))"))
      return
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(100)) {
      self.wait(
        connection,
        targetRunning: targetRunning,
        deadline: deadline,
        result: result)
    }
  }
}
