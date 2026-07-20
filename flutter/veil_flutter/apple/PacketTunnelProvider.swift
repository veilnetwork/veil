import Foundation
import Network
import NetworkExtension

private let veilTunnelStopped: Int32 = 0
private let veilTunnelRunning: Int32 = 2
private let veilTunnelError: Int32 = 3
private let veilOK: Int32 = 0
private let veilQueueFull: Int32 = -1
private let maxPendingPackets = 128
private let maxPlatformRoutes = 12_000

private enum VeilPacketTunnelError: LocalizedError {
    case invalidConfiguration(String)
    case engineStart(Int32, String)
    case engineStopped(String)
    case ingress(Int32)

    var errorDescription: String? {
        switch self {
        case let .invalidConfiguration(detail):
            return "Invalid VPN configuration: \(detail)"
        case let .engineStart(code, detail):
            return "Packet engine failed to start (\(code)): \(detail)"
        case let .engineStopped(detail):
            return "Packet engine stopped during startup: \(detail)"
        case let .ingress(code):
            return "Packet engine rejected ingress packet (\(code))"
        }
    }
}

private enum ParsedRoute {
    case ipv4(address: String, mask: String)
    case ipv6(address: String, prefix: NSNumber)

    init?(_ cidr: String) {
        let pieces = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 2, let prefix = Int(pieces[1]) else { return nil }
        let address = String(pieces[0])

        if let ipv4 = IPv4Address(address), (0...32).contains(prefix) {
            var network = [UInt8](ipv4.rawValue)
            var mask = [UInt8](repeating: 0, count: 4)
            for index in mask.indices {
                let bits = min(max(prefix - index * 8, 0), 8)
                mask[index] = bits == 0 ? 0 : UInt8.max << (8 - bits)
                network[index] &= mask[index]
            }
            guard let networkAddress = IPv4Address(Data(network)),
                  let maskAddress = IPv4Address(Data(mask))
            else { return nil }
            self = .ipv4(
                address: String(describing: networkAddress),
                mask: String(describing: maskAddress)
            )
            return
        }

        if let ipv6 = IPv6Address(address), (0...128).contains(prefix) {
            var network = [UInt8](ipv6.rawValue)
            for index in network.indices {
                let bits = min(max(prefix - index * 8, 0), 8)
                let mask: UInt8 = bits == 0 ? 0 : UInt8.max << (8 - bits)
                network[index] &= mask
            }
            guard let networkAddress = IPv6Address(Data(network)) else { return nil }
            self = .ipv6(
                address: String(describing: networkAddress),
                prefix: NSNumber(value: prefix)
            )
            return
        }
        return nil
    }
}

private struct VeilTunnelConfiguration {
    let socks5Listen: String
    let routeMode: String
    let includedRoutes: [ParsedRoute]
    let excludedRoutes: [ParsedRoute]
    let routeDNS: Bool
    let dnsServers: [String]
    let allowLAN: Bool
    let mtu: UInt16

    init(_ raw: [String: Any]) throws {
        guard let socks5Listen = raw["socks5Listen"] as? String,
              !socks5Listen.isEmpty
        else {
            throw VeilPacketTunnelError.invalidConfiguration("missing SOCKS5 listener")
        }
        self.socks5Listen = socks5Listen

        let routeMode = raw["routeMode"] as? String ?? "allTraffic"
        guard ["allTraffic", "includeOnly", "excludeOnly"].contains(routeMode) else {
            throw VeilPacketTunnelError.invalidConfiguration("unknown route mode")
        }
        self.routeMode = routeMode

        let includedCIDRs = Self.strings(raw["includedCidrs"])
        let excludedCIDRs = Self.strings(raw["excludedCidrs"])
        guard includedCIDRs.count <= maxPlatformRoutes,
              excludedCIDRs.count <= maxPlatformRoutes
        else {
            throw VeilPacketTunnelError.invalidConfiguration("too many routes")
        }
        guard routeMode != "includeOnly" || !includedCIDRs.isEmpty else {
            throw VeilPacketTunnelError.invalidConfiguration("include-only mode needs a route")
        }
        guard includedCIDRs.allSatisfy({ ParsedRoute($0) != nil }),
              excludedCIDRs.allSatisfy({ ParsedRoute($0) != nil })
        else {
            throw VeilPacketTunnelError.invalidConfiguration("invalid CIDR")
        }
        includedRoutes = includedCIDRs.compactMap(ParsedRoute.init)
        excludedRoutes = excludedCIDRs.compactMap(ParsedRoute.init)

        routeDNS = raw["routeDns"] as? Bool ?? true
        let dnsServers = Self.strings(raw["dnsServers"])
        guard !routeDNS || !dnsServers.isEmpty else {
            throw VeilPacketTunnelError.invalidConfiguration("DNS routing needs a server")
        }
        guard dnsServers.allSatisfy({ IPv4Address($0) != nil || IPv6Address($0) != nil }) else {
            throw VeilPacketTunnelError.invalidConfiguration("invalid DNS server")
        }
        self.dnsServers = dnsServers
        allowLAN = raw["allowLan"] as? Bool ?? true

        let mtuValue = (raw["mtu"] as? NSNumber)?.intValue ?? 1280
        guard (1280...9000).contains(mtuValue) else {
            throw VeilPacketTunnelError.invalidConfiguration("MTU must be 1280...9000")
        }
        mtu = UInt16(mtuValue)
    }

    private static func strings(_ value: Any?) -> [String] {
        guard let values = value as? [Any] else { return [] }
        var seen = Set<String>()
        return values.compactMap { value in
            guard let string = value as? String else { return nil }
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, seen.insert(trimmed).inserted else { return nil }
            return trimmed
        }
    }
}

@_cdecl("veil_apple_packet_write")
private func veilApplePacketWrite(
    context: UnsafeMutableRawPointer?,
    data: UnsafePointer<UInt8>?,
    length: UInt
) {
    guard let context, let data, length > 0 else { return }
    let provider = Unmanaged<PacketTunnelProvider>
        .fromOpaque(context)
        .takeUnretainedValue()
    provider.writePacketFromEngine(data: data, length: Int(length))
}

/// Public-API Network Extension provider for xVeil's callback packet engine.
///
/// The provider never reaches into `NEPacketTunnelFlow` with KVC/private file
/// descriptor access. Raw IP packets cross the stable C callback ABI instead.
public final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let packetQueue = DispatchQueue(
        label: "network.veil.packet-tunnel",
        qos: .userInitiated
    )
    private var acceptingPackets = false
    private var pendingIngress: [Data] = []
    private var configuredMTU = 1280

    public override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        packetQueue.async {
            do {
                guard let tunnelProtocol = self.protocolConfiguration as? NETunnelProviderProtocol,
                      let raw = tunnelProtocol.providerConfiguration
                else {
                    throw VeilPacketTunnelError.invalidConfiguration("provider configuration missing")
                }
                let configuration = try VeilTunnelConfiguration(raw)
                self.configuredMTU = Int(configuration.mtu)
                let settings = self.networkSettings(configuration)
                self.setTunnelNetworkSettings(settings) { error in
                    self.packetQueue.async {
                        if let error {
                            completionHandler(error)
                            return
                        }
                        self.startEngine(configuration, completionHandler: completionHandler)
                    }
                }
            } catch {
                completionHandler(error)
            }
        }
    }

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        packetQueue.async {
            self.acceptingPackets = false
            self.pendingIngress.removeAll(keepingCapacity: false)
            _ = veil_packet_tunnel_stop()
            completionHandler()
        }
    }

    public override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    public override func wake() {}

    fileprivate func writePacketFromEngine(data: UnsafePointer<UInt8>, length: Int) {
        let packet = Data(bytes: data, count: length)
        packetQueue.async {
            guard self.acceptingPackets else { return }
            guard packet.count <= self.configuredMTU else {
                self.failTunnel(
                    VeilPacketTunnelError.engineStopped("over-MTU output packet")
                )
                return
            }
            guard let first = packet.first else { return }
            let family: NSNumber
            switch first >> 4 {
            case 4: family = NSNumber(value: AF_INET)
            case 6: family = NSNumber(value: AF_INET6)
            default:
                self.failTunnel(
                    VeilPacketTunnelError.engineStopped("output is not an IP packet")
                )
                return
            }
            self.packetFlow.writePackets([packet], withProtocols: [family])
        }
    }

    private func startEngine(
        _ configuration: VeilTunnelConfiguration,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let proxyURL = "socks5://\(configuration.socks5Listen)"
        let dnsIP = configuration.dnsServers.first ?? "1.1.1.1"
        let context = Unmanaged.passUnretained(self).toOpaque()
        let code = proxyURL.withCString { proxy in
            dnsIP.withCString { dns in
                veil_packet_tunnel_start_packets(
                    proxy,
                    dns,
                    configuration.mtu,
                    true,
                    veilApplePacketWrite,
                    context
                )
            }
        }
        guard code == veilOK else {
            completionHandler(
                VeilPacketTunnelError.engineStart(code, Self.lastEngineError())
            )
            return
        }
        waitForEngine(deadline: .now() + .seconds(2), completionHandler: completionHandler)
    }

    private func waitForEngine(
        deadline: DispatchTime,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let phase = veil_packet_tunnel_status()
        if phase == veilTunnelRunning {
            acceptingPackets = true
            readPackets()
            monitorEngine()
            completionHandler(nil)
            return
        }
        if phase == veilTunnelError || phase == veilTunnelStopped || .now() >= deadline {
            _ = veil_packet_tunnel_stop()
            completionHandler(
                VeilPacketTunnelError.engineStopped(Self.lastEngineError())
            )
            return
        }
        packetQueue.asyncAfter(deadline: .now() + .milliseconds(20)) {
            self.waitForEngine(deadline: deadline, completionHandler: completionHandler)
        }
    }

    private func readPackets() {
        guard acceptingPackets, pendingIngress.isEmpty else { return }
        packetFlow.readPackets { packets, _ in
            self.packetQueue.async {
                guard self.acceptingPackets else { return }
                guard packets.count <= maxPendingPackets else {
                    self.failTunnel(
                        VeilPacketTunnelError.engineStopped("packet-flow batch exceeded bound")
                    )
                    return
                }
                self.pendingIngress = packets
                self.drainIngress()
            }
        }
    }

    private func drainIngress() {
        guard acceptingPackets else { return }
        while let packet = pendingIngress.first {
            if packet.isEmpty {
                pendingIngress.removeFirst()
                continue
            }
            let code = packet.withUnsafeBytes { bytes -> Int32 in
                guard let base = bytes.bindMemory(to: UInt8.self).baseAddress else {
                    return -2
                }
                return veil_packet_tunnel_send_packet(base, UInt(packet.count))
            }
            if code == veilOK {
                pendingIngress.removeFirst()
                continue
            }
            if code == veilQueueFull {
                packetQueue.asyncAfter(deadline: .now() + .milliseconds(2)) {
                    self.drainIngress()
                }
                return
            }
            let error = VeilPacketTunnelError.ingress(code)
            failTunnel(error)
            return
        }
        readPackets()
    }

    private func monitorEngine() {
        guard acceptingPackets else { return }
        let phase = veil_packet_tunnel_status()
        guard phase == veilTunnelRunning else {
            failTunnel(
                VeilPacketTunnelError.engineStopped(Self.lastEngineError())
            )
            return
        }
        packetQueue.asyncAfter(deadline: .now() + .milliseconds(250)) {
            self.monitorEngine()
        }
    }

    private func failTunnel(_ error: Error) {
        guard acceptingPackets else { return }
        acceptingPackets = false
        pendingIngress.removeAll(keepingCapacity: false)
        _ = veil_packet_tunnel_stop()
        cancelTunnelWithError(error)
    }

    private func networkSettings(
        _ configuration: VeilTunnelConfiguration
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: configuration.mtu)

        let ipv4 = NEIPv4Settings(
            addresses: ["198.18.0.1"],
            subnetMasks: ["255.255.255.252"]
        )
        let ipv6 = NEIPv6Settings(
            addresses: ["fd00:7665:696c::1"],
            networkPrefixLengths: [126]
        )

        var included4: [NEIPv4Route] = []
        var included6: [NEIPv6Route] = []
        if configuration.routeMode == "includeOnly" {
            Self.append(configuration.includedRoutes, ipv4: &included4, ipv6: &included6)
        } else {
            included4.append(.default())
            included6.append(.default())
        }

        var excluded = configuration.excludedRoutes
        excluded.append(contentsOf: ["127.0.0.0/8", "::1/128"].compactMap(ParsedRoute.init))
        if configuration.allowLAN {
            excluded.append(contentsOf: [
                "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                "192.168.0.0/16", "fc00::/7", "fe80::/10",
            ].compactMap(ParsedRoute.init))
        }
        var excluded4: [NEIPv4Route] = []
        var excluded6: [NEIPv6Route] = []
        Self.append(excluded, ipv4: &excluded4, ipv6: &excluded6)

        if configuration.routeDNS && configuration.routeMode == "includeOnly" {
            let dnsRoutes = configuration.dnsServers.compactMap { address in
                ParsedRoute("\(address)/\(address.contains(":") ? 128 : 32)")
            }
            Self.append(dnsRoutes, ipv4: &included4, ipv6: &included6)
        }
        ipv4.includedRoutes = included4
        ipv4.excludedRoutes = excluded4
        ipv6.includedRoutes = included6
        ipv6.excludedRoutes = excluded6
        settings.ipv4Settings = ipv4
        settings.ipv6Settings = ipv6

        if configuration.routeDNS {
            let dns = NEDNSSettings(servers: configuration.dnsServers)
            dns.matchDomains = [""]
            settings.dnsSettings = dns
        }
        return settings
    }

    private static func append(
        _ routes: [ParsedRoute],
        ipv4: inout [NEIPv4Route],
        ipv6: inout [NEIPv6Route]
    ) {
        for route in routes {
            switch route {
            case let .ipv4(address, mask):
                ipv4.append(NEIPv4Route(destinationAddress: address, subnetMask: mask))
            case let .ipv6(address, prefix):
                ipv6.append(
                    NEIPv6Route(destinationAddress: address, networkPrefixLength: prefix)
                )
            }
        }
    }

    private static func lastEngineError() -> String {
        guard let pointer = veil_packet_tunnel_last_error() else {
            return "no engine detail"
        }
        defer { veil_free_string(pointer) }
        return String(cString: pointer)
    }
}
