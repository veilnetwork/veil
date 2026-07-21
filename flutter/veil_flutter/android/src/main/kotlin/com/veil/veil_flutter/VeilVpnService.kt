package com.veil.veil_flutter

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.net.InetAddress

/** Owns Android's TUN descriptor; packet forwarding itself stays in Rust. */
class VeilVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.veil.veil_flutter.VPN_START"
        const val ACTION_STOP = "com.veil.veil_flutter.VPN_STOP"
        const val EXTRA_ROUTE_MODE = "routeMode"
        const val EXTRA_INCLUDED = "includedCidrs"
        const val EXTRA_EXCLUDED = "excludedCidrs"
        const val EXTRA_ROUTE_DNS = "routeDns"
        const val EXTRA_DNS = "dnsServers"
        const val EXTRA_ALLOW_LAN = "allowLan"
        const val EXTRA_MTU = "mtu"

        const val PHASE_STOPPED = "stopped"
        const val PHASE_STARTING = "starting"
        const val PHASE_RUNNING = "running"
        const val PHASE_ERROR = "error"
        private const val MAX_PLATFORM_ROUTES = 12_000

        @Volatile var phase: String = PHASE_STOPPED
            private set
        @Volatile var detail: String? = null
            private set
        @Volatile var tunFd: Int? = null
            private set

        fun confirmRunning() {
            if (tunFd != null) phase = PHASE_RUNNING
        }

        fun fail(message: String) {
            detail = message
            phase = PHASE_ERROR
        }
    }

    private var descriptor: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopTunnel()
            ACTION_START -> startTunnel(intent)
        }
        return Service.START_NOT_STICKY
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        closeDescriptor()
        super.onDestroy()
    }

    private fun startTunnel(intent: Intent) {
        phase = PHASE_STARTING
        detail = null
        closeDescriptor()
        startVpnForeground()
        var stage = "read VPN policy"
        try {
            val routeMode = intent.getStringExtra(EXTRA_ROUTE_MODE) ?: "allTraffic"
            val included = intent.getStringArrayListExtra(EXTRA_INCLUDED) ?: arrayListOf()
            val excluded = intent.getStringArrayListExtra(EXTRA_EXCLUDED) ?: arrayListOf()
            val routeDns = intent.getBooleanExtra(EXTRA_ROUTE_DNS, true)
            val dnsServers = intent.getStringArrayListExtra(EXTRA_DNS) ?: arrayListOf("1.1.1.1")
            val allowLan = intent.getBooleanExtra(EXTRA_ALLOW_LAN, true)
            val mtu = intent.getIntExtra(EXTRA_MTU, 1280)

            if (mtu !in 1280..9000) error("MTU must be between 1280 and 9000")
            stage = "configure tunnel addresses"
            val builder = Builder()
                .setSession("xVeil")
                .setMtu(mtu)
                .addAddress("198.18.0.1", 30)
                .addAddress("fd00:7665:696c::1", 126)

            // The embedded node and the tunnel's own local SOCKS connection
            // must use the physical network, otherwise they recursively enter
            // the TUN. Other apps remain eligible for the VPN.
            builder.addDisallowedApplication(packageName)

            stage = "configure VPN routes"
            if (routeMode == "includeOnly") {
                if (included.isEmpty()) error("At least one included subnet is required")
                if (included.size > MAX_PLATFORM_ROUTES) error("Too many included VPN routes")
                included.forEach { addRoute(builder, it) }
            } else {
                val effectiveExcluded = ArrayList(excluded)
                if (allowLan) {
                    effectiveExcluded.addAll(listOf(
                        // Loopback is always resolved locally by Android and
                        // HyperOS rejects excludeRoute(127.0.0.0/8) with
                        // EFAULT/"Bad address". Do not feed that redundant
                        // prefix to VpnService.Builder.
                        "10.0.0.0/8", "169.254.0.0/16",
                        "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10",
                    ))
                }
                if (effectiveExcluded.size > MAX_PLATFORM_ROUTES) {
                    error("Too many excluded VPN routes")
                }
                if (Build.VERSION.SDK_INT >= 33) {
                    addRoute(builder, "0.0.0.0/0")
                    addRoute(builder, "::/0")
                    effectiveExcluded.distinct().forEach { excludeRoute(builder, it) }
                } else {
                    // Android 12 and older have no Builder.excludeRoute. Build
                    // the exact complement as positive routes so exclusions
                    // remain functional instead of being silently ignored.
                    addComplementRoutes(builder, effectiveExcluded)
                }
            }

            stage = "configure VPN DNS"
            if (routeDns) {
                if (dnsServers.isEmpty()) error("At least one DNS server is required")
                dnsServers.forEach { server ->
                    builder.addDnsServer(server)
                    if (routeMode == "includeOnly") {
                        addRoute(builder, if (server.contains(':')) "$server/128" else "$server/32")
                    }
                }
            }

            stage = "establish VPN interface"
            descriptor = builder.establish() ?: error("Android declined VPN interface creation")
            tunFd = descriptor!!.fd
            // Rust must confirm packet forwarding before the plugin promotes
            // this to PHASE_RUNNING.
            phase = PHASE_STARTING
        } catch (error: Exception) {
            closeDescriptor()
            fail("$stage: ${error.message ?: error.javaClass.simpleName}")
        }
    }

    private fun addRoute(builder: Builder, cidr: String) {
        try {
            val prefix = parsePrefix(cidr)
            builder.addRoute(prefix.address, prefix.prefixLength)
        } catch (error: Exception) {
            throw IllegalArgumentException("could not add route $cidr: ${error.message}", error)
        }
    }

    private fun excludeRoute(builder: Builder, cidr: String) {
        try {
            builder.excludeRoute(parsePrefix(cidr))
        } catch (error: Exception) {
            throw IllegalArgumentException("could not exclude route $cidr: ${error.message}", error)
        }
    }

    private fun parsePrefix(cidr: String): IpPrefix {
        val separator = cidr.lastIndexOf('/')
        if (separator <= 0 || separator == cidr.lastIndex) {
            error("Invalid CIDR: $cidr")
        }
        val address = InetAddress.getByName(cidr.substring(0, separator))
        val prefixLength = cidr.substring(separator + 1).toIntOrNull()
            ?: error("Invalid CIDR prefix: $cidr")
        val maximum = if (address.address.size == 4) 32 else 128
        if (prefixLength !in 0..maximum) error("Invalid CIDR prefix: $cidr")

        // IpPrefix requires a canonical network address and throws the opaque
        // "Bad address" error when a syntactically valid CIDR retains host
        // bits. GeoIP feeds and user-entered routes do not always arrive
        // canonicalised (for example 10.1.2.3/8), so mask them here instead of
        // aborting the whole VPN interface build.
        val network = address.address.clone()
        val wholeBytes = prefixLength / 8
        val remainingBits = prefixLength % 8
        if (remainingBits != 0) {
            val mask = (0xff shl (8 - remainingBits)) and 0xff
            network[wholeBytes] = (network[wholeBytes].toInt() and mask).toByte()
        }
        val hostStart = wholeBytes + if (remainingBits == 0) 0 else 1
        for (index in hostStart until network.size) network[index] = 0
        return IpPrefix(InetAddress.getByAddress(network), prefixLength)
    }

    private fun addComplementRoutes(builder: Builder, excluded: List<String>) {
        val ipv4 = PrefixTrieNode()
        val ipv6 = PrefixTrieNode()
        excluded.distinct().map(::parsePrefix).forEach { prefix ->
            val address = prefix.address.address
            insertPrefix(
                if (address.size == 4) ipv4 else ipv6,
                address,
                prefix.prefixLength,
            )
        }
        val routes = ArrayList<IpPrefix>()
        emitIncludedPrefixes(ipv4, ByteArray(4), 0, routes)
        emitIncludedPrefixes(ipv6, ByteArray(16), 0, routes)
        if (routes.size > MAX_PLATFORM_ROUTES) {
            error("VPN exclusions expand to too many Android routes")
        }
        routes.forEach { builder.addRoute(it.address, it.prefixLength) }
    }

    private fun insertPrefix(root: PrefixTrieNode, address: ByteArray, prefixLength: Int) {
        var node = root
        for (depth in 0 until prefixLength) {
            if (node.excluded) return
            val bit = address.bitAt(depth)
            var child = node.children[bit]
            if (child == null) {
                child = PrefixTrieNode()
                node.children[bit] = child
            }
            node = child
        }
        node.excluded = true
        node.children[0] = null
        node.children[1] = null
    }

    private fun emitIncludedPrefixes(
        node: PrefixTrieNode?,
        network: ByteArray,
        depth: Int,
        output: MutableList<IpPrefix>,
    ) {
        if (node?.excluded == true) return
        if (node == null) {
            output.add(IpPrefix(InetAddress.getByAddress(network), depth))
            return
        }
        if (depth == network.size * 8) return
        for (bit in 0..1) {
            val childNetwork = network.clone()
            childNetwork.setBit(depth, bit)
            emitIncludedPrefixes(node.children[bit], childNetwork, depth + 1, output)
        }
    }

    private fun ByteArray.bitAt(index: Int): Int =
        (this[index / 8].toInt() ushr (7 - index % 8)) and 1

    private fun ByteArray.setBit(index: Int, value: Int) {
        val byteIndex = index / 8
        val mask = 1 shl (7 - index % 8)
        this[byteIndex] = if (value == 0) {
            (this[byteIndex].toInt() and mask.inv()).toByte()
        } else {
            (this[byteIndex].toInt() or mask).toByte()
        }
    }

    private fun stopTunnel() {
        closeDescriptor()
        phase = PHASE_STOPPED
        detail = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeDescriptor() {
        try { descriptor?.close() } catch (_: Exception) {}
        descriptor = null
        tunFd = null
    }

    private fun startVpnForeground() {
        val channelId = "veil_vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(
                channelId,
                "xVeil VPN",
                NotificationManager.IMPORTANCE_LOW,
            ))
        }
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launch?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }
        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(com.veil.veil_flutter.R.drawable.veil_notification_icon)
            .setContentTitle("xVeil VPN")
            .setContentText("Traffic is routed through veil")
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(pending)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(42042, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(42042, notification)
        }
    }
}

private class PrefixTrieNode {
    var excluded: Boolean = false
    val children: Array<PrefixTrieNode?> = arrayOfNulls(2)
}
