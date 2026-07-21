package com.veil.veil_flutter

import android.content.Context
import android.net.ConnectivityManager
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Authenticated loopback flow→UID selector for tun2proxy.
 *
 * The TUN packets contain no package identifier. Android's public
 * getConnectionOwnerUid API resolves the original TCP/UDP tuple, after which
 * this service returns the SOCKS listener assigned to that package. Unknown
 * apps receive DEFAULT; malformed/unauthenticated requests are closed without
 * a response so the Rust side fails the flow closed.
 */
internal class VpnFlowSelector(
    context: Context,
    applicationRoutes: Map<String, String>,
) : AutoCloseable {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val routesByAppId = applicationRoutes.map { (packageName, listen) ->
        require(isLoopbackListen(listen)) { "application oproxy is not loopback: $listen" }
        try {
            val uid = context.packageManager.getApplicationInfo(packageName, 0).uid
            appId(uid) to listen
        } catch (error: Exception) {
            throw IllegalArgumentException("application is unavailable: $packageName", error)
        }
    }.toMap()
    // Keep the advertised and bound address identical. getLoopbackAddress()
    // may prefer ::1 on some Android builds while Rust deliberately connects
    // to the IPv4 address below.
    private val server = ServerSocket(0, 32, InetAddress.getByName("127.0.0.1"))
    private val executor = Executors.newFixedThreadPool(4)
    private val tokenBytes = ByteArray(32).also(SecureRandom()::nextBytes)
    val token: String = tokenBytes.joinToString("") { "%02x".format(it) }
    val listen: String = "127.0.0.1:${server.localPort}"

    @Volatile private var closed = false

    init {
        executor.execute {
            while (!closed) {
                try {
                    val socket = server.accept()
                    executor.execute { handle(socket) }
                } catch (_: Exception) {
                    if (!closed) continue
                }
            }
        }
    }

    private fun handle(socket: Socket) {
        socket.use { client ->
            client.soTimeout = 750
            val line = BufferedReader(InputStreamReader(client.getInputStream())).readLine()
                ?: return
            if (line.length > 1024) return
            val fields = line.split('\t')
            if (fields.size != 6) return
            val supplied = try {
                fields[0].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            } catch (_: Exception) {
                return
            }
            if (!MessageDigest.isEqual(tokenBytes, supplied)) return
            val protocol = fields[1].toIntOrNull() ?: return
            if (protocol != 6 && protocol != 17) return
            val source = try {
                InetSocketAddress(InetAddress.getByName(fields[2]), fields[3].toInt())
            } catch (_: Exception) {
                return
            }
            val destination = try {
                InetSocketAddress(InetAddress.getByName(fields[4]), fields[5].toInt())
            } catch (_: Exception) {
                return
            }
            val uid = try {
                connectivity.getConnectionOwnerUid(protocol, source, destination)
            } catch (_: Exception) {
                INVALID_UID
            }
            // Ownership lookup failures are not equivalent to an unconfigured
            // app: returning no line makes the Rust selector reject the flow.
            if (uid == INVALID_UID) return
            val selected = routesByAppId[appId(uid)] ?: "DEFAULT"
            client.getOutputStream().write("$selected\n".toByteArray(Charsets.US_ASCII))
            client.getOutputStream().flush()
        }
    }

    override fun close() {
        closed = true
        try { server.close() } catch (_: Exception) {}
        executor.shutdownNow()
        try { executor.awaitTermination(500, TimeUnit.MILLISECONDS) } catch (_: Exception) {}
    }

    private fun appId(uid: Int): Int = uid % PER_USER_RANGE

    private companion object {
        const val INVALID_UID = -1
        const val PER_USER_RANGE = 100_000

        fun isLoopbackListen(value: String): Boolean {
            val separator = value.lastIndexOf(':')
            if (separator <= 0 || separator == value.lastIndex) return false
            val host = value.substring(0, separator).removePrefix("[").removeSuffix("]")
            val port = value.substring(separator + 1).toIntOrNull() ?: return false
            return port in 1..65535 && try {
                InetAddress.getByName(host).isLoopbackAddress
            } catch (_: Exception) {
                false
            }
        }
    }
}
