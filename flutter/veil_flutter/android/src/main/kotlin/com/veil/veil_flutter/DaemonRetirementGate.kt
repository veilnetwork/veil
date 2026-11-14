package com.veil.veil_flutter

/** Process-local admission, not a receipt that the Android Service was destroyed.
 * Resource observations come from the service, never from channel arguments.
 */
internal class DaemonRetirementGate(private val newToken: () -> String) {
    private var token: String? = null
    private var released: String? = null
    private var verified = false
    private var generation = 0L
    private var stickyGeneration: Long? = null

    @Synchronized fun allowsStart(): Boolean = token == null

    @Synchronized fun startTicket(): Long? = if (token == null) generation else null
    @Synchronized fun commandGeneration(): Long = generation
    @Synchronized fun matchesGeneration(ticket: Long?): Boolean = ticket == generation

    @Synchronized fun acceptStart(ticket: Long?, sticky: Boolean): Boolean {
        if (token != null) return false
        if (ticket != null && ticket == generation) {
            stickyGeneration = generation
            return true
        }
        return sticky && ticket == null &&
            (generation == 0L || stickyGeneration == generation)
    }

    @Synchronized fun begin(): String {
        if (token == null) {
            token = newToken().also { check(it.isNotEmpty()) }
            generation++
            stickyGeneration = null
        }
        verified = false
        return token!!
    }

    @Synchronized fun confirm(value: String, foreground: Boolean, wakeLock: Boolean) {
        requireCurrent(value)
        verified = false
        check(!foreground && !wakeLock) { "background resources remain" }
        verified = true
    }

    @Synchronized fun resume(value: String, foreground: Boolean, wakeLock: Boolean) {
        // Lost reply retry is harmless, but cannot release a newer retirement.
        if (token == null && released == value) return
        requireCurrent(value)
        check(verified && !foreground && !wakeLock) { "background retirement unverified" }
        released = value
        // STOP commands accepted while sealed belong to the retired interval,
        // not the newly admitted service lifetime.
        generation++
        token = null
        verified = false
    }

    private fun requireCurrent(value: String) {
        check(value.isNotEmpty() && token == value) { "background retirement unavailable" }
    }
}
