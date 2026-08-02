package com.veil.veil_flutter

import java.security.SecureRandom

/**
 * One-time capabilities for the call actions carried on notification
 * PendingIntents.
 *
 * ## Why this exists
 *
 * The launcher activity is necessarily `exported="true"`, and the accept /
 * hangup actions were expressed as a plain `xveil_call_action` string extra.
 * Any installed app could therefore start the activity explicitly with that
 * extra and have the call answered — turning on the microphone and camera with
 * permissions the user granted for a call they never took — or hang up a call
 * in progress. There was no token, no call id, and no way to tell a tap on our
 * own notification from an intent someone else composed.
 *
 * A capability closes it without needing the activity to become
 * non-exported: the value in the extra is a secret this process minted a
 * moment ago and will accept exactly once. Another app cannot guess it, and
 * cannot read it out of the PendingIntent either — `FLAG_IMMUTABLE` keeps it
 * from being rewritten, and the extras of a PendingIntent it does not own are
 * not readable.
 *
 * ## One-shot
 *
 * A token is consumed on first use. A second delivery of the same intent — a
 * replay, or a stale PendingIntent the system re-delivers — finds nothing.
 * Each `buildNotification` mints fresh tokens, and the notification is rebuilt
 * on every call-state change, so the live buttons always carry a valid one.
 */
object CallActionCapability {
    private val rng = SecureRandom()
    private val lock = Any()

    /** action → the single token currently honoured for it. */
    private val live = HashMap<String, String>()

    /**
     * Mint (and store) the capability for [action], replacing any previous one.
     *
     * Replacing rather than accumulating is deliberate: only the buttons on the
     * notification the user can actually see should work, and rebuilding the
     * notification is what makes older ones unreachable.
     */
    fun mint(action: String): String {
        val bytes = ByteArray(32)
        rng.nextBytes(bytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        synchronized(lock) { live[action] = token }
        return token
    }

    /**
     * Whether [token] is the capability currently held for [action]; consumes it.
     *
     * Compared in constant time. The comparison is not a secret-recovery oracle
     * in any practical sense — an attacker gets one guess per activity launch —
     * but a length-and-prefix compare is the kind of thing that becomes one
     * after someone adds a retry path, and the cost here is nil.
     */
    fun consume(action: String?, token: String?): Boolean {
        if (action == null || token == null) return false
        // ONE critical section: compare AND remove (audit V-12). Split across
        // two `synchronized` blocks, two concurrent callers both read the same
        // `expected`, both matched, and both returned true — the second one's
        // removal was a no-op it had already been paid for. "One-shot" then
        // rested on the main looper serialising callers rather than on this
        // code, which is the kind of guarantee that evaporates the first time
        // an action is dispatched from anywhere else.
        synchronized(lock) {
            val expected = live[action] ?: return false
            if (!constantTimeEquals(expected, token)) return false
            live.remove(action)
            return true
        }
    }

    /** Drop every outstanding capability — the call is over, nothing may act. */
    fun revokeAll() {
        synchronized(lock) { live.clear() }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }

    /** Extra key for the capability that authorises [EXTRA_CALL_ACTION]. */
    const val EXTRA_CALL_TOKEN: String = "xveil_call_token"

    /** Extra key naming the requested action (`accept` / `hangup`). */
    const val EXTRA_CALL_ACTION: String = "xveil_call_action"
}
