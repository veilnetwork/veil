package com.veil.veil_flutter

private fun refused(work: () -> Unit) {
    var failed = false
    try { work() } catch (_: IllegalStateException) { failed = true }
    check(failed) { "unverified operation was accepted" }
}

fun main() {
    var issued = 0
    val gate = DaemonRetirementGate { "synthetic-${++issued}" }
    val original = gate.startTicket()!!
    check(gate.acceptStart(original, sticky = false))
    check(gate.acceptStart(null, sticky = true))
    val stopped = gate.begin()
    val sealedStop = gate.commandGeneration()
    check(!gate.allowsStart() && gate.startTicket() == null)
    check(!gate.acceptStart(original, sticky = false))
    check(!gate.acceptStart(null, sticky = true))
    refused { gate.resume(stopped, false, false) }
    for ((foreground, wake) in listOf(true to false, false to true, true to true)) {
        refused { gate.confirm(stopped, foreground, wake) }
        refused { gate.resume(stopped, false, false) }
    }
    refused { gate.confirm("wrong", false, false) }
    gate.confirm(stopped, false, false)
    refused { gate.resume(stopped, true, false) }
    refused { gate.resume(stopped, false, true) }
    gate.resume(stopped, false, false)
    gate.resume(stopped, true, true) // Lost release reply: no effect on live work.
    check(gate.allowsStart())
    check(!gate.acceptStart(original, sticky = false))
    check(!gate.matchesGeneration(original)) // Delayed old STOP cannot win.
    check(!gate.matchesGeneration(sealedStop)) // Nor a STOP queued while sealed.
    check(!gate.acceptStart(null, sticky = true))
    val fresh = gate.startTicket()!!
    check(fresh != original && gate.matchesGeneration(fresh))
    check(gate.acceptStart(fresh, sticky = false))
    check(gate.acceptStart(null, sticky = true))
    val next = gate.begin()
    check(next != stopped)
    gate.confirm(next, false, false)
    refused { gate.resume(stopped, false, false) }
    check(!gate.allowsStart())
    check(gate.begin() == next && issued == 2) // Lost acquire reply/retry.
    refused { gate.resume(next, false, false) } // Retry needs fresh confirmation.
    gate.confirm(next, false, false)
    gate.resume(next, false, false)
    check(!gate.acceptStart(fresh, sticky = false))
    println("DaemonRetirementGate: admission, resources, retries and stale generations passed")
}
