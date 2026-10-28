// Pure JVM regression, no Android runtime or test-only production hooks:
// kotlinc android/src/main/kotlin/com/veil/veil_flutter/CallActionCapability.kt \
//   test/android/call_action_capability_test.kt -include-runtime -d /tmp/call-actions.jar
// java -jar /tmp/call-actions.jar
import com.veil.veil_flutter.CallActionCapability
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger

fun main() {
    var scenarios = 0
    fun scenario(body: () -> Unit) {
        CallActionCapability.revokeAll()
        body()
        scenarios++
    }
    scenario {
        val token = CallActionCapability.mint("hangup", "first")
        check(token.matches(Regex("[0-9a-f]{64}")))
        check(CallActionCapability.consume("hangup", token, "first"))
        check(!CallActionCapability.consume("hangup", token, "first"))
    }
    scenario {
        val token = CallActionCapability.mint("accept", "first")
        check(!CallActionCapability.consume("accept", token, "second"))
        check(!CallActionCapability.consume("accept", token))
        check(CallActionCapability.consume("accept", token, "first"))
    }
    scenario {
        val token = CallActionCapability.mint("accept", "first")
        CallActionCapability.mint("hangup", "second")
        // An old button cannot substitute the new notification's session.
        check(!CallActionCapability.consume("accept", token, "second"))
        check(CallActionCapability.consume("accept", token, "first"))
    }
    scenario {
        val old = CallActionCapability.mint("hangup", "first")
        val next = CallActionCapability.mint("hangup", "second")
        check(!CallActionCapability.consume("hangup", old, "first"))
        check(!CallActionCapability.consume("hangup", next, "first"))
        check(CallActionCapability.consume("hangup", next, "second"))
    }
    scenario {
        val token = CallActionCapability.mint("hangup", "first")
        check(!CallActionCapability.consume("accept", token, "first"))
        check(!CallActionCapability.consume("hangup", "wrong", "first"))
        check(CallActionCapability.consume("hangup", token, "first"))
    }
    scenario {
        val accept = CallActionCapability.mint("accept", "first")
        val end = CallActionCapability.mint("hangup", "first")
        CallActionCapability.revokeAll()
        check(!CallActionCapability.consume("accept", accept, "first"))
        check(!CallActionCapability.consume("hangup", end, "first"))
    }
    scenario {
        val token = CallActionCapability.mint("hangup", "first")
        val gate = CountDownLatch(1)
        val accepted = AtomicInteger()
        val threads = List(32) {
            Thread {
                gate.await()
                if (CallActionCapability.consume("hangup", token, "first")) {
                    accepted.incrementAndGet()
                }
            }.apply { start() }
        }
        gate.countDown()
        threads.forEach { it.join() }
        check(accepted.get() == 1)
    }
    scenario {
        // Preserve the old host API for callers that have not adopted scopes.
        val token = CallActionCapability.mint("hangup")
        check(CallActionCapability.consume("hangup", token))
        check(!CallActionCapability.consume("hangup", token))
    }
    CallActionCapability.revokeAll()
    println("Call action capability: $scenarios scenarios passed")
}
