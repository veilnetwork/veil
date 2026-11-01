package com.veil.veil_flutter

import android.app.Activity
import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.text.TextUtils
import android.widget.ImageView
import android.widget.ScrollView
import android.widget.FrameLayout
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.graphics.drawable.RoundedBitmapDrawableFactory
import java.lang.ref.WeakReference

/** A call-only surface above the keyguard, never the host's unlocked UI.
 * Caller display data lives only in this process, never in a PendingIntent.
 * Opening the host UI still requires dismissing the keyguard.
 * Answer/decline still use the host's existing one-use, session-bound checks.
 */
class CallScreenActivity : Activity() {
    interface Host {
        fun dispatchCallScreenAction(intent: Intent): Boolean
    }

    private data class Presentation(
        val session: String,
        val ringing: Boolean,
        val answer: Intent?,
        val end: Intent,
        val label: String?,
        val avatar: Bitmap?,
        val statusTitle: String?,
    )

    private data class Caller(val label: String?, val avatar: Bitmap?)

    companion object {
        private const val EXTRA_SESSION = "veil_call_screen_session"
        private var current: Presentation? = null
        private var expectedSession: String? = null
        private var caller: Caller? = null
        private var visible = WeakReference<CallScreenActivity>(null)
        private var host = WeakReference<Host>(null)

        fun attachHost(owner: Host) { host = WeakReference(owner) }
        fun hasHost(): Boolean = host.get() != null
        fun detachHost(owner: Host) {
            if (host.get() === owner) { host.clear(); clear() }
        }

        fun fullScreenAllowed(context: Context): Boolean =
            Build.VERSION.SDK_INT < 34 ||
                context.getSystemService(NotificationManager::class.java).canUseFullScreenIntent()

        /** Prepare before asynchronous Service delivery so a fast contact read
         * can arrive first. At most one session's presentation is retained. */
        fun prepare(session: String?) {
            if (expectedSession == session) return
            expectedSession = session
            caller = null
            current = null
            visible.get()?.finish()
        }

        /** No filenames/URLs, notification extras or persistent cache. */
        fun updateCaller(session: String?, name: String?, bytes: ByteArray?): Boolean {
            if (session.isNullOrEmpty() || session != expectedSession) return false
            val label = name?.filterNot { it.isISOControl() }?.trim()?.take(160)?.takeIf { it.isNotEmpty() }
            var image: Bitmap? = null
            if (bytes != null && bytes.isNotEmpty() && bytes.size <= 8192) {
                try {
                    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                    if (bounds.outWidth in 1..128 && bounds.outHeight in 1..128) {
                        image = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    }
                } catch (_: RuntimeException) { /* malformed image: use initials */ }
            }
            caller = Caller(label, image)
            current = current?.takeIf { it.session == session }?.copy(label = label, avatar = image)
            visible.get()?.render()
            return true
        }

        /** Called only by the same-process service, after constructing tokens. */
        fun update(session: String?, ringing: Boolean, answer: Intent?, end: Intent?, fallbackName: String? = null, statusTitle: String? = null) {
            if (session == null || end == null) { clear(); return }
            prepare(session)
            current = Presentation(session, ringing, answer, end,
                caller?.label ?: fallbackName?.take(160), caller?.avatar, statusTitle?.take(160))
            visible.get()?.render()
        }

        fun clear() {
            expectedSession = null
            caller = null
            current = null
            visible.get()?.finish()
        }

        fun intent(context: Context, session: String): Intent =
            Intent(context, CallScreenActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                addCategory("com.veil.veil_flutter.CALL_SCREEN.$session")
                putExtra(EXTRA_SESSION, session)
            }
    }

    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() {
            if (presentation() == null) finish()
            else handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 27) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)
        }
        visible = WeakReference(this)
        render()
        handler.post(poll)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        render()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        if (visible.get() === this) visible.clear()
        super.onDestroy()
    }

    private fun presentation(): Presentation? = current?.takeIf {
        it.session == intent.getStringExtra(EXTRA_SESSION)
    }

    private fun dispatch(action: Intent) {
        // Do not start the exported launcher over the keyguard. The retained
        // engine's host authenticates this action without exposing chat UI.
        if (host.get()?.dispatchCallScreenAction(Intent(action)) != true) {
            openApp()
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun render() {
        val call = presentation() ?: run { finish(); return }
        val accent = 0xff83d9c9.toInt()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(24), dp(32), dp(24), dp(32))
            setBackgroundColor(0xff101b19.toInt())
        }
        column.addView(TextView(this).apply {
            text = call.statusTitle ?: getString(if (call.ringing) R.string.veil_call_screen_incoming else R.string.veil_call_screen_ongoing)
            textSize = 18f
            setTextColor(accent)
            gravity = Gravity.CENTER
        }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(28) })
        val label = call.label ?: getString(R.string.veil_call_screen_unknown)
        val circle = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(0xff29433e.toInt()) }
        val avatar: View = if (call.avatar != null) ImageView(this).apply {
            setImageDrawable(RoundedBitmapDrawableFactory.create(resources, call.avatar).apply {
                isCircular = true
            })
            scaleType = ImageView.ScaleType.CENTER_CROP
            background = circle
            clipToOutline = true
            contentDescription = getString(R.string.veil_call_screen_avatar)
        } else TextView(this).apply {
            text = label.take(1).uppercase()
            textSize = 48f
            setTextColor(accent)
            gravity = Gravity.CENTER
            background = circle
        }
        column.addView(avatar, LinearLayout.LayoutParams(dp(112), dp(112)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            bottomMargin = dp(20)
        })
        column.addView(TextView(this).apply {
            text = label
            textSize = 28f
            setTextColor(Color.WHITE)
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
        }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(40) })
        val controls = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun button(labelId: Int, color: Int, textColor: Int, outline: Boolean = false, action: () -> Unit): Button =
            Button(this).apply {
                setText(labelId)
                textSize = 16f
                isAllCaps = false
                setTextColor(textColor)
                minimumHeight = dp(56)
                minWidth = 0
                backgroundTintList = null
                val shape = GradientDrawable().apply {
                    cornerRadius = dp(28).toFloat()
                    setColor(color)
                    if (outline) setStroke(dp(1), accent)
                }
                background = RippleDrawable(ColorStateList.valueOf(0x33ffffff), shape, null)
                setPadding(dp(10), dp(12), dp(10), dp(12))
                setOnClickListener {
                    if (presentation()?.session != call.session) { finish(); return@setOnClickListener }
                    isEnabled = false
                    action()
                }
            }
        if (call.ringing && call.answer != null) {
            controls.addView(button(R.string.veil_call_screen_answer, accent, 0xff102820.toInt()) { dispatch(call.answer) },
                LinearLayout.LayoutParams(0, -2, 1f).apply { marginEnd = dp(8) })
        }
        controls.addView(button(
            if (call.ringing) R.string.veil_call_screen_decline else R.string.veil_call_screen_end,
            0xffc54d5b.toInt(), Color.WHITE,
        ) { dispatch(call.end) }, LinearLayout.LayoutParams(0, -2, 1f))
        column.addView(controls, LinearLayout.LayoutParams(-1, -2))
        column.addView(button(R.string.veil_call_screen_open, Color.TRANSPARENT, accent, true) { openApp() },
            LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(20) })
        setContentView(ScrollView(this).apply {
            isFillViewport = true
            addView(column, FrameLayout.LayoutParams(-1, -2))
        })
    }

    private fun openApp() {
        fun launch() {
            val open = packageManager.getLaunchIntentForPackage(packageName) ?: return
            startActivity(open)
            finish()
        }
        val keyguard = getSystemService(KeyguardManager::class.java)
        if (Build.VERSION.SDK_INT >= 26 && keyguard.isKeyguardLocked) {
            keyguard.requestDismissKeyguard(this, object : KeyguardManager.KeyguardDismissCallback() {
                override fun onDismissSucceeded() { if (!isFinishing) launch() }
                override fun onDismissCancelled() { if (!isFinishing) render() }
                override fun onDismissError() { if (!isFinishing) render() }
            })
        } else launch()
    }
}
