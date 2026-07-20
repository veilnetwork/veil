// Foreground service that keeps the Flutter process alive while the
// veil daemon needs to run in the background (Epic 489.6).
//
// Android aggressively kills backgrounded processes after ~5-15 min
// of being idle (varies by vendor — Xiaomi/Huawei more aggressive).
// A foreground service displays a persistent notification and signals
// the OS "this process is doing user-visible work — don't kill" —
// without it, the veil daemon embedded in the Flutter process
// disconnects whenever the screen turns off, and messages stop
// flowing.  With it, the daemon stays connected for hours / until
// the user explicitly stops it.
//
// The service itself does NO work in its run loop — it exists ONLY
// to keep the process alive.  The actual daemon lives in the Rust
// FFI library loaded into the Flutter process; pinning the process
// transitively pins all its threads and Rust-side state.
//
// Lifecycle (start path):
//   1. Dart calls `VeilClient.startBackgroundService()` via
//      MethodChannel.
//   2. Plugin Java/Kotlin invokes `startForegroundService(intent)`.
//   3. The OS creates the service; within 5 seconds it MUST call
//      `startForeground(notificationId, notification)` or the OS kills
//      it.  We do that immediately in `onCreate`.
//   4. Notification stays visible until `stopForeground + stopSelf`.
//
// Lifecycle (stop path):
//   1. Dart calls `VeilClient.stopBackgroundService()` (typically
//      from a logout / "go offline" UI action).
//   2. Plugin Kotlin sends ACTION_STOP intent → service unwinds.

package com.veil.veil_flutter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat

class VeilDaemonService : Service() {

    companion object {
        const val ACTION_START = "com.veil.veil_flutter.action.START"
        const val ACTION_STOP  = "com.veil.veil_flutter.action.STOP"
        const val EXTRA_NOTIFICATION_TITLE = "notification_title"
        const val EXTRA_NOTIFICATION_TEXT  = "notification_text"
        const val EXTRA_HANGUP_ACTION = "hangup_action"
        const val EXTRA_RINGING = "ringing"
        const val EXTRA_MICROPHONE = "microphone"
        const val EXTRA_CAMERA = "camera"

        private const val CHANNEL_ID = "veil_daemon"
        private const val CALL_INCOMING_CHANNEL_ID = "veil_call_incoming_v2"
        private const val CALL_ONGOING_CHANNEL_ID = "veil_call_ongoing_v2"
        private const val CHANNEL_NAME = "Veil daemon"
        private const val CALL_INCOMING_CHANNEL_NAME = "Incoming xVeil calls"
        private const val CALL_ONGOING_CHANNEL_NAME = "Ongoing xVeil calls"
        private const val NOTIFICATION_ID = 0xfee1
        private const val WAKE_LOCK_TAG = "veil:daemon"
        private const val APP_ACTION_HANGUP = "network.veil.xveil.action.HANGUP_CALL"
        private const val APP_ACTION_ACCEPT = "network.veil.xveil.action.ACCEPT_CALL"
        private const val TAG = "VeilDaemonService"
    }

    // Partial wake lock held for the service's lifetime. A foreground service
    // stops the process being KILLED, but under Doze (screen off, stationary)
    // the CPU is still suspended between maintenance windows — so the daemon's
    // socket keepalive and the onion circuit heartbeat timers stop firing and
    // the first-hop TCP dies, stalling inbound messages until the next wake.
    // A PARTIAL_WAKE_LOCK keeps the CPU (not the screen) running so those timers
    // fire on schedule and the connection stays warm. Costs battery — which is
    // exactly why the whole background service is opt-in.
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
        // Start foreground IMMEDIATELY (within 5 s of onCreate) — Android
        // 12+ is strict about this and kills the service otherwise.
        // The notification text is updated later when onStartCommand
        // receives the actual title / body via Intent extras.
        startForegroundCompat(
            buildNotification(getString(R.string.veil_default_title), null),
            microphone = false,
            camera = false,
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                releaseWakeLock()
                stopForegroundCompat()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                val title = intent?.getStringExtra(EXTRA_NOTIFICATION_TITLE)
                    ?: getString(R.string.veil_default_title)
                val text = intent?.getStringExtra(EXTRA_NOTIFICATION_TEXT)
                val hangupAction = intent?.getBooleanExtra(EXTRA_HANGUP_ACTION, false) ?: false
                val ringing = intent?.getBooleanExtra(EXTRA_RINGING, false) ?: false
                val microphone = intent?.getBooleanExtra(EXTRA_MICROPHONE, false) ?: false
                val camera = intent?.getBooleanExtra(EXTRA_CAMERA, false) ?: false
                startForegroundCompat(
                    buildNotification(title, text, hangupAction, ringing),
                    microphone = microphone,
                    camera = camera,
                )
                acquireWakeLock()
            }
        }
        // START_STICKY: if the OS kills us under memory pressure,
        // re-create the service on next available opportunity.  Persistent-
        // by-design for a P2P connection-maintaining service.
        return START_STICKY
    }

    override fun onDestroy() {
        releaseWakeLock()
        super.onDestroy()
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG).apply {
            setReferenceCounted(false)
            acquire() // released explicitly on ACTION_STOP / onDestroy
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    override fun onBind(intent: Intent?): IBinder? = null  // not bind-API'd

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channel = NotificationChannel(
                CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Keeps veil daemon connected while the app is in the background."
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
            }
            mgr.createNotificationChannel(channel)
            val incomingChannel = NotificationChannel(
                CALL_INCOMING_CHANNEL_ID,
                CALL_INCOMING_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Ringing xVeil calls."
                setShowBadge(false)
                setSound(Settings.System.DEFAULT_RINGTONE_URI, null)
                enableVibration(true)
            }
            mgr.createNotificationChannel(incomingChannel)
            val ongoingChannel = NotificationChannel(
                CALL_ONGOING_CHANNEL_ID,
                CALL_ONGOING_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Current xVeil call controls."
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
            }
            mgr.createNotificationChannel(ongoingChannel)
        }
    }

    private fun buildNotification(
        title: String,
        text: String?,
        hangupAction: Boolean = false,
        ringing: Boolean = false,
    ): Notification {
        val openIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val openPendingIntent = openIntent?.let {
            PendingIntent.getActivity(
                this,
                0xfee2,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }
        val channelId = when {
            ringing -> CALL_INCOMING_CHANNEL_ID
            hangupAction -> CALL_ONGOING_CHANNEL_ID
            else -> CHANNEL_ID
        }
        val builder = NotificationCompat.Builder(this, channelId)
            .setContentTitle(title)
            .setSmallIcon(R.drawable.veil_notification_icon)
            .setOngoing(true)  // user can't swipe-dismiss
            .setShowWhen(false)
            .setPriority(if (ringing) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_HIGH)
            .setCategory(if (hangupAction) NotificationCompat.CATEGORY_CALL else NotificationCompat.CATEGORY_SERVICE)
            .setColor(Color.RED)
            .setContentIntent(openPendingIntent)
        if (text != null) builder.setContentText(text)
        if (hangupAction && openIntent != null) {
            if (ringing) {
                val acceptIntent = Intent(openIntent).apply {
                    action = APP_ACTION_ACCEPT
                    putExtra("xveil_call_action", "accept")
                }
                val acceptPendingIntent = PendingIntent.getActivity(
                    this,
                    0xfee4,
                    acceptIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                builder.addAction(
                    R.drawable.veil_notification_icon,
                    "Answer",
                    acceptPendingIntent,
                )
            }
            val endIntent = Intent(openIntent).apply {
                action = APP_ACTION_HANGUP
                putExtra("xveil_call_action", "hangup")
            }
            val endPendingIntent = PendingIntent.getActivity(
                this,
                0xfee3,
                endIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            builder.addAction(
                R.drawable.veil_notification_icon,
                "End call",
                endPendingIntent,
            )
        }
        if (ringing && openPendingIntent != null) {
            builder.setFullScreenIntent(openPendingIntent, true)
        }
        return builder.build()
    }

    private fun startForegroundCompat(
        notification: Notification,
        microphone: Boolean,
        camera: Boolean,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Android 14+ requires a foregroundServiceType matching
            // the service's actual purpose.  REMOTE_MESSAGING fits
            // veil's use case (continuously receive messages over
            // the internet for messaging apps) — gives us latitude
            // to maintain network connections in the background
            // without the user-visible CONNECTED_DEVICE / DATA_SYNC
            // restrictions.
            var type = ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING
            if (microphone) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            if (camera) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
            try {
                startForeground(NOTIFICATION_ID, notification, type)
            } catch (error: SecurityException) {
                // Runtime capture permissions and Android's foreground-only
                // eligibility can change while a call is entering PiP.  A
                // rejected media type must degrade to process/network
                // retention, never crash the entire application.
                Log.w(TAG, "Media foreground-service type rejected; using remoteMessaging", error)
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING,
                )
            }
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }
}
