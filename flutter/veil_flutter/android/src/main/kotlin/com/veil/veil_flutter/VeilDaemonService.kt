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
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

class VeilDaemonService : Service() {

    companion object {
        const val ACTION_START = "com.veil.veil_flutter.action.START"
        const val ACTION_STOP  = "com.veil.veil_flutter.action.STOP"
        const val EXTRA_NOTIFICATION_TITLE = "notification_title"
        const val EXTRA_NOTIFICATION_TEXT  = "notification_text"

        private const val CHANNEL_ID = "veil_daemon"
        private const val CHANNEL_NAME = "Veil daemon"
        private const val NOTIFICATION_ID = 0xfee1
    }

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
        // Start foreground IMMEDIATELY (within 5 s of onCreate) — Android
        // 12+ is strict about this and kills the service otherwise.
        // The notification text is updated later when onStartCommand
        // receives the actual title / body via Intent extras.
        startForegroundCompat(buildNotification(getString(R.string.veil_default_title), null))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForegroundCompat()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                val title = intent?.getStringExtra(EXTRA_NOTIFICATION_TITLE)
                    ?: getString(R.string.veil_default_title)
                val text = intent?.getStringExtra(EXTRA_NOTIFICATION_TEXT)
                startForegroundCompat(buildNotification(title, text))
            }
        }
        // START_STICKY: if the OS kills us under memory pressure,
        // re-create the service on next available opportunity.  Persistent-
        // by-design for a P2P connection-maintaining service.
        return START_STICKY
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
        }
    }

    private fun buildNotification(title: String, text: String?): Notification {
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setSmallIcon(R.drawable.veil_notification_icon)
            .setOngoing(true)  // user can't swipe-dismiss
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
        if (text != null) builder.setContentText(text)
        return builder.build()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Android 14+ requires a foregroundServiceType matching
            // the service's actual purpose.  REMOTE_MESSAGING fits
            // veil's use case (continuously receive messages over
            // the internet for messaging apps) — gives us latitude
            // to maintain network connections in the background
            // without the user-visible CONNECTED_DEVICE / DATA_SYNC
            // restrictions.
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING,
            )
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
