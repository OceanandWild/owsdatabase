package com.oceanwildstudios.wavernote

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.support.v4.media.MediaMetadataCompat
import android.support.v4.media.session.MediaSessionCompat
import android.support.v4.media.session.PlaybackStateCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * Notificación de reproducción estilo Spotify para WaverNote.
 *
 * No reproduce audio: el sonido y la cola viven en el WebView. Este servicio
 * mantiene el proceso en primer plano, pinta la notificación con carátula y
 * traduce los controles del sistema a acciones del reproductor web.
 */
class MediaPlaybackService : Service() {
  companion object {
    private const val ACTION_UPDATE = "com.oceanwildstudios.wavernote.media.UPDATE"
    private const val ACTION_STOP = "com.oceanwildstudios.wavernote.media.STOP"
    private const val ACTION_PLAY = "com.oceanwildstudios.wavernote.media.PLAY"
    private const val ACTION_PAUSE = "com.oceanwildstudios.wavernote.media.PAUSE"
    private const val ACTION_NEXT = "com.oceanwildstudios.wavernote.media.NEXT"
    private const val ACTION_PREVIOUS = "com.oceanwildstudios.wavernote.media.PREVIOUS"

    private const val EXTRA_STATE = "state"
    private const val CHANNEL_ID = "wavernote-playback"
    private const val NOTIFICATION_ID = 4101
    private const val ARTWORK_MAX_SIZE = 512

    @Volatile
    var isRunning: Boolean = false
      private set

    @Volatile
    private var instance: MediaPlaybackService? = null

    fun update(context: Context, state: JSONObject) {
      // Si el servicio ya está vivo, actualizamos en el acto: no hace falta
      // volver a arrancar un servicio en primer plano cada cinco segundos.
      val running = instance
      if (running != null) {
        running.updateFromJson(state.toString())
        return
      }

      val intent = Intent(context, MediaPlaybackService::class.java).apply {
        action = ACTION_UPDATE
        putExtra(EXTRA_STATE, state.toString())
      }
      try {
        ContextCompat.startForegroundService(context, intent)
      } catch (err: Exception) {
        /* Android puede bloquear el arranque en segundo plano; la app sigue */
      }
    }

    fun stop(context: Context) {
      context.stopService(Intent(context, MediaPlaybackService::class.java))
    }
  }

  private lateinit var session: MediaSessionCompat
  private val artworkExecutor = Executors.newSingleThreadExecutor()
  private val mainHandler = Handler(Looper.getMainLooper())

  private var snapshot = Snapshot()
  private var artwork: Bitmap? = null
  private var artworkUrl = ""
  private var foregroundStarted = false
  private var wakeLock: PowerManager.WakeLock? = null

  private data class Snapshot(
    val title: String = "WaverNote",
    val artist: String = "",
    val album: String = "",
    val artworkUrl: String = "",
    val isPlaying: Boolean = false,
    val duration: Long = 0,
    val position: Long = 0
  )

  override fun onCreate() {
    super.onCreate()
    isRunning = true
    instance = this
    createChannel()

    session = MediaSessionCompat(this, "WaverNote").apply {
      setCallback(object : MediaSessionCompat.Callback() {
        override fun onPlay() {
          optimism(true)
          MediaBridge.dispatch("play")
        }

        override fun onPause() {
          optimism(false)
          MediaBridge.dispatch("pause")
        }

        override fun onSkipToNext() {
          MediaBridge.dispatch("next")
        }

        override fun onSkipToPrevious() {
          MediaBridge.dispatch("previous")
        }

        override fun onSeekTo(pos: Long) {
          MediaBridge.dispatch("seek:${pos / 1000.0}")
        }

        override fun onStop() {
          optimism(false)
          MediaBridge.dispatch("stop")
        }
      })
      isActive = true
    }
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (intent == null) {
      // El sistema recreó el servicio sin datos: mostramos la notificación
      // mínima y lo cerramos para no dejar el proceso en primer plano.
      if (!foregroundStarted) startForegroundCompat()
      stopSelfSafely()
      return START_NOT_STICKY
    }

    when (intent.action) {
      ACTION_UPDATE -> {
        applyState(intent.getStringExtra(EXTRA_STATE))
        render()
      }
      ACTION_PLAY -> {
        optimism(true)
        MediaBridge.dispatch("play")
      }
      ACTION_PAUSE -> {
        optimism(false)
        MediaBridge.dispatch("pause")
      }
      ACTION_NEXT -> MediaBridge.dispatch("next")
      ACTION_PREVIOUS -> MediaBridge.dispatch("previous")
      ACTION_STOP -> {
        MediaBridge.dispatch("stop")
        stopSelfSafely()
      }
      else -> stopSelfSafely()
    }

    return START_NOT_STICKY
  }

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onDestroy() {
    isRunning = false
    if (instance === this) instance = null
    updateWakeLock(false)
    artworkExecutor.shutdownNow()
    session.isActive = false
    session.release()
    super.onDestroy()
  }

  /** Actualización recibida mientras el servicio ya estaba corriendo. */
  fun updateFromJson(json: String) {
    mainHandler.post {
      applyState(json)
      render()
    }
  }

  private fun applyState(json: String?) {
    if (json.isNullOrBlank()) return
    val data = try {
      JSONObject(json)
    } catch (err: Exception) {
      return
    }

    snapshot = Snapshot(
      title = data.optString("title", "WaverNote"),
      artist = data.optString("artist", ""),
      album = data.optString("album", ""),
      artworkUrl = data.optString("artwork", ""),
      isPlaying = data.optBoolean("isPlaying", false),
      duration = (data.optDouble("duration", 0.0) * 1000.0).toLong().coerceAtLeast(0),
      position = (data.optDouble("position", 0.0) * 1000.0).toLong().coerceAtLeast(0)
    )

    if (snapshot.artworkUrl != artworkUrl) {
      artworkUrl = snapshot.artworkUrl
      artwork = null
      loadArtwork(artworkUrl)
    }
  }

  /** Antes de que conteste el WebView, el botón responde al instante. */
  private fun optimism(playing: Boolean) {
    if (snapshot.isPlaying == playing) return
    snapshot = snapshot.copy(isPlaying = playing)
    render()
  }

  private fun render() {
    if (!foregroundStarted) {
      startForegroundCompat()
    }

    updateWakeLock(snapshot.isPlaying)
    updateSession()
    val notification = buildNotification()

    if (foregroundStarted) {
      try {
        NotificationManagerCompat.from(this).notify(NOTIFICATION_ID, notification)
      } catch (err: SecurityException) {
        /* Android 13 sin permiso de notificaciones: el servicio sigue vivo */
      }
    }
  }

  private fun startForegroundCompat() {
    try {
      val notification = buildNotification()
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        startForeground(
          NOTIFICATION_ID,
          notification,
          ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
        )
      } else {
        startForeground(NOTIFICATION_ID, notification)
      }
      foregroundStarted = true
    } catch (err: Exception) {
      foregroundStarted = false
      stopSelfSafely()
    }
  }

  /**
   * Mantiene la CPU despierta mientras suena la cola, incluso con la pantalla
   * apagada. Sin esto Android puede suspender los temporizadores del WebView
   * y la reproducción se corta al terminar la pista actual.
   */
  private fun updateWakeLock(playing: Boolean) {
    if (playing) {
      if (wakeLock?.isHeld == true) return
      val power = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return
      wakeLock = power.newWakeLock(
        PowerManager.PARTIAL_WAKE_LOCK,
        "WaverNote:Playback"
      ).apply {
        setReferenceCounted(false)
        acquire(10 * 60 * 60 * 1000L)
      }
    } else {
      wakeLock?.let { if (it.isHeld) it.release() }
      wakeLock = null
    }
  }

  private fun updateSession() {
    val metadata = MediaMetadataCompat.Builder()
      .putString(MediaMetadataCompat.METADATA_KEY_TITLE, snapshot.title)
      .putString(MediaMetadataCompat.METADATA_KEY_ARTIST, snapshot.artist)
      .putString(MediaMetadataCompat.METADATA_KEY_ALBUM, snapshot.album)
      .putLong(MediaMetadataCompat.METADATA_KEY_DURATION, snapshot.duration)

    artwork?.let {
      metadata.putBitmap(MediaMetadataCompat.METADATA_KEY_ALBUM_ART, it)
      metadata.putBitmap(MediaMetadataCompat.METADATA_KEY_ART, it)
    }
    session.setMetadata(metadata.build())

    val actions = PlaybackStateCompat.ACTION_PLAY or
      PlaybackStateCompat.ACTION_PAUSE or
      PlaybackStateCompat.ACTION_PLAY_PAUSE or
      PlaybackStateCompat.ACTION_SKIP_TO_NEXT or
      PlaybackStateCompat.ACTION_SKIP_TO_PREVIOUS or
      PlaybackStateCompat.ACTION_SEEK_TO or
      PlaybackStateCompat.ACTION_STOP

    session.setPlaybackState(
      PlaybackStateCompat.Builder()
        .setActions(actions)
        .setState(
          if (snapshot.isPlaying) PlaybackStateCompat.STATE_PLAYING else PlaybackStateCompat.STATE_PAUSED,
          snapshot.position,
          if (snapshot.isPlaying) 1f else 0f
        )
        .build()
    )
  }

  private fun buildNotification(): Notification {
    val openIntent = Intent(this, MainActivity::class.java).apply {
      flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
    }
    val contentIntent = PendingIntent.getActivity(
      this,
      0,
      openIntent,
      pendingIntentFlags()
    )

    val subtitle = listOf(snapshot.artist, snapshot.album)
      .filter { it.isNotBlank() }
      .joinToString(" · ")

    val builder = NotificationCompat.Builder(this, CHANNEL_ID)
      .setSmallIcon(R.drawable.ic_stat_wavernote)
      .setContentTitle(snapshot.title.ifBlank { "WaverNote" })
      .setContentText(subtitle.ifBlank { "Tu música" })
      .setSubText("WaverNote")
      .setLargeIcon(artwork ?: BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher))
      .setContentIntent(contentIntent)
      .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
      .setCategory(NotificationCompat.CATEGORY_TRANSPORT)
      .setColor(0xFF0E2A2A.toInt())
      .setOnlyAlertOnce(true)
      .setShowWhen(false)
      .setOngoing(snapshot.isPlaying)
      .setSilent(true)
      .addAction(
        android.R.drawable.ic_media_previous,
        "Anterior",
        serviceIntent(ACTION_PREVIOUS, 1)
      )
      .addAction(
        if (snapshot.isPlaying) android.R.drawable.ic_media_pause else android.R.drawable.ic_media_play,
        if (snapshot.isPlaying) "Pausar" else "Reproducir",
        serviceIntent(if (snapshot.isPlaying) ACTION_PAUSE else ACTION_PLAY, 2)
      )
      .addAction(
        android.R.drawable.ic_media_next,
        "Siguiente",
        serviceIntent(ACTION_NEXT, 3)
      )
      .setStyle(
        androidx.media.app.NotificationCompat.MediaStyle()
          .setMediaSession(session.sessionToken)
          .setShowActionsInCompactView(0, 1, 2)
      )

    if (snapshot.duration > 0) {
      builder.setProgress(
        snapshot.duration.toInt(),
        snapshot.position.coerceAtMost(snapshot.duration).toInt(),
        false
      )
    }

    return builder.build()
  }

  private fun serviceIntent(action: String, requestCode: Int): PendingIntent {
    val intent = Intent(this, MediaPlaybackService::class.java).apply {
      this.action = action
    }
    return PendingIntent.getService(this, requestCode, intent, pendingIntentFlags())
  }

  private fun pendingIntentFlags(): Int {
    var flags = PendingIntent.FLAG_UPDATE_CURRENT
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      flags = flags or PendingIntent.FLAG_IMMUTABLE
    }
    return flags
  }

  private fun createChannel() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    val manager = getSystemService(NotificationManager::class.java) ?: return
    val channel = NotificationChannel(
      CHANNEL_ID,
      "Reproducción",
      NotificationManager.IMPORTANCE_LOW
    ).apply {
      description = "Controles de la música que suena en WaverNote"
      setShowBadge(false)
      lockscreenVisibility = Notification.VISIBILITY_PUBLIC
    }
    manager.createNotificationChannel(channel)
  }

  private fun loadArtwork(url: String) {
    if (url.isBlank()) {
      mainHandler.post { render() }
      return
    }

    artworkExecutor.execute {
      val bitmap = downloadArtwork(url)
      if (bitmap == null) return@execute
      mainHandler.post {
        if (artworkUrl == url) {
          artwork = bitmap
          render()
        }
      }
    }
  }

  private fun downloadArtwork(url: String): Bitmap? {
    var connection: HttpURLConnection? = null
    return try {
      connection = (URL(url).openConnection() as HttpURLConnection).apply {
        connectTimeout = 8000
        readTimeout = 8000
        instanceFollowRedirects = true
      }
      val bitmap = connection.inputStream.use { BitmapFactory.decodeStream(it) }
        ?: return null
      val largest = maxOf(bitmap.width, bitmap.height)
      if (largest <= ARTWORK_MAX_SIZE) {
        bitmap
      } else {
        val scale = ARTWORK_MAX_SIZE.toFloat() / largest
        Bitmap.createScaledBitmap(
          bitmap,
          (bitmap.width * scale).toInt().coerceAtLeast(1),
          (bitmap.height * scale).toInt().coerceAtLeast(1),
          true
        ).also { if (it !== bitmap) bitmap.recycle() }
      }
    } catch (err: Exception) {
      null
    } finally {
      connection?.disconnect()
    }
  }

  private fun stopSelfSafely() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      stopForeground(Service.STOP_FOREGROUND_REMOVE)
    } else {
      @Suppress("DEPRECATION")
      stopForeground(true)
    }
    stopSelf()
  }
}
