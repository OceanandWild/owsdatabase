package com.oceanwildstudios.wavernote

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject

/**
 * Puente entre el reproductor web de WaverNote y Android.
 *
 * El audio sigue saliendo del <audio> del WebView. Android solo se encarga de
 * dos cosas que la web no puede resolver sola dentro de una app:
 *  - mostrar la notificación de reproducción (MediaStyle) con carátula y
 *    controles de anterior / play-pausa / siguiente;
 *  - mantener viva la WebView cuando la app pasa a segundo plano, para que el
 *    temporizador que avanza la cola siga funcionando.
 */
object MediaBridge {
  private const val NOTIFICATION_PERMISSION_REQUEST = 4102

  @Volatile
  private var activity: Activity? = null

  @Volatile
  private var webView: WebView? = null

  @Volatile
  private var notificationPermissionRequested = false

  @Volatile
  var isPlaying: Boolean = false
    private set

  fun attachActivity(activity: Activity) {
    this.activity = activity
  }

  fun detachActivity(activity: Activity) {
    if (this.activity === activity) this.activity = null
  }

  fun attachWebView(view: WebView?) {
    webView = view
  }

  /** La notificación actualiza su estado (título, carátula, play/pausa). */
  @JavascriptInterface
  fun updateMedia(json: String) {
    val data = try {
      JSONObject(json)
    } catch (err: Exception) {
      return
    }

    isPlaying = data.optBoolean("isPlaying", false)

    val context = activity ?: return
    if (isPlaying || MediaPlaybackService.isRunning) {
      MediaPlaybackService.update(context, data)
    }
    requestNotificationPermissionIfNeeded(context)
  }

  /** Evita que Android pause la WebView mientras hay audio en curso. */
  @JavascriptInterface
  fun setPlaybackActive(active: Boolean) {
    isPlaying = active
  }

  /**
   * Deshace el [WebView.onPause] que Tauri aplica al pasar a segundo plano.
   *
   * Sin esto Android detiene los temporizadores de JavaScript y la cola deja
   * de avanzar sola cuando se cierra la pantalla o se abre otra app. Solo se
   * llama mientras hay reproducción o una notificación activa.
   */
  fun resumeWebView() {
    val view = webView ?: return
    view.post {
      try {
        view.onResume()
        view.resumeTimers()
      } catch (err: Exception) {
        /* la WebView pudo haberse destruido */
      }
    }
  }

  @JavascriptInterface
  fun stopMedia() {
    isPlaying = false
    activity?.let { MediaPlaybackService.stop(it) }
  }

  /** Un botón de la notificación o del lockscreen llega al reproductor web. */
  fun dispatch(action: String) {
    val view = webView ?: return
    val safe = action.replace("\\", "\\\\").replace("'", "\\'")
    view.post {
      try {
        view.evaluateJavascript(
          "window.WaverNoteMediaControls && window.WaverNoteMediaControls.handle('$safe');",
          null
        )
      } catch (err: Exception) {
        /* la WebView pudo haberse destruido */
      }
    }
  }

  private fun requestNotificationPermissionIfNeeded(activity: Activity) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    if (notificationPermissionRequested) return
    if (ContextCompat.checkSelfPermission(
        activity,
        android.Manifest.permission.POST_NOTIFICATIONS
      ) == PackageManager.PERMISSION_GRANTED
    ) {
      return
    }

    notificationPermissionRequested = true
    activity.runOnUiThread {
      ActivityCompat.requestPermissions(
        activity,
        arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
        NOTIFICATION_PERMISSION_REQUEST
      )
    }
  }
}
