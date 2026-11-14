package com.oceanwildstudios.wavernote

import android.content.Intent
import android.os.Bundle
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  // Con música sonando, "atrás" manda la app al fondo en vez de cerrarla:
  // la cola y la notificación siguen funcionando. En pausa o sin música se
  // comporta como siempre y la app se cierra.
  private val backCallback = object : OnBackPressedCallback(true) {
    override fun handleOnBackPressed() {
      if (MediaBridge.isPlaying) {
        moveTaskToBack(true)
      } else {
        isEnabled = false
        onBackPressedDispatcher.onBackPressed()
      }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    MediaBridge.attachActivity(this)
    WatchedFolderBridge.attachActivity(this)
    super.onCreate(savedInstanceState)
    onBackPressedDispatcher.addCallback(this, backCallback)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    MediaBridge.attachWebView(webView)
    WatchedFolderBridge.attachWebView(webView)
    webView.addJavascriptInterface(MediaBridge, "WaverNoteAndroid")
    webView.addJavascriptInterface(WatchedFolderBridge, "WaverNoteFolder")
  }

  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (WatchedFolderBridge.onActivityResult(requestCode, resultCode, data)) return
    super.onActivityResult(requestCode, resultCode, data)
  }

  override fun onResume() {
    super.onResume()
    backCallback.isEnabled = true
  }

  // Tauri pausa la WebView al mandar la app al fondo, y con ella los
  // temporizadores de JavaScript que hacen avanzar la cola. Mientras suena
  // música (o sigue la notificación) la reanudamos para que el reproductor
  // continúe pista tras pista con la pantalla apagada o en otra app.
  override fun onPause() {
    super.onPause()
    if (MediaBridge.isPlaying || MediaPlaybackService.isRunning) {
      MediaBridge.resumeWebView()
    }
  }

  override fun onDestroy() {
    MediaBridge.attachWebView(null)
    WatchedFolderBridge.attachWebView(null)
    WatchedFolderBridge.detachActivity(this)
    // La WebView se destruye con la actividad, así que el audio ya no puede
    // seguir: cerramos también la notificación para no dejar un aviso muerto.
    MediaBridge.stopMedia()
    MediaBridge.detachActivity(this)
    super.onDestroy()
  }
}
