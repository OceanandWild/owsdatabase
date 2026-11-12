package com.oceanwildstudios.wavernote

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin
import java.io.File

@InvokeArg
class InstallApkArgs {
  lateinit var path: String
}

/**
 * Puente mínimo con Android para instalar el APK que descarga el updater de
 * WaverNote. No pide permisos de almacenamiento: el archivo vive en la caché
 * privada de la app y se comparte con el instalador vía FileProvider.
 */
@TauriPlugin
class UpdaterPlugin(private val activity: Activity) : Plugin(activity) {
  @Command
  fun installApk(invoke: Invoke) {
    try {
      val args = invoke.parseArgs(InstallApkArgs::class.java)
      val file = File(args.path)
      if (!file.isFile) {
        invoke.reject("El instalador descargado ya no está disponible. Volvé a intentar.")
        return
      }

      // Android 8+: la app necesita "Instalar apps desconocidas". Si todavía
      // no está habilitado, abrimos los ajustes de WaverNote para que el
      // usuario lo active y pueda reintentar.
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
        !activity.packageManager.canRequestPackageInstalls()
      ) {
        val settings = Intent(
          Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
          Uri.parse("package:${activity.packageName}")
        )
        activity.startActivity(settings)
        invoke.reject("Habilitá «Instalar apps desconocidas» para WaverNote y volvé a intentar.")
        return
      }

      val uri = FileProvider.getUriForFile(
        activity,
        "${activity.packageName}.fileprovider",
        file
      )
      val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, "application/vnd.android.package-archive")
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      }
      activity.startActivity(intent)
      invoke.resolve()
    } catch (err: Exception) {
      invoke.reject(err.message ?: "No se pudo abrir el instalador de Android.")
    }
  }
}
