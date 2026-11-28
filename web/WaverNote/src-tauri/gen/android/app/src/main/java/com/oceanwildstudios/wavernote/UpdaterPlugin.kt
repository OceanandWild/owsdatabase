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
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest

@InvokeArg
class InstallApkArgs {
  lateinit var path: String
}

@InvokeArg
class DownloadApkArgs {
  lateinit var url: String
  var sha256: String = ""
  var sizeBytes: Long = 0
  var fileName: String = ""
  lateinit var onEvent: Channel
}

/**
 * Puente con Android para bajar e instalar el APK de WaverNote.
 *
 * La descarga usa HttpURLConnection para apoyarse en la pila de red del
 * sistema (TLS, proxy y resolución de nombres del dispositivo), reanuda desde
 * el byte donde se cortó y valida el SHA-256 antes de abrir el instalador.
 * No pide permisos de almacenamiento: el archivo vive en la caché privada de
 * la app y se comparte con el instalador vía FileProvider.
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

  @Command
  fun downloadApk(invoke: Invoke) {
    val args = try {
      invoke.parseArgs(DownloadApkArgs::class.java)
    } catch (err: Exception) {
      invoke.reject(err.message ?: "No se pudo iniciar la descarga del APK.")
      return
    }

    if (!args.url.startsWith("https://", ignoreCase = true)) {
      invoke.reject("La actualización tiene que descargarse por HTTPS.")
      return
    }

    val expectedSha256 = args.sha256.trim().lowercase()
    if (!SHA256_PATTERN.matches(expectedSha256)) {
      invoke.reject("La actualización no incluye un SHA-256 válido. No se descargará.")
      return
    }

    // La descarga bloquea el hilo: se hace fuera del hilo principal para que
    // la interfaz siga respondiendo y la Activity no se congele.
    Thread {
      try {
        val path = downloadApkBlocking(
          args.url,
          expectedSha256,
          args.sizeBytes,
          args.fileName,
          args.onEvent
        )
        activity.runOnUiThread { invoke.resolveObject(path) }
      } catch (err: Exception) {
        activity.runOnUiThread {
          invoke.reject(err.message ?: "No se pudo descargar el APK.")
        }
      }
    }.apply {
      name = "wavernote-apk-download"
      start()
    }
  }

  private fun downloadApkBlocking(
    url: String,
    expectedSha256: String,
    expectedSize: Long,
    rawFileName: String,
    channel: Channel
  ): String {
    val dir = File(activity.cacheDir, "updates")
    if (!dir.isDirectory && !dir.mkdirs()) {
      throw IOException("No se pudo preparar la carpeta de descargas.")
    }

    val dest = File(dir, safeApkName(rawFileName))
    val expectedLength = if (expectedSize > 0) expectedSize else 0L

    // Los APK de versiones anteriores solo ocupan espacio. El archivo de esta
    // versión se conserva para poder reintentar la instalación sin bajarlo de
    // nuevo si el usuario todavía no habilitó "Instalar apps desconocidas".
    runCatching {
      dir.listFiles()?.forEach { file ->
        if (file.isFile && file.name != dest.name && file.name.endsWith(".apk", true)) {
          file.delete()
        }
      }
    }

    // Si una descarga anterior ya terminó y el hash coincide, no se repite.
    if (dest.isFile && expectedLength > 0) {
      if (dest.length() == expectedLength && sha256Of(dest) == expectedSha256) {
        sendStarted(channel, expectedLength, expectedLength)
        channel.send(downloadEvent("Finished"))
        return dest.absolutePath
      }
      if (dest.length() > expectedLength) {
        dest.delete()
      }
    }

    var lastMessage = "La descarga no se completó."
    for (attempt in 1..APK_DOWNLOAD_ATTEMPTS) {
      try {
        downloadApkPass(url, dest, expectedSha256, expectedLength, channel)
        channel.send(downloadEvent("Finished"))
        return dest.absolutePath
      } catch (err: Exception) {
        val message = err.message?.trim()
        if (!message.isNullOrEmpty()) lastMessage = message
        // Un archivo con otro contenido no se puede reanudar: se descarta.
        if (err is ApkHashMismatchException) dest.delete()

        if (attempt < APK_DOWNLOAD_ATTEMPTS) {
          val partial = if (dest.isFile) dest.length() else 0L
          sendStarted(channel, expectedLength, partial)
          Thread.sleep(APK_RETRY_DELAY_MS)
        }
      }
    }

    throw IOException(
      "$lastMessage Se intentó $APK_DOWNLOAD_ATTEMPTS veces; revisá la conexión y volvé a probar."
    )
  }

  private fun downloadApkPass(
    url: String,
    dest: File,
    expectedSha256: String,
    expectedLength: Long,
    channel: Channel
  ) {
    var existing = if (dest.isFile) dest.length() else 0L
    if (expectedLength > 0 && existing > expectedLength) {
      dest.delete()
      existing = 0L
    }
    if (expectedLength > 0 && existing == expectedLength) {
      if (sha256Of(dest) == expectedSha256) {
        sendStarted(channel, expectedLength, existing)
        return
      }
      dest.delete()
      existing = 0L
    }

    val connection = openApkConnection(url, existing)
    try {
      val code = connection.responseCode
      var range: Pair<Long, Long>? = null

      if (code == HttpURLConnection.HTTP_OK) {
        // El servidor ignoró el Range: se descarga desde el principio.
        existing = 0L
      } else if (code == HttpURLConnection.HTTP_PARTIAL) {
        range = parseContentRange(connection.getHeaderField("Content-Range"))
        if (range != null && range.first != existing) {
          dest.delete()
          throw IOException("El servidor devolvió un tramo distinto al solicitado.")
        }
      } else if (code == 416) {
        dest.delete()
        throw IOException("El servidor rechazó reanudar la descarga.")
      } else {
        throw IOException("El servidor respondió $code.")
      }

      val rangeTotal = range?.second ?: 0L
      val total = when {
        expectedLength > 0 -> expectedLength
        rangeTotal > 0 -> rangeTotal
        else -> contentLength(connection)
      }

      sendStarted(channel, total, existing)

      var received = existing
      var lastReport = 0L
      val buffer = ByteArray(APK_BUFFER_SIZE)
      RandomAccessFile(dest, "rw").use { file ->
        file.setLength(existing)
        file.seek(existing)
        connection.inputStream.use { input ->
          while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            file.write(buffer, 0, read)
            received += read

            val now = System.currentTimeMillis()
            if (now - lastReport >= APK_PROGRESS_INTERVAL_MS) {
              lastReport = now
              val data = JSObject()
              data.put("chunkLength", read)
              data.put("received", received)
              channel.send(downloadEvent("Progress", data))
            }
          }
        }
      }

      if (expectedLength > 0 && received != expectedLength) {
        throw IOException("La descarga llegó incompleta ($received de $expectedLength bytes).")
      }
      if (total > 0 && received != total) {
        throw IOException("La descarga llegó incompleta ($received de $total bytes).")
      }
      if (sha256Of(dest) != expectedSha256) {
        throw ApkHashMismatchException("El APK descargado no coincide con el SHA-256 del manifiesto.")
      }
    } finally {
      connection.disconnect()
    }
  }

  /**
   * Abre la conexión siguiendo las redirecciones a mano para conservar el
   * encabezado Range cuando GitHub deriva el APK a su CDN.
   */
  private fun openApkConnection(url: String, rangeStart: Long): HttpURLConnection {
    var current = url
    for (hop in 0..APK_MAX_REDIRECTS) {
      val connection = (URL(current).openConnection() as? HttpURLConnection)
        ?: throw IOException("El servidor de actualizaciones no es válido.")

      connection.instanceFollowRedirects = false
      connection.connectTimeout = APK_CONNECT_TIMEOUT_MS
      connection.readTimeout = APK_READ_TIMEOUT_MS
      connection.useCaches = false
      connection.requestMethod = "GET"
      connection.setRequestProperty("User-Agent", "WaverNote-Android")
      connection.setRequestProperty(
        "Accept",
        "application/vnd.android.package-archive, application/octet-stream"
      )
      connection.setRequestProperty("Accept-Encoding", "identity")
      if (rangeStart > 0) {
        connection.setRequestProperty("Range", "bytes=$rangeStart-")
      }

      val code = connection.responseCode
      if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
        val location = connection.getHeaderField("Location")
        connection.disconnect()
        if (location.isNullOrBlank()) {
          throw IOException("El servidor redirigió la descarga sin destino.")
        }
        val next = URI(current).resolve(location).toString()
        if (!next.startsWith("https://", ignoreCase = true)) {
          throw IOException("La redirección de la descarga no es segura.")
        }
        current = next
        continue
      }

      return connection
    }

    throw IOException("La descarga dio demasiadas vueltas.")
  }

  private fun sendStarted(channel: Channel, total: Long, received: Long) {
    val data = JSObject()
    data.put("contentLength", total)
    data.put("received", received)
    channel.send(downloadEvent("Started", data))
  }

  private fun downloadEvent(name: String, data: JSObject? = null): JSObject {
    val event = JSObject()
    event.put("event", name)
    if (data != null) event.put("data", data)
    return event
  }

  private fun contentLength(connection: HttpURLConnection): Long {
    val value = connection.getHeaderField("Content-Length")?.trim()?.toLongOrNull() ?: 0L
    return if (value > 0) value else 0L
  }

  /** Devuelve (primer byte, total) del encabezado Content-Range. */
  private fun parseContentRange(value: String?): Pair<Long, Long>? {
    if (value.isNullOrBlank()) return null
    val match = CONTENT_RANGE_PATTERN.find(value) ?: return null
    val start = match.groupValues[1].toLongOrNull() ?: return null
    val total = match.groupValues[3].toLongOrNull() ?: 0L
    return start to total
  }

  private fun safeApkName(raw: String): String {
    var name = raw.filter {
      it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' || it == '_'
    }.trim('.')
    if (name.isEmpty()) name = "wavernote-update"
    if (!name.endsWith(".apk", ignoreCase = true)) name += ".apk"
    return name
  }

  private fun sha256Of(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    FileInputStream(file).use { input ->
      val buffer = ByteArray(APK_BUFFER_SIZE)
      while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        if (read > 0) digest.update(buffer, 0, read)
      }
    }
    return digest.digest().joinToString("") { byte ->
      "%02x".format(byte.toInt() and 0xff)
    }
  }

  private class ApkHashMismatchException(message: String) : IOException(message)

  private companion object {
    const val APK_DOWNLOAD_ATTEMPTS = 3
    const val APK_RETRY_DELAY_MS = 2000L
    const val APK_CONNECT_TIMEOUT_MS = 20000
    const val APK_READ_TIMEOUT_MS = 60000
    const val APK_PROGRESS_INTERVAL_MS = 250L
    const val APK_BUFFER_SIZE = 64 * 1024
    const val APK_MAX_REDIRECTS = 5

    val SHA256_PATTERN = Regex("^[a-f0-9]{64}$")
    val CONTENT_RANGE_PATTERN = Regex("""bytes\s+(\d+)-(\d+)/(\d+|\*)""", RegexOption.IGNORE_CASE)
  }
}
