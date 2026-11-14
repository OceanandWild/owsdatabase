package com.oceanwildstudios.wavernote

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.provider.DocumentsContract
import android.webkit.JavascriptInterface
import android.webkit.WebView
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.ArrayDeque
import java.util.concurrent.Executors

/**
 * Carpeta vigilada en Android.
 *
 * Usa el selector de árbol del sistema (SAF): no pide permiso de
 * almacenamiento y guarda el acceso a la carpeta elegida. Desde acá se
 * enumeran los audios, se leen sus etiquetas y se sube el archivo que el
 * frontend reconoció como pendiente.
 *
 * Igual que MediaBridge, es un puente JavaScript nativo para no agregar un
 * plugin de Tauri específico. La app no descarga música de ninguna plataforma.
 */
object WatchedFolderBridge {
  private const val PICK_REQUEST = 4104
  private const val MAX_FILES = 12_000
  private const val MAX_DEPTH = 12
  private const val MAX_TAG_FILES = 150

  private val AUDIO_EXTENSIONS = setOf(
    "mp3", "wav", "ogg", "oga", "m4a", "mp4", "aac", "flac", "opus", "webm"
  )

  private val SYSTEM_DIRS = setOf(
    "\$recycle.bin", "system volume information", "recycler", "lost+found", "node_modules"
  )

  private val DOC_PROJECTION = arrayOf(
    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
    DocumentsContract.Document.COLUMN_MIME_TYPE,
    DocumentsContract.Document.COLUMN_SIZE,
    DocumentsContract.Document.COLUMN_LAST_MODIFIED
  )

  @Volatile
  private var activity: Activity? = null

  @Volatile
  private var webView: WebView? = null

  private val scanner = Executors.newSingleThreadExecutor()
  private val uploader = Executors.newFixedThreadPool(2)

  fun attachActivity(value: Activity) {
    activity = value
  }

  fun attachWebView(view: WebView?) {
    webView = view
  }

  fun detachActivity(value: Activity) {
    if (activity === value) activity = null
  }

  @JavascriptInterface
  fun pickWatchedFolder() {
    val current = activity ?: return
    current.runOnUiThread {
      try {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
          addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
          addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
          addFlags(Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
        }
        current.startActivityForResult(intent, PICK_REQUEST)
      } catch (err: ActivityNotFoundException) {
        emitFolder(errorPayload("No hay un selector de carpetas disponible."))
      } catch (err: Exception) {
        emitFolder(errorPayload("No se pudo abrir el selector de carpetas."))
      }
    }
  }

  /** Devuelve true si el resultado era del selector de la carpeta vigilada. */
  fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
    if (requestCode != PICK_REQUEST) return false

    if (resultCode != Activity.RESULT_OK) {
      emitFolder(JSONObject().put("ok", false).put("cancelled", true))
      return true
    }

    val uri = data?.data
    if (uri == null) {
      emitFolder(errorPayload("El selector no devolvió ninguna carpeta."))
      return true
    }

    val current = activity
    if (current != null) {
      try {
        current.contentResolver.takePersistableUriPermission(
          uri,
          Intent.FLAG_GRANT_READ_URI_PERMISSION
        )
      } catch (err: SecurityException) {
        // Algunos proveedores no permiten persistir el permiso. La carpeta
        // se puede leer ahora; si el sistema lo retira, el frontend pide
        // elegirla de nuevo.
      } catch (err: Exception) {
        // idem
      }
    }

    emitFolder(
      JSONObject()
        .put("ok", true)
        .put("kind", "tree")
        .put("value", uri.toString())
        .put("uri", uri.toString())
        .put("label", treeLabel(uri) ?: uri.lastPathSegment ?: "Carpeta de música")
    )
    return true
  }

  @JavascriptInterface
  fun hasWatchedPermission(uriString: String): Boolean {
    val current = activity ?: return false
    return try {
      val uri = Uri.parse(uriString)
      current.contentResolver.persistedUriPermissions.any { permission ->
        permission.uri == uri && permission.isReadPermission
      }
    } catch (err: Exception) {
      false
    }
  }

  @JavascriptInterface
  fun scanWatchedFolder(uriString: String) {
    val treeUri = try {
      Uri.parse(uriString)
    } catch (err: Exception) {
      emitScan(errorPayload("La carpeta elegida no es válida."))
      return
    }

    scanner.execute {
      val result = try {
        scanTree(treeUri)
      } catch (err: SecurityException) {
        JSONObject()
          .put("ok", false)
          .put("permission", true)
          .put("error", "Android retiró el permiso de esta carpeta.")
      } catch (err: Exception) {
        errorPayload("No se pudo revisar la carpeta: ${friendlyMessage(err)}")
      }
      emitScan(result)
    }
  }

  @JavascriptInterface
  fun readWatchedTags(payload: String): String {
    val current = activity ?: return "[]"
    val entries = try {
      JSONArray(payload)
    } catch (err: Exception) {
      return "[]"
    }

    val result = JSONArray()
    val limit = minOf(entries.length(), MAX_TAG_FILES)

    for (index in 0 until limit) {
      val entry = entries.optJSONObject(index) ?: continue
      val uriString = entry.optString("uri")
      if (uriString.isBlank()) continue

      val retriever = MediaMetadataRetriever()
      try {
        retriever.setDataSource(current, Uri.parse(uriString))
        val title = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_TITLE).orEmpty()
        val artist = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_ARTIST).orEmpty()
        val album = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_ALBUM).orEmpty()
        val durationMs = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)
          ?.toLongOrNull() ?: 0L

        if (title.isNotBlank() || artist.isNotBlank() || album.isNotBlank()) {
          result.put(
            JSONObject()
              .put("uri", uriString)
              .put("title", title)
              .put("artist", artist)
              .put("album", album)
              .put("duration", (durationMs / 1000L).toInt())
          )
        }
      } catch (err: Exception) {
        // Un archivo sin etiquetas legibles no es un error fatal.
      } finally {
        try {
          retriever.release()
        } catch (err: Exception) {
          // noop
        }
      }
    }

    return result.toString()
  }

  @JavascriptInterface
  fun uploadWatchedFile(payload: String) {
    val request = try {
      JSONObject(payload)
    } catch (err: Exception) {
      return
    }

    val requestId = request.optString("requestId")
    uploader.execute {
      val result = try {
        performUpload(request)
      } catch (err: Exception) {
        errorPayload(friendlyMessage(err))
      }
      result.put("requestId", requestId)
      emit("onNativeUpload", result.toString())
    }
  }

  /* ------------------------------------------------------------
     Escaneo
     ------------------------------------------------------------ */

  private fun scanTree(treeUri: Uri): JSONObject {
    val current = activity ?: throw IllegalStateException("La actividad no está disponible.")
    val resolver = current.contentResolver
    val treeDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
    val rootChildren = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeDocumentId)

    val files = JSONArray()
    val queue = ArrayDeque<Pair<String, String>>()
    queue.addLast(rootChildren.toString() to "")

    var truncated = false
    var depthLimited = false

    while (queue.isNotEmpty()) {
      if (files.length() >= MAX_FILES) {
        truncated = true
        break
      }

      val (childrenUriString, prefix) = queue.removeFirst()
      if (prefix.isNotEmpty() && prefix.split("/").size >= MAX_DEPTH) {
        depthLimited = true
        continue
      }

      val childrenUri = Uri.parse(childrenUriString)
      try {
        resolver.query(childrenUri, DOC_PROJECTION, null, null, null)?.use { cursor ->
          val idIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
          val nameIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
          val mimeIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
          val sizeIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
          val modifiedIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)

          while (cursor.moveToNext() && files.length() < MAX_FILES) {
            val documentId = if (idIndex >= 0) cursor.getString(idIndex) else null
            if (documentId.isNullOrBlank()) continue

            val name = (if (nameIndex >= 0) cursor.getString(nameIndex) else null)
              ?.takeIf { it.isNotBlank() }
              ?: documentId.substringAfterLast('/').ifBlank { "audio" }
            if (name.startsWith(".")) continue

            val mime = if (mimeIndex >= 0) cursor.getString(mimeIndex).orEmpty() else ""
            val relative = if (prefix.isEmpty()) name else "$prefix/$name"
            val isDirectory = mime == DocumentsContract.Document.MIME_TYPE_DIR

            if (isDirectory) {
              if (SYSTEM_DIRS.contains(name.lowercase())) continue
              val childUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, documentId)
              queue.addLast(childUri.toString() to relative)
              continue
            }

            val extension = name.substringAfterLast('.', "").lowercase()
            if (!AUDIO_EXTENSIONS.contains(extension)) continue

            val size = if (sizeIndex >= 0) cursor.getLong(sizeIndex) else 0L
            val modified = if (modifiedIndex >= 0) cursor.getLong(modifiedIndex) else 0L
            val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)

            files.put(
              JSONObject()
                .put("uri", fileUri.toString())
                .put("name", name)
                .put("relative", relative)
                .put("size", if (size > 0) size else 0L)
                .put("modified", if (modified > 0) modified else 0L)
            )
          }
        }
      } catch (err: Exception) {
        // Una subcarpeta restringida no debe cortar el resto del escaneo.
      }
    }

    if (files.length() >= MAX_FILES) truncated = true

    return JSONObject()
      .put("ok", true)
      .put("kind", "tree")
      .put("root", treeUri.toString())
      .put("files", files)
      .put("truncated", truncated)
      .put("depthLimited", depthLimited)
  }

  private fun treeLabel(treeUri: Uri): String? {
    val current = activity ?: return null
    return try {
      val documentUri = DocumentsContract.buildDocumentUriUsingTree(
        treeUri,
        DocumentsContract.getTreeDocumentId(treeUri)
      )
      current.contentResolver.query(
        documentUri,
        arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
        null,
        null,
        null
      )?.use { cursor ->
        if (cursor.moveToFirst()) cursor.getString(0) else null
      }
    } catch (err: Exception) {
      null
    }
  }

  /* ------------------------------------------------------------
     Subida multipart (sin cargar el archivo entero en memoria)
     ------------------------------------------------------------ */

  private fun performUpload(request: JSONObject): JSONObject {
    val current = activity ?: throw IllegalStateException("La actividad no está disponible.")
    val uriString = request.optString("uri")
    val apiBase = request.optString("apiBase")
    val token = request.optString("token")
    val fields = request.optJSONObject("fields") ?: JSONObject()

    if (uriString.isBlank()) throw IllegalArgumentException("El archivo no es válido.")
    if (!apiBase.startsWith("https://")) {
      throw IllegalArgumentException("La dirección del servidor no es segura.")
    }

    val uri = Uri.parse(uriString)
    val name = sanitizeFileName(request.optString("name").ifBlank { "audio" })
    val mime = mimeFor(name)
    val boundary = "----WaverNote${System.currentTimeMillis()}"
    val endpoint = URL("${apiBase.trimEnd('/')}/wavernote/tracks")

    val connection = (endpoint.openConnection() as HttpURLConnection).apply {
      requestMethod = "POST"
      doInput = true
      doOutput = true
      useCaches = false
      connectTimeout = 30_000
      readTimeout = 300_000
      setChunkedStreamingMode(256 * 1024)
      setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
      setRequestProperty("Accept", "application/json")
      if (token.isNotBlank()) setRequestProperty("Authorization", "Bearer $token")
    }

    try {
      connection.outputStream.use { rawOutput ->
        val output = rawOutput.buffered(128 * 1024)

        fun writeText(text: String) {
          output.write(text.toByteArray(Charsets.UTF_8))
        }

        val keys = fields.keys()
        while (keys.hasNext()) {
          val key = keys.next()
          val value = fields.optString(key)
          if (value.isBlank()) continue
          writeText(
            "--$boundary\r\n" +
              "Content-Disposition: form-data; name=\"${escapeField(key)}\"\r\n\r\n" +
              "$value\r\n"
          )
        }

        writeText(
          "--$boundary\r\n" +
            "Content-Disposition: form-data; name=\"audio\"; filename=\"${escapeField(name)}\"\r\n" +
            "Content-Type: $mime\r\n\r\n"
        )

        val input = current.contentResolver.openInputStream(uri)
          ?: throw IllegalStateException("No se pudo abrir el archivo.")
        BufferedInputStream(input).use { stream ->
          stream.copyTo(output, 128 * 1024)
        }
        writeText("\r\n--$boundary--\r\n")
        output.flush()
      }

      val status = connection.responseCode
      val stream = if (status in 200..299) connection.inputStream else connection.errorStream
      val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
      val parsed = try {
        if (body.isBlank()) null else JSONObject(body)
      } catch (err: Exception) {
        null
      }

      val track = parsed?.optJSONObject("track")
      if (status in 200..299 && track != null) {
        return JSONObject()
          .put("ok", true)
          .put("status", status)
          .put("track", track)
      }

      return JSONObject()
        .put("ok", false)
        .put("status", status)
        .put(
          "error",
          parsed?.optString("error").orEmpty().ifBlank {
            "No se pudo subir el archivo ($status)."
          }
        )
    } finally {
      try {
        connection.disconnect()
      } catch (err: Exception) {
        // noop
      }
    }
  }

  /* ------------------------------------------------------------
     Utilidades
     ------------------------------------------------------------ */

  private fun mimeFor(name: String): String {
    return when (name.substringAfterLast('.', "").lowercase()) {
      "mp3" -> "audio/mpeg"
      "wav" -> "audio/wav"
      "ogg", "oga", "opus" -> "audio/ogg"
      "m4a", "mp4" -> "audio/mp4"
      "aac" -> "audio/aac"
      "flac" -> "audio/flac"
      "webm" -> "audio/webm"
      else -> "application/octet-stream"
    }
  }

  private fun sanitizeFileName(value: String): String {
    val cleaned = value
      .replace("\"", "")
      .replace("\\", "-")
      .replace("\r", " ")
      .replace("\n", " ")
      .trim()
      .take(120)
    return cleaned.ifBlank { "audio" }
  }

  private fun escapeField(value: String): String =
    value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", " ").replace("\n", " ")

  private fun friendlyMessage(err: Exception): String {
    val message = err.message?.trim().orEmpty()
    return when {
      message.isBlank() -> "No se pudo completar la operación."
      message.length > 220 -> message.take(217) + "..."
      else -> message
    }
  }

  private fun errorPayload(message: String): JSONObject =
    JSONObject().put("ok", false).put("error", message)

  private fun emitFolder(payload: JSONObject) {
    emit("onNativeFolderPicked", payload.toString())
  }

  private fun emitScan(payload: JSONObject) {
    emit("onNativeScan", payload.toString())
  }

  private fun emit(functionName: String, payload: String) {
    val view = webView ?: return
    val literal = JSONObject.quote(payload)
    view.post {
      try {
        view.evaluateJavascript(
          "window.WaverNoteWatched && window.WaverNoteWatched.$functionName($literal);",
          null
        )
      } catch (err: Exception) {
        // la WebView pudo haberse destruido
      }
    }
  }
}
