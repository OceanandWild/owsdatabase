//! WaverNote — backend Tauri v2.
//!
//! La app es HTML/CSS/JS sin bundler y habla directo con la API de OWS
//! (PostgreSQL + Cloudinary) usando la sesión de Surface. Este backend expone
//! el diagnóstico de la app y el canal de actualizaciones:
//!
//! - Windows: `tauri-plugin-updater` (manifiesto `wavernote-update.json`).
//! - Android: descarga del APK firmado + instalador del sistema, porque el
//!   plugin updater de Tauri no soporta móviles.

use tauri::Manager;

#[tauri::command]
fn app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "WaverNote",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
    })
}

/// Progreso de la descarga del APK. Usa la misma forma que los eventos del
/// plugin updater (`{ event, data }`) para que el frontend tenga un solo lector.
#[derive(Clone, serde::Serialize)]
#[serde(tag = "event", content = "data")]
enum ApkDownloadEvent {
    #[serde(rename = "Started")]
    Started {
        #[serde(rename = "contentLength")]
        content_length: Option<u64>,
    },
    #[serde(rename = "Progress")]
    Progress {
        #[serde(rename = "chunkLength")]
        chunk_length: usize,
    },
    #[serde(rename = "Finished")]
    Finished,
}

/// Deja el nombre del APK en algo seguro para el sistema de archivos.
fn safe_apk_name(file_name: Option<String>) -> String {
    let cleaned: String = String::from(file_name.unwrap_or_default())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let mut name = cleaned.trim_matches('.').to_string();
    if name.is_empty() {
        name = "wavernote-update.apk".to_string();
    }
    if !name.to_ascii_lowercase().ends_with(".apk") {
        name.push_str(".apk");
    }
    name
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Descarga el APK de una actualización a la caché de la app y devuelve la ruta
/// lista para que el instalador de Android la abra.
#[tauri::command]
async fn apk_download(
    app: tauri::AppHandle,
    url: String,
    sha256: Option<String>,
    file_name: Option<String>,
    on_event: tauri::ipc::Channel<ApkDownloadEvent>,
) -> Result<String, String> {
    if !url.to_ascii_lowercase().starts_with("https://") {
        return Err("La actualización tiene que descargarse por HTTPS.".to_string());
    }

    // Sin hash no hay forma de comprobar que el APK llegó completo y sin
    // cambios, así que no se descarga nada.
    let expected = sha256
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| {
            "La actualización no incluye un SHA-256 válido. No se descargará.".to_string()
        })?;

    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|err| format!("No se pudo preparar la carpeta de descargas: {err}"))?
        .join("updates");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|err| format!("No se pudo preparar la carpeta de descargas: {err}"))?;

    let dest = dir.join(safe_apk_name(file_name));
    let _ = tokio::fs::remove_file(&dest).await;

    // En Android, reqwest con rustls usaría rustls-platform-verifier, que
    // necesita inicialización JNI y un componente Kotlin extra. Para no
    // depender de eso, se configura rustls con las raíces de webpki, que ya
    // vienen compiladas en la app y funcionan igual en todas las plataformas.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("No se pudo preparar la conexión segura: {err}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let client = reqwest::Client::builder()
        .user_agent(concat!("WaverNote/", env!("CARGO_PKG_VERSION")))
        .tls_backend_preconfigured(tls)
        .build()
        .map_err(|err| format!("No se pudo iniciar la descarga: {err}"))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|err| format!("No se pudo conectar con el servidor: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("El servidor respondió {}.", response.status()));
    }

    let content_length = response.content_length();

    use futures_util::StreamExt;
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::File::create(&dest)
        .await
        .map_err(|err| format!("No se pudo crear el archivo del APK: {err}"))?;
    let mut stream = response.bytes_stream();
    let mut hasher = sha2::Sha256::new();
    let mut received: u64 = 0;
    let mut started = false;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| format!("La descarga se cortó: {err}"))?;
        if !started {
            started = true;
            let _ = on_event.send(ApkDownloadEvent::Started { content_length });
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|err| format!("No se pudo escribir el APK: {err}"))?;
        received += chunk.len() as u64;
        let _ = on_event.send(ApkDownloadEvent::Progress {
            chunk_length: chunk.len(),
        });
    }

    file.flush()
        .await
        .map_err(|err| format!("No se pudo guardar el APK: {err}"))?;
    drop(file);

    if received == 0 {
        let _ = tokio::fs::remove_file(&dest).await;
        return Err("La descarga llegó vacía.".to_string());
    }

    let digest = hasher.finalize();
    let actual = sha256_hex(digest.as_slice());
    if actual != expected {
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(
            "El APK descargado no coincide con la firma esperada. No se instalará.".to_string(),
        );
    }

    let _ = on_event.send(ApkDownloadEvent::Finished);
    Ok(dest.to_string_lossy().to_string())
}

/// Abre el instalador de Android para el APK ya descargado.
#[cfg(target_os = "android")]
struct MobileUpdaterHandle(tauri::plugin::PluginHandle<tauri::Wry>);

#[cfg(target_os = "android")]
#[tauri::command]
async fn apk_install(app: tauri::AppHandle, path: String) -> Result<(), String> {
    let state = app.state::<MobileUpdaterHandle>();
    state
        .0
        .run_mobile_plugin_async::<()>("installApk", serde_json::json!({ "path": path }))
        .await
        .map_err(|err| format!("No se pudo abrir el instalador de Android: {err}"))
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn apk_install(_path: String) -> Result<(), String> {
    Err("La instalación de APK solo está disponible en Android.".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(
            tauri::plugin::Builder::<tauri::Wry>::new("wavernote-mobile")
                .setup(|app, api| {
                    #[cfg(target_os = "android")]
                    {
                        let handle = api
                            .register_android_plugin(
                                "com.oceanwildstudios.wavernote",
                                "UpdaterPlugin",
                            )
                            .map_err(|err| err.to_string())?;
                        app.manage(MobileUpdaterHandle(handle));
                    }
                    #[cfg(not(target_os = "android"))]
                    {
                        let _ = (app, api);
                    }
                    Ok(())
                })
                .build(),
        )
        .invoke_handler(tauri::generate_handler![
            app_info,
            apk_download,
            apk_install
        ]);

    #[cfg(not(target_os = "android"))]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());

    builder
        .run(tauri::generate_context!())
        .expect("error while running WaverNote");
}
