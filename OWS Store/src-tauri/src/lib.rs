use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::UpdaterExt;
use serde::Serialize;

// ─── State ─────────────────────────────────────────────────────────

struct DownloadTask {
    cancelled: Arc<AtomicBool>,
}

struct AppState {
    download_tasks: Mutex<HashMap<String, DownloadTask>>,
}

// ─── Response Types ────────────────────────────────────────────────

#[derive(Serialize)]
struct CmdResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Serialize)]
struct VersionResult {
    version: String,
}

#[derive(Serialize)]
struct WnsResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Serialize)]
struct InstallResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cached: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct AppResult {
    installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uninstall_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    install_dir: Option<String>,
}

#[derive(Serialize)]
struct BatchItem {
    slug: String,
    installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uninstall_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    install_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct PackageJsonResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct UpdateCheckResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_update: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

// ─── Helpers ───────────────────────────────────────────────────────

fn compare_version_like(a: &str, b: &str) -> i32 {
    fn parse_part(s: &str) -> [i32; 5] {
        let s = s.trim().to_lowercase();
        let mut major = 0i32; let mut minor = 0i32; let mut patch = 0i32;
        let mut has_tag = 0i32; let mut tag_num = 0i32;
        let mut chars = s.chars().peekable();
        // parse major
        let mut num_str = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() { num_str.push(c); chars.next(); } else { break; }
        }
        if !num_str.is_empty() { major = num_str.parse().unwrap_or(0); num_str.clear(); }
        if chars.peek() == Some(&'.') { chars.next(); }
        // parse minor
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() { num_str.push(c); chars.next(); } else { break; }
        }
        if !num_str.is_empty() { minor = num_str.parse().unwrap_or(0); num_str.clear(); }
        if chars.peek() == Some(&'.') { chars.next(); }
        // parse patch
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() { num_str.push(c); chars.next(); } else { break; }
        }
        if !num_str.is_empty() { patch = num_str.parse().unwrap_or(0); num_str.clear(); }
        // tag separator
        if matches!(chars.peek(), Some(&'.') | Some(&'_') | Some(&'-')) { chars.next(); }
        // check for 't' tag
        if chars.peek() == Some(&'t') { has_tag = 1; chars.next(); }
        // parse tag number
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() { num_str.push(c); chars.next(); } else { break; }
        }
        if !num_str.is_empty() { tag_num = num_str.parse().unwrap_or(0); }
        [major, minor, patch, has_tag, tag_num]
    }
    let a_p = parse_part(a);
    let b_p = parse_part(b);
    for i in 0..5 {
        if a_p[i] != b_p[i] { return a_p[i] - b_p[i]; }
    }
    0
}

fn collect_install_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(d) = std::env::var("LOCALAPPDATA") { roots.push(PathBuf::from(d).join("Programs")); }
    if let Ok(d) = std::env::var("ProgramFiles") { roots.push(PathBuf::from(d)); }
    if let Ok(d) = std::env::var("ProgramFiles(x86)") { roots.push(PathBuf::from(d)); }
    roots
}

fn is_mz_header(path: &str) -> bool {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut buf = [0u8; 2];
        if f.read_exact(&mut buf).is_ok() {
            return buf[0] == 0x4d && buf[1] == 0x5a;
        }
    }
    false
}

fn format_iso_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let secs_in_day = 86400;
    let mut days = d / secs_in_day;
    let time_secs = d % secs_in_day;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;
    let mut y = 1970i64;
    loop {
        let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 366 } else { 365 };
        if days >= leap { days -= leap; y += 1; } else { break; }
    }
    let months_days = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
        [31,29,31,30,31,30,31,31,30,31,30,31]
    } else { [31,28,31,30,31,30,31,31,30,31,30,31] };
    let mut mo = 1;
    for &md in months_days.iter() {
        if days >= md { days -= md; mo += 1; } else { break; }
    }
    let day = days + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, day, h, m, s)
}

// ─── Commands ─────────────────────────────────────────────────────

#[tauri::command]
fn get_app_version() -> VersionResult {
    VersionResult { version: env!("CARGO_PKG_VERSION").to_string() }
}

#[tauri::command]
async fn quit_app(app: AppHandle) {
    app.exit(0);
}

#[tauri::command]
async fn open_external_url(url: String, app: AppHandle) -> bool {
    if !url.starts_with("http://") && !url.starts_with("https://") { return false; }
    app.opener().open_url(&url, None::<&str>).is_ok()
}

#[tauri::command]
async fn show_system_notification(payload: Option<serde_json::Value>) -> CmdResult {
    let title = payload.as_ref().and_then(|p| p.get("title")).and_then(|v| v.as_str()).unwrap_or("OWS Store");
    let body = payload.as_ref().and_then(|p| p.get("body")).and_then(|v| v.as_str()).unwrap_or("");
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]>$null;$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);$n=$t.GetElementsByTagName('text');$n.Item(0).AppendChild($t.CreateTextNode('{0}'))>$null;$n.Item(1).AppendChild($t.CreateTextNode('{1}'))>$null;[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('OWS Store').Show([Windows.UI.Notifications.ToastNotification]::new($t))",
            title.replace('\'', "''"),
            body.replace('\'', "''")
        );
        let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &script]).spawn();
    }
    CmdResult { ok: true, reason: None, message: None }
}

#[tauri::command]
async fn resolve_installed_app(payload: Option<serde_json::Value>) -> AppResult {
    let p = match payload {
        Some(v) => v,
        None => return AppResult { installed: false, exe_path: None, uninstall_path: None, install_dir: None },
    };
    let dir_names: Vec<String> = p.get("installDirNames")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let exe_names: Vec<String> = p.get("executableNames")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let un_names: Vec<String> = p.get("uninstallerNames")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if dir_names.is_empty() { return AppResult { installed: false, exe_path: None, uninstall_path: None, install_dir: None }; }

    let mut exe_path: Option<String> = None;
    let mut uninstall_path: Option<String> = None;
    let mut install_dir: Option<String> = None;

    for root in &collect_install_roots() {
        for dn in &dir_names {
            let dir = root.join(dn);
            if !dir.exists() { continue; }
            if install_dir.is_none() { install_dir = Some(dir.to_string_lossy().to_string()); }
            for en in &exe_names {
                let c = dir.join(en);
                if c.exists() && exe_path.is_none() { exe_path = Some(c.to_string_lossy().to_string()); }
            }
            for un in &un_names {
                let c = dir.join(un);
                if c.exists() && uninstall_path.is_none() { uninstall_path = Some(c.to_string_lossy().to_string()); }
            }
        }
    }

    AppResult { installed: exe_path.is_some(), exe_path, uninstall_path, install_dir }
}

#[tauri::command]
async fn resolve_installed_apps_batch(projects: Vec<serde_json::Value>) -> Vec<BatchItem> {
    let mut results: Vec<BatchItem> = Vec::new();
    for p in &projects {
        let slug = p.get("slug").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let hints = p.get("hints").cloned();
        let app = resolve_installed_app(hints).await;
        results.push(BatchItem {
            slug, installed: app.installed,
            exe_path: app.exe_path.clone(),
            uninstall_path: app.uninstall_path,
            install_dir: app.install_dir,
            version: None, error: None,
        });
    }

    // Batch version extraction via PowerShell Get-Item
    let paths: Vec<&str> = results.iter().filter_map(|r| r.exe_path.as_deref()).collect();
    if !paths.is_empty() {
        let escaped: Vec<String> = paths.iter().map(|p| p.replace('\'', "''")).collect();
        let arr = format!("@('{}')", escaped.join("','"));
        let cmd = format!("powershell -NoProfile -Command \"Get-Item {} -ErrorAction SilentlyContinue | ForEach-Object {{ [PSCustomObject]@{{ Path=$_.FullName; Version=$_.VersionInfo.FileVersion }} }} | ConvertTo-Json -Compress\"", arr);
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd]).output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                let mut version_map: HashMap<String, String> = HashMap::new();
                for item in parsed {
                    if let (Some(path), Some(ver)) = (
                        item.get("Path").and_then(|v| v.as_str()),
                        item.get("Version").and_then(|v| v.as_str())
                    ) {
                        version_map.insert(path.to_lowercase(), ver.to_string());
                    }
                }
                for r in &mut results {
                    if let Some(ref exe) = r.exe_path {
                        if let Some(ver) = version_map.get(&exe.to_lowercase()) {
                            r.version = Some(ver.clone());
                        }
                    }
                }
            }
        }
    }

    results
}

#[tauri::command]
async fn launch_installed_app(payload: Option<serde_json::Value>) -> CmdResult {
    let exe = payload.as_ref().and_then(|p| p.get("exePath")).and_then(|v| v.as_str()).unwrap_or("");
    if exe.is_empty() || !PathBuf::from(exe).exists() {
        return CmdResult { ok: false, reason: Some("Ejecutable no encontrado.".into()), message: None };
    }
    match std::process::Command::new(exe).spawn() {
        Ok(_) => CmdResult { ok: true, reason: None, message: None },
        Err(e) => CmdResult { ok: false, reason: Some(e.to_string()), message: None },
    }
}

#[tauri::command]
async fn uninstall_installed_app(payload: Option<serde_json::Value>) -> CmdResult {
    let un = payload.as_ref().and_then(|p| p.get("uninstallPath")).and_then(|v| v.as_str()).unwrap_or("");
    if un.is_empty() || !PathBuf::from(un).exists() {
        return CmdResult { ok: false, reason: Some("Desinstalador no encontrado.".into()), message: None };
    }
    match std::process::Command::new(un)
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => CmdResult { ok: true, reason: None, message: None },
        Err(e) => CmdResult { ok: false, reason: Some(e.to_string()), message: None },
    }
}

#[tauri::command]
async fn install_external_installer(
    payload: Option<serde_json::Value>,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<InstallResult, String> {
    let p = match payload {
        Some(v) => v,
        None => return Ok(InstallResult { ok: false, file_path: None, task_id: None, cached: None, error: Some("No payload".into()) }),
    };
    let url = p.get("url").and_then(|v| v.as_str()).unwrap_or("");
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Ok(InstallResult { ok: false, file_path: None, task_id: None, cached: None, error: Some("URL de instalador invalida.".into()) });
    }

    let task_id = p.get("taskId").and_then(|v| v.as_str()).unwrap_or("installer").to_string();
    let installer_name = p.get("name").and_then(|v| v.as_str()).unwrap_or("installer.exe");
    let is_apk = p.get("isApk").and_then(|v| v.as_bool()).unwrap_or(false);

    // Check existing task
    if state.download_tasks.lock().unwrap().contains_key(&task_id) {
        return Ok(InstallResult { ok: false, file_path: None, task_id: Some(task_id), cached: None, error: Some("Ya existe una instalacion en curso para este proyecto.".into()) });
    }

    let cancelled_flag = Arc::new(AtomicBool::new(false));
    state.download_tasks.lock().unwrap().insert(task_id.clone(), DownloadTask { cancelled: cancelled_flag.clone() });

    let temp_dir = std::env::temp_dir().join("ows-store-installers");
    let _ = std::fs::create_dir_all(&temp_dir);
    let target_path = temp_dir.join(installer_name);

    // Cache check
    let expected_size = p.get("expectedSize").and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
    let use_cached = target_path.exists() && if expected_size > 0 {
        std::fs::metadata(&target_path).map(|m| m.len() == expected_size).unwrap_or(false)
    } else { true };

    if use_cached {
        let _ = app.emit("external-install-status", serde_json::json!({
            "taskId": task_id, "phase": "launching", "message": "Instalador en cache encontrado. Abriendo...",
        }));
        match std::process::Command::new(&target_path).spawn() {
            Ok(_) => {
                let _ = app.emit("external-install-status", serde_json::json!({
                    "taskId": task_id, "phase": "done", "message": "Instalador abierto desde cache.",
                }));
                state.download_tasks.lock().unwrap().remove(&task_id);
                return Ok(InstallResult { ok: true, file_path: Some(target_path.to_string_lossy().to_string()), task_id: Some(task_id), cached: Some(true), error: None });
            }
            Err(_) => { let _ = std::fs::remove_file(&target_path); }
        }
    }

    // Download
    let _ = app.emit("external-install-status", serde_json::json!({
        "taskId": task_id, "phase": "downloading", "message": "Descargando instalador...", "percent": 0,
    }));

    let client = reqwest::Client::builder()
        .user_agent("OWS-Store-Client")
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client.get(url).send().await.map_err(|e| {
        let _ = app.emit("external-install-status", serde_json::json!({
            "taskId": &task_id, "phase": "error", "message": format!("Error de conexion: {}", e),
        }));
        format!("Error de conexion: {}", e)
    })?;

    let total = response.content_length().unwrap_or(0);
    let mut file = std::fs::File::create(&target_path).map_err(|e| e.to_string())?;

    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;
    let mut last_emit: u64 = 0;
    let mut chunks_since_emit: u64 = 0;

    while let Some(item) = stream.next().await {
        if cancelled_flag.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&target_path);
            state.download_tasks.lock().unwrap().remove(&task_id);
            return Ok(InstallResult { ok: false, file_path: None, task_id: Some(task_id), cached: None, error: Some("Instalacion cancelada por el usuario.".into()) });
        }
        use std::io::Write;
        let chunk = item.map_err(|e| {
            let _ = app.emit("external-install-status", serde_json::json!({
                "taskId": &task_id, "phase": "error", "message": format!("Error de descarga: {}", e),
            }));
            format!("Error de descarga: {}", e)
        })?;
        file.write_all(&chunk).map_err(|e| e.to_string())?;
        downloaded += chunk.len() as u64;
        chunks_since_emit += chunk.len() as u64;
        // Emit progress every 512KB OR when we have no content_length (emit every 2MB)
        let should_emit = if total > 0 {
            downloaded - last_emit > 524288
        } else {
            chunks_since_emit > 2_097_152
        };
        if should_emit {
            last_emit = downloaded;
            chunks_since_emit = 0;
            let (percent, msg) = if total > 0 {
                let p = ((downloaded as f64 / total as f64) * 100.0) as u32;
                (p, format!("Descargando... {}%", p))
            } else {
                let mb = downloaded as f64 / 1_048_576.0;
                (0, format!("Descargando... {:.1} MB", mb))
            };
            let _ = app.emit("external-install-status", serde_json::json!({
                "taskId": task_id, "phase": "downloading", "message": msg,
                "percent": percent, "downloadedBytes": downloaded, "totalBytes": total,
            }));
        }
    }
    // Final progress emit
    if downloaded > 0 {
        let (percent, msg) = if total > 0 {
            let p = ((downloaded as f64 / total as f64) * 100.0) as u32;
            (p, format!("Descargado {}%", p))
        } else {
            let mb = downloaded as f64 / 1_048_576.0;
            (100, format!("Descargado {:.1} MB", mb))
        };
        let _ = app.emit("external-install-status", serde_json::json!({
            "taskId": task_id, "phase": "downloading", "message": msg,
            "percent": percent, "downloadedBytes": downloaded, "totalBytes": total,
        }));
    }

    // Validate
    if !is_apk && !is_mz_header(&target_path.to_string_lossy()) {
        let _ = std::fs::remove_file(&target_path);
        state.download_tasks.lock().unwrap().remove(&task_id);
        return Ok(InstallResult { ok: false, file_path: None, task_id: Some(task_id), cached: None, error: Some("El archivo descargado no es un instalador Windows valido.".into()) });
    }

    // Launch
    let _ = app.emit("external-install-status", serde_json::json!({
        "taskId": task_id, "phase": "launching", "message": "Abriendo instalador...",
    }));

    let launch_result: Result<(), String> = if is_apk {
        app.opener().open_url(&format!("file://{}", target_path.to_string_lossy()), None::<&str>)
            .map_err(|e| e.to_string())
    } else {
        std::process::Command::new(&target_path).spawn()
            .map_err(|e| e.to_string()).map(|_| ())
    };

    match launch_result {
        Ok(_) => {
            let _ = app.emit("external-install-status", serde_json::json!({
                "taskId": task_id, "phase": "done", "message": "Instalador abierto.",
            }));
            state.download_tasks.lock().unwrap().remove(&task_id);

            // Self-update: close the app so the NSIS installer can replace files
            if task_id == "ows-store" {
                let app_clone = app.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    app_clone.exit(0);
                });
            }

            Ok(InstallResult { ok: true, file_path: Some(target_path.to_string_lossy().to_string()), task_id: Some(task_id), cached: Some(false), error: None })
        }
        Err(e) => {
            state.download_tasks.lock().unwrap().remove(&task_id);
            Ok(InstallResult { ok: false, file_path: None, task_id: Some(task_id), cached: None, error: Some(format!("Error al abrir instalador: {}", e)) })
        }
    }
}

#[tauri::command]
async fn cancel_external_installer(
    payload: Option<serde_json::Value>,
    state: tauri::State<'_, AppState>,
) -> Result<CmdResult, String> {
    let task_id = payload.as_ref().and_then(|p| p.get("taskId")).and_then(|v| v.as_str()).unwrap_or("");
    let mut tasks = state.download_tasks.lock().unwrap();
    if let Some(task) = tasks.get(task_id) {
        task.cancelled.store(true, Ordering::SeqCst);
        tasks.remove(task_id);
        Ok(CmdResult { ok: true, reason: None, message: None })
    } else {
        Ok(CmdResult { ok: false, reason: Some("No hay descarga activa para cancelar.".into()), message: None })
    }
}

#[tauri::command]
async fn read_project_package_json(path: String) -> PackageJsonResult {
    match std::fs::read_to_string(&path) {
        Ok(c) => match serde_json::from_str::<serde_json::Value>(&c) {
            Ok(d) => PackageJsonResult { ok: true, data: Some(d), error: None },
            Err(e) => PackageJsonResult { ok: false, data: None, error: Some(format!("JSON invalido: {}", e)) },
        },
        Err(e) => PackageJsonResult { ok: false, data: None, error: Some(format!("Error al leer archivo: {}", e)) },
    }
}

#[tauri::command]
async fn check_for_updates(app: AppHandle) -> UpdateCheckResult {
    let current = env!("CARGO_PKG_VERSION");
    let latest_yml_url = "https://github.com/OceanandWild/owsdatabase/releases/latest/download/latest.yml";
    let client = reqwest::Client::builder()
        .user_agent("OWS-Store-Client")
        .build()
        .unwrap_or_default();

    let remote_version = match client.get(latest_yml_url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                body.lines().find_map(|line| {
                    let t = line.trim();
                    t.strip_prefix("version: ").map(|v| v.trim().to_string())
                })
            } else { None }
        }
        Err(_) => None,
    };

    if let Some(ref rv) = remote_version {
        if compare_version_like(rv, current) > 0 {
            let _ = app.emit("update-available", serde_json::json!({
                "version": rv, "releaseDate": format_iso_now(),
            }));
            return UpdateCheckResult { ok: true, has_update: Some(true), version: Some(rv.clone()), reason: None, message: None };
        } else {
            let _ = app.emit("update-not-available", serde_json::Value::Null);
            return UpdateCheckResult { ok: true, has_update: Some(false), version: None, reason: None, message: None };
        }
    }

    let _ = app.emit("update-error", "No se pudo verificar actualizaciones.");
    UpdateCheckResult { ok: false, reason: Some("check-failed".into()), message: Some("No se pudo conectar con el servidor de actualizaciones.".into()), has_update: None, version: None }
}

#[tauri::command]
async fn install_update(app: AppHandle) -> CmdResult {
    // Try updater plugin first
    if let Ok(updater) = app.updater() {
        match updater.check().await {
            Ok(Some(update)) => {
                let app_clone = app.clone();
                let result = update.download_and_install(
                    |chunk_length, content_length| {
                        let _ = app_clone.emit("update-download-progress", serde_json::json!({
                            "chunkLength": chunk_length, "contentLength": content_length,
                        }));
                    },
                    || {
                        let _ = app_clone.emit("update-downloaded", serde_json::Value::Null);
                    },
                ).await;

                match result {
                    Ok(_) => {
                        return CmdResult { ok: true, reason: None, message: Some("closing".to_string()) };
                    }
                    Err(e) => {
                        let _ = app.emit("update-error", format!("Auto-update fallo: {}", e));
                    }
                }
            }
            Ok(None) => {
                // No update from updater plugin, try manual fallback
            }
            Err(e) => {
                let _ = app.emit("update-error", format!("Updater check fallo: {}", e));
            }
        }
    }

    // Manual fallback: download latest release from GitHub and launch installer
    let client = reqwest::Client::builder()
        .user_agent("OWS-Store-Updater")
        .build()
        .unwrap_or_default();

    let latest_yml_url = "https://github.com/OceanandWild/owsdatabase/releases/latest/download/latest.yml";
    let yml_body = match client.get(latest_yml_url).send().await {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(e) => {
            return CmdResult { ok: false, reason: Some("check-failed".into()), message: Some(format!("Error de red: {}", e)) };
        }
    };

    let version = yml_body.lines()
        .find_map(|l| l.trim().strip_prefix("version: ").map(|v| v.trim().to_string()));
    let installer_file = yml_body.lines()
        .find_map(|l| l.trim().strip_prefix("files: ").or(l.trim().strip_prefix("url: ")).map(|v| v.trim().to_string()));

    let inst_file = installer_file.unwrap_or_else(|| format!("OWS.Store.Setup.{}.exe", version.as_deref().unwrap_or("0.0.0")));

    // Construct download URL same pattern as GitHub release artifacts
    let download_url = format!(
        "https://github.com/OceanandWild/owsdatabase/releases/latest/download/{}",
        inst_file
    );

    let temp_dir = std::env::temp_dir().join("ows-store-update");
    let _ = std::fs::create_dir_all(&temp_dir);
    let target_path = temp_dir.join(&inst_file);

    let _ = app.emit("update-download-progress", serde_json::json!({
        "percent": 0, "downloadedBytes": 0, "totalBytes": 0,
    }));

    let response = match client.get(&download_url).send().await {
        Ok(r) => r,
        Err(e) => return CmdResult { ok: false, reason: Some("download-failed".into()), message: Some(format!("Error de descarga: {}", e)) },
    };

    let total = response.content_length().unwrap_or(0);
    let mut file = match std::fs::File::create(&target_path) {
        Ok(f) => f,
        Err(e) => return CmdResult { ok: false, reason: Some("file-error".into()), message: Some(e.to_string()) },
    };

    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;

    while let Some(item) = stream.next().await {
        use std::io::Write;
        let chunk = match item {
            Ok(c) => c,
            Err(e) => return CmdResult { ok: false, reason: Some("download-error".into()), message: Some(e.to_string()) },
        };
        if let Err(e) = file.write_all(&chunk) {
            return CmdResult { ok: false, reason: Some("write-error".into()), message: Some(e.to_string()) };
        }
        downloaded += chunk.len() as u64;
        if total > 0 {
            let percent = ((downloaded as f64 / total as f64) * 100.0) as u32;
            let _ = app.emit("update-download-progress", serde_json::json!({
                "percent": percent, "downloadedBytes": downloaded, "totalBytes": total,
                "bytesPerSecond": 0,
            }));
        }
    }

    let _ = app.emit("update-downloaded", serde_json::Value::Null);

    // Launch the installer
    match std::process::Command::new(&target_path).spawn() {
        Ok(_) => CmdResult { ok: true, reason: None, message: Some("closing".to_string()) },
        Err(e) => CmdResult { ok: false, reason: Some("launch-error".into()), message: Some(e.to_string()) },
    }
}

#[tauri::command]
async fn get_wns_channel_uri() -> WnsResult {
    #[cfg(target_os = "windows")]
    {
        let ps_script = r#"
try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
  $op = [Windows.Networking.PushNotifications.PushNotificationChannelManager, Windows.Networking.PushNotifications, ContentType=WindowsRuntime]::CreatePushNotificationChannelForApplicationAsync()
  $task = [System.WindowsRuntimeSystemExtensions]::AsTask($op)
  $null = $task.Wait(20000)
  if ($task.IsCompleted -and $task.Result -and $task.Result.Uri) {
    Write-Output $task.Result.Uri
    exit 0
  }
  exit 2
} catch {
  Write-Output $_.Exception.Message
  exit 1
}
"#;
        match std::process::Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if output.status.success() && !stdout.is_empty() {
                    return WnsResult { ok: true, uri: Some(stdout), reason: None, detail: None };
                }
                return WnsResult { ok: false, uri: None, reason: Some(format!("exit-{}", output.status.code().unwrap_or(-1))), detail: Some(stderr) };
            }
            Err(e) => return WnsResult { ok: false, uri: None, reason: Some(e.to_string()), detail: None },
        }
    }

    #[cfg(not(target_os = "windows"))]
    WnsResult { ok: false, uri: None, reason: Some("not-windows".into()), detail: None }
}

// ─── Entry Point ──────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .setup(|app| {
            #[cfg(desktop)]
            {
                use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
                use tauri::tray::TrayIconBuilder;

                let show = MenuItem::new(app, "Abrir OWS Store", true, None::<&str>)?;
                let separator = PredefinedMenuItem::separator(app)?;
                let quit = MenuItem::with_id(app, "quit", "Salir", true, None::<&str>)?;

                let menu = Menu::with_items(app, &[&show, &separator, &quit])?;

                let icon = app.default_window_icon().expect("default icon configured").clone();

                TrayIconBuilder::new()
                    .icon(icon)
                    .tooltip("OWS Store")
                    .menu(&menu)
                    .on_menu_event(|app, event| {
                        match event.id().as_ref() {
                            "quit" => { app.exit(0); }
                            _ => {
                                if let Some(window) = app.get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                            }
                        }
                    })
                    .build(app)?;
            }
            Ok(())
        })
        .manage(AppState { download_tasks: Mutex::new(HashMap::new()) })
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            quit_app,
            open_external_url,
            show_system_notification,
            resolve_installed_app,
            resolve_installed_apps_batch,
            launch_installed_app,
            uninstall_installed_app,
            install_external_installer,
            cancel_external_installer,
            read_project_package_json,
            check_for_updates,
            install_update,
            get_wns_channel_uri,
        ])
        .run(tauri::generate_context!())
        .expect("error while running OWS Store");
}
