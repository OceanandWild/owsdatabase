//! Carpeta vigilada en Windows.
//!
//! La app no descarga música: este módulo solo enumera los archivos de audio
//! de una carpeta elegida y entrega sus bytes al frontend para subirlos cuando
//! completan una canción pendiente. El frontend decide las coincidencias; acá
//! solo se evita leer rutas que no salieron de un escaneo previo.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

const AUDIO_EXTENSIONS: &[&str] = &[
    "mp3", "wav", "ogg", "oga", "m4a", "mp4", "aac", "flac", "opus", "webm",
];

const MAX_FILES_DEFAULT: usize = 20_000;
const MAX_DEPTH_DEFAULT: u32 = 12;
const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Rutas habilitadas por el último escaneo. Sin esta lista, un script en la
/// WebView podría pedir cualquier archivo del equipo.
#[derive(Default)]
pub struct WatchedFolderState(pub Mutex<HashSet<PathBuf>>);

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannedFile {
    path: String,
    name: String,
    relative: String,
    size: u64,
    modified: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    root: String,
    files: Vec<ScannedFile>,
    truncated: bool,
    depth_limited: bool,
}

fn is_hidden_name(name: &str) -> bool {
    name.starts_with('.')
}

fn is_system_dir(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "$recycle.bin"
            | "system volume information"
            | "recycler"
            | "lost+found"
            | "node_modules"
            | "__pycache__"
    )
}

#[cfg(windows)]
fn is_hidden_path(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    std::fs::metadata(path)
        .map(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_hidden_path(_path: &Path) -> bool {
    false
}

fn is_audio_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| {
            let lower = value.to_ascii_lowercase();
            AUDIO_EXTENSIONS.iter().any(|extension| *extension == lower)
        })
        .unwrap_or(false)
}

fn relative_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn modified_ms(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

struct WalkOptions {
    root: PathBuf,
    max_depth: u32,
    max_files: usize,
    files: Vec<ScannedFile>,
    allowed: HashSet<PathBuf>,
    truncated: bool,
    depth_limited: bool,
}

fn walk_dir(dir: &Path, depth: u32, options: &mut WalkOptions) {
    if options.truncated {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(|entry| entry.file_name().to_string_lossy().to_ascii_lowercase());

    for entry in entries {
        if options.truncated {
            break;
        }

        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(value) => value,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_dir() {
            if is_hidden_name(&name) || is_system_dir(&name) || is_hidden_path(&path) {
                continue;
            }
            if depth >= options.max_depth {
                options.depth_limited = true;
                continue;
            }
            walk_dir(&path, depth + 1, options);
            continue;
        }

        if !file_type.is_file() || is_hidden_name(&name) || !is_audio_file(&path) {
            continue;
        }

        let size = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        if size == 0 {
            continue;
        }

        options.files.push(ScannedFile {
            path: path.to_string_lossy().to_string(),
            name,
            relative: relative_string(&options.root, &path),
            size,
            modified: modified_ms(&path),
        });
        options.allowed.insert(path);

        if options.files.len() >= options.max_files {
            options.truncated = true;
            break;
        }
    }
}

#[tauri::command]
pub fn watched_scan_folder(
    state: tauri::State<'_, WatchedFolderState>,
    root: String,
    max_files: Option<usize>,
    max_depth: Option<u32>,
) -> Result<ScanResult, String> {
    let root_path = PathBuf::from(root.trim());
    if !root_path.is_dir() {
        return Err(
            "La carpeta elegida ya no existe o no se puede leer. Volvé a elegirla.".to_string(),
        );
    }
    if std::fs::read_dir(&root_path).is_err() {
        return Err(
            "No se pudo leer la carpeta elegida. Revisá los permisos o elegí otra carpeta."
                .to_string(),
        );
    }

    let max_files = max_files
        .unwrap_or(MAX_FILES_DEFAULT)
        .clamp(1, MAX_FILES_DEFAULT);
    let max_depth = max_depth.unwrap_or(MAX_DEPTH_DEFAULT).clamp(1, 32);

    let mut options = WalkOptions {
        root: root_path.clone(),
        max_depth,
        max_files,
        files: Vec::new(),
        allowed: HashSet::new(),
        truncated: false,
        depth_limited: false,
    };

    walk_dir(&root_path, 0, &mut options);

    let allowed = std::mem::take(&mut options.allowed);
    let mut guard = state
        .0
        .lock()
        .map_err(|_| "No se pudo preparar la carpeta vigilada.".to_string())?;
    guard.clear();
    guard.extend(allowed);

    Ok(ScanResult {
        root: root_path.to_string_lossy().to_string(),
        files: options.files,
        truncated: options.truncated,
        depth_limited: options.depth_limited,
    })
}

#[tauri::command]
pub fn watched_read_chunk(
    state: tauri::State<'_, WatchedFolderState>,
    path: String,
    offset: u64,
    length: usize,
) -> Result<tauri::ipc::Response, String> {
    let path_buf = PathBuf::from(&path);
    let allowed = state
        .0
        .lock()
        .map_err(|_| "No se pudo leer la carpeta vigilada.".to_string())?;
    if !allowed.contains(&path_buf) {
        return Err("Ese archivo no salió de la carpeta vigilada.".to_string());
    }
    drop(allowed);

    if !is_audio_file(&path_buf) {
        return Err("El archivo no es un formato de audio compatible.".to_string());
    }

    let mut file =
        File::open(&path_buf).map_err(|err| format!("No se pudo abrir el archivo: {err}"))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| format!("No se pudo leer el archivo: {err}"))?;

    let wanted = length.min(MAX_CHUNK_BYTES);
    let mut buffer = vec![0u8; wanted];
    let mut read = 0usize;
    while read < wanted {
        match file.read(&mut buffer[read..]) {
            Ok(0) => break,
            Ok(bytes) => read += bytes,
            Err(err) => return Err(format!("No se pudo leer el archivo: {err}")),
        }
    }
    buffer.truncate(read);

    Ok(tauri::ipc::Response::new(buffer))
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn watched_pick_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::{DialogExt, FilePath};

    let (sender, receiver) = std::sync::mpsc::channel::<Option<FilePath>>();
    app.dialog()
        .file()
        .set_title("Elegí tu carpeta de música")
        .pick_folder(move |folder| {
            let _ = sender.send(folder);
        });

    let folder = receiver
        .recv_timeout(std::time::Duration::from_secs(300))
        .map_err(|_| "El selector de carpetas no respondió.".to_string())?;

    match folder {
        Some(path) => path
            .into_path()
            .map(|value| Some(value.to_string_lossy().to_string()))
            .map_err(|err| format!("No se pudo leer la carpeta elegida: {err}")),
        None => Ok(None),
    }
}

#[cfg(target_os = "android")]
#[tauri::command]
pub fn watched_pick_folder() -> Result<Option<String>, String> {
    Err("En Android la carpeta se elige desde el selector del sistema.".to_string())
}
