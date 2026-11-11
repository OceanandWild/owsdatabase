//! WaverNote — backend Tauri v2.
//!
//! La app es HTML/CSS/JS sin bundler y habla directo con la API de OWS
//! (PostgreSQL + Cloudinary) usando la sesión de Surface. Este backend solo
//! expone un comando de diagnóstico y deja el ciclo de vida en manos de Tauri,
//! que es lo que necesitan Windows y Android.

#[tauri::command]
fn app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "WaverNote",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_info])
        .run(tauri::generate_context!())
        .expect("error while running WaverNote");
}
