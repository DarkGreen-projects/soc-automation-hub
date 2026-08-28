use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tauri_plugin_dialog::DialogExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedQuery {
    id: String,
    name: String,
    query: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDef {
    name: String,
    #[serde(rename = "type")]
    field_type: String,
    description: String,
    example: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetDef {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
    query: String,
    #[serde(default)]
    custom: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    theme: String,
    last_query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserData {
    saved_queries: Vec<SavedQuery>,
    custom_snippets: Vec<SnippetDef>,
    custom_fields: Vec<FieldDef>,
    preferences: Preferences,
}

impl Default for UserData {
    fn default() -> Self {
        Self {
            saved_queries: vec![],
            custom_snippets: vec![],
            custom_fields: vec![],
            preferences: Preferences {
                theme: "dark".to_string(),
                last_query: String::new(),
            },
        }
    }
}

fn portable_data_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe
        .parent()
        .ok_or_else(|| "Impossibile determinare la directory dell'eseguibile.".to_string())?
        .join("data");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn user_data_path() -> Result<PathBuf, String> {
    Ok(portable_data_dir()?.join("user-data.json"))
}

fn osint_keys_path() -> Result<PathBuf, String> {
    Ok(portable_data_dir()?.join("osint-keys.json"))
}

fn schema_catalog_path() -> Result<PathBuf, String> {
    Ok(portable_data_dir()?.join("schema-catalog.json"))
}

fn csv_vt_checkpoint_path() -> Result<PathBuf, String> {
    Ok(portable_data_dir()?.join("csv-vt-checkpoint.json"))
}

fn bulk_osint_checkpoint_path() -> Result<PathBuf, String> {
    Ok(portable_data_dir()?.join("bulk-osint-checkpoint.json"))
}

fn allowlist_path() -> Result<PathBuf, String> {
    Ok(portable_data_dir()?.join("allowlist.json"))
}

fn alert_coverage_path() -> Result<PathBuf, String> {
    Ok(portable_data_dir()?.join("alert-coverage.json"))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OsintKeys {
    /// Legacy single key (kept for older osint-keys.json files).
    #[serde(default)]
    pub vt_api_key: String,
    /// Multiple VirusTotal API keys (preferred). Merged with `vt_api_key` on read.
    #[serde(default)]
    pub vt_api_keys: Vec<String>,
    #[serde(default)]
    pub abuse_ipdb_api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsintKeysStatus {
    pub vt_configured: bool,
    pub vt_key_count: u32,
    pub abuse_configured: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsintKeysUpdate {
    /// Legacy: add or set a single key (appended if not already present).
    pub vt_api_key: Option<String>,
    /// Replace the full VT key list (empty strings ignored). Pass `[]` to clear.
    pub vt_api_keys: Option<Vec<String>>,
    pub abuse_ipdb_api_key: Option<String>,
}

fn dedupe_keys(keys: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out = Vec::new();
    for key in keys {
        let trimmed = key.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if !out.iter().any(|k| k == &trimmed) {
            out.push(trimmed);
        }
    }
    out
}

/// Merge legacy `vtApiKey` into `vtApiKeys` and keep `vtApiKey` as first key.
pub(crate) fn normalize_osint_keys(mut keys: OsintKeys) -> OsintKeys {
    let mut list = keys.vt_api_keys;
    if !keys.vt_api_key.trim().is_empty() {
        list.insert(0, keys.vt_api_key.trim().to_string());
    }
    keys.vt_api_keys = dedupe_keys(list);
    keys.vt_api_key = keys
        .vt_api_keys
        .first()
        .cloned()
        .unwrap_or_default();
    keys
}

fn osint_status(keys: &OsintKeys) -> OsintKeysStatus {
    let count = keys.vt_api_keys.len() as u32;
    OsintKeysStatus {
        vt_configured: count > 0,
        vt_key_count: count,
        abuse_configured: !keys.abuse_ipdb_api_key.trim().is_empty(),
    }
}

pub(crate) fn read_osint_keys() -> Result<OsintKeys, String> {
    let path = osint_keys_path()?;
    if !path.exists() {
        return Ok(OsintKeys::default());
    }
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let parsed: OsintKeys = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(normalize_osint_keys(parsed))
}

fn write_osint_keys(keys: &OsintKeys) -> Result<(), String> {
    let path = osint_keys_path()?;
    let normalized = normalize_osint_keys(keys.clone());
    let content = serde_json::to_string_pretty(&normalized).map_err(|e| e.to_string())?;
    fs::write(path, content).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_osint_keys() -> Result<OsintKeysStatus, String> {
    Ok(osint_status(&read_osint_keys()?))
}

#[tauri::command]
pub fn save_osint_keys(payload: OsintKeysUpdate) -> Result<OsintKeysStatus, String> {
    let mut keys = read_osint_keys()?;
    if let Some(list) = payload.vt_api_keys {
        keys.vt_api_keys = dedupe_keys(list);
        keys.vt_api_key = keys
            .vt_api_keys
            .first()
            .cloned()
            .unwrap_or_default();
    } else if let Some(value) = payload.vt_api_key {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            keys.vt_api_keys.push(trimmed);
            keys = normalize_osint_keys(keys);
        }
    }
    if let Some(value) = payload.abuse_ipdb_api_key {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            keys.abuse_ipdb_api_key = trimmed;
        }
    }
    write_osint_keys(&keys)?;
    Ok(osint_status(&keys))
}

fn read_user_data() -> Result<UserData, String> {
    let path = user_data_path()?;
    if !path.exists() {
        return Ok(UserData::default());
    }
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

fn write_user_data(data: &UserData) -> Result<(), String> {
    let path = user_data_path()?;
    let content = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(path, content).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_user_data() -> Result<UserData, String> {
    read_user_data()
}

#[tauri::command]
pub fn save_user_data(payload: UserData) -> Result<(), String> {
    write_user_data(&payload)
}

#[tauri::command]
pub fn get_data_dir() -> Result<String, String> {
    portable_data_dir().map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
pub fn load_schema_catalog() -> Result<String, String> {
    let path = schema_catalog_path()?;
    if !path.exists() {
        return Ok("{\"samples\":[]}".to_string());
    }
    fs::read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_schema_catalog(payload: String) -> Result<(), String> {
    let path = schema_catalog_path()?;
    fs::write(path, payload).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_schema_catalog(app: tauri::AppHandle, payload: String) -> Result<(), String> {
    let path = app
        .dialog()
        .file()
        .set_title("Esporta schemi anonimi")
        .add_filter("JSON", &["json"])
        .blocking_save_file();

    if let Some(file_path) = path {
        let path_buf = file_path.into_path().map_err(|e| e.to_string())?;
        fs::write(path_buf, payload).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportTextFilePayload {
    pub content: String,
    pub title: String,
    pub default_file_name: String,
}

/// Save arbitrary text via native "Save as" dialog. Returns true if written, false if cancelled.
#[tauri::command]
pub async fn export_text_file(
    app: tauri::AppHandle,
    payload: ExportTextFilePayload,
) -> Result<bool, String> {
    let mut builder = app
        .dialog()
        .file()
        .set_title(&payload.title)
        .add_filter("CSV", &["csv"])
        .add_filter("Tutti i file", &["*"]);
    if !payload.default_file_name.trim().is_empty() {
        builder = builder.set_file_name(&payload.default_file_name);
    }
    let path = builder.blocking_save_file();

    match path {
        Some(file_path) => {
            let path_buf = file_path.into_path().map_err(|e| e.to_string())?;
            fs::write(path_buf, payload.content).map_err(|e| e.to_string())?;
            Ok(true)
        }
        None => Ok(false),
    }
}

#[tauri::command]
pub async fn export_user_data(app: tauri::AppHandle, payload: String) -> Result<(), String> {
    let path = app
        .dialog()
        .file()
        .set_title("Esporta dati utente")
        .add_filter("JSON", &["json"])
        .blocking_save_file();

    if let Some(file_path) = path {
        let path_buf = file_path.into_path().map_err(|e| e.to_string())?;
        fs::write(path_buf, payload).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn import_user_data(app: tauri::AppHandle) -> Result<UserData, String> {
    let path = app
        .dialog()
        .file()
        .set_title("Importa dati utente")
        .add_filter("JSON", &["json"])
        .blocking_pick_file();

    match path {
        Some(file_path) => {
            let path_buf = file_path.into_path().map_err(|e| e.to_string())?;
            let content = fs::read_to_string(path_buf).map_err(|e| e.to_string())?;
            serde_json::from_str(&content).map_err(|e| e.to_string())
        }
        None => Err("Import annullato.".to_string()),
    }
}

#[tauri::command]
pub fn save_csv_vt_checkpoint(payload: String) -> Result<(), String> {
    let path = csv_vt_checkpoint_path()?;
    fs::write(path, payload).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_csv_vt_checkpoint() -> Result<Option<String>, String> {
    let path = csv_vt_checkpoint_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    if content.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(content))
}

#[tauri::command]
pub fn clear_csv_vt_checkpoint() -> Result<(), String> {
    let path = csv_vt_checkpoint_path()?;
    if path.exists() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn save_bulk_osint_checkpoint(payload: String) -> Result<(), String> {
    let path = bulk_osint_checkpoint_path()?;
    fs::write(path, payload).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_bulk_osint_checkpoint() -> Result<Option<String>, String> {
    let path = bulk_osint_checkpoint_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    if content.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(content))
}

#[tauri::command]
pub fn clear_bulk_osint_checkpoint() -> Result<(), String> {
    let path = bulk_osint_checkpoint_path()?;
    if path.exists() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn load_allowlist() -> Result<String, String> {
    let path = allowlist_path()?;
    if !path.exists() {
        return Ok("{}".into());
    }
    fs::read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_allowlist(payload: String) -> Result<(), String> {
    let path = allowlist_path()?;
    // Validate JSON object
    let _: serde_json::Value = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
    fs::write(path, payload).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_alert_coverage() -> Result<String, String> {
    let path = alert_coverage_path()?;
    if !path.exists() {
        return Ok("{}".into());
    }
    fs::read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_alert_coverage(payload: String) -> Result<(), String> {
    let path = alert_coverage_path()?;
    let _: serde_json::Value = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
    fs::write(path, payload).map_err(|e| e.to_string())
}

/// Open a text file (one key per line), merge into saved VT keys, return status.
#[tauri::command]
pub async fn import_vt_keys_from_file(app: tauri::AppHandle) -> Result<OsintKeysStatus, String> {
    let path = app
        .dialog()
        .file()
        .set_title("Importa API key VirusTotal")
        .add_filter("Testo", &["txt", "text", "csv", "keys"])
        .add_filter("Tutti i file", &["*"])
        .blocking_pick_file();

    let Some(file_path) = path else {
        return Err("Import annullato.".to_string());
    };
    let path_buf = file_path.into_path().map_err(|e| e.to_string())?;
    let content = fs::read_to_string(path_buf).map_err(|e| e.to_string())?;
    let mut incoming: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    // also allow comma-separated on a single line
    if incoming.len() == 1 && incoming[0].contains(',') {
        incoming = incoming[0]
            .split(|c| c == ',' || c == ';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if incoming.is_empty() {
        return Err("Nessuna chiave trovata nel file.".to_string());
    }

    let mut keys = read_osint_keys()?;
    keys.vt_api_keys.extend(incoming);
    keys = normalize_osint_keys(keys);
    write_osint_keys(&keys)?;
    Ok(osint_status(&keys))
}
