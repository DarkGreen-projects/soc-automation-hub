mod osint;
mod storage;

use osint::{abuseipdb_lookup, open_external_url, vt_key_pool_status, vt_lookup};
use storage::{
    clear_bulk_osint_checkpoint, clear_csv_vt_checkpoint, export_schema_catalog, export_text_file,
    export_user_data, get_data_dir, import_user_data, import_vt_keys_from_file,
    load_alert_coverage, load_allowlist, load_bulk_osint_checkpoint, load_csv_vt_checkpoint,
    load_osint_keys, load_schema_catalog, load_user_data, save_alert_coverage, save_allowlist,
    save_bulk_osint_checkpoint, save_csv_vt_checkpoint, save_osint_keys, save_schema_catalog,
    save_user_data,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            load_user_data,
            save_user_data,
            get_data_dir,
            export_user_data,
            import_user_data,
            load_osint_keys,
            save_osint_keys,
            import_vt_keys_from_file,
            load_schema_catalog,
            save_schema_catalog,
            export_schema_catalog,
            export_text_file,
            save_csv_vt_checkpoint,
            load_csv_vt_checkpoint,
            clear_csv_vt_checkpoint,
            save_bulk_osint_checkpoint,
            load_bulk_osint_checkpoint,
            clear_bulk_osint_checkpoint,
            load_allowlist,
            save_allowlist,
            load_alert_coverage,
            save_alert_coverage,
            vt_lookup,
            vt_key_pool_status,
            abuseipdb_lookup,
            open_external_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
