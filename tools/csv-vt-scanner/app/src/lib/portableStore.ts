export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export interface OsintKeysStatus {
  vtConfigured: boolean;
  vtKeyCount: number;
  abuseConfigured: boolean;
}

export interface OsintKeysUpdate {
  vtApiKey?: string;
  vtApiKeys?: string[];
  abuseIpdbApiKey?: string;
}

const BROWSER_CSV_VT_CHECKPOINT = "csv-vt-scanner-checkpoint";

function normalizeStatus(raw: {
  vtConfigured?: boolean;
  vtKeyCount?: number;
  vt_key_count?: number;
  abuseConfigured?: boolean;
}): OsintKeysStatus {
  const count =
    typeof raw.vtKeyCount === "number"
      ? raw.vtKeyCount
      : typeof raw.vt_key_count === "number"
        ? raw.vt_key_count
        : raw.vtConfigured
          ? 1
          : 0;
  return {
    vtConfigured: Boolean(raw.vtConfigured) || count > 0,
    vtKeyCount: count,
    abuseConfigured: Boolean(raw.abuseConfigured),
  };
}

async function invokeStorage<T>(cmd: string, payload?: unknown): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  if (payload !== undefined) {
    return invoke<T>(cmd, { payload });
  }
  return invoke<T>(cmd);
}

export async function loadOsintKeys(): Promise<OsintKeysStatus> {
  if (isTauri()) {
    try {
      const status = await invokeStorage<OsintKeysStatus>("load_osint_keys");
      return normalizeStatus(status);
    } catch {
      return { vtConfigured: false, vtKeyCount: 0, abuseConfigured: false };
    }
  }
  return { vtConfigured: false, vtKeyCount: 0, abuseConfigured: false };
}

export async function saveOsintKeys(update: OsintKeysUpdate): Promise<OsintKeysStatus> {
  if (isTauri()) {
    const status = await invokeStorage<OsintKeysStatus>("save_osint_keys", update);
    return normalizeStatus(status);
  }
  return { vtConfigured: false, vtKeyCount: 0, abuseConfigured: false };
}

export async function getDataDirectory(): Promise<string> {
  if (isTauri()) {
    return invokeStorage<string>("get_data_dir");
  }
  return "browser demo mode";
}

export interface ExportTextFileOptions {
  title: string;
  defaultFileName: string;
}

export async function exportTextFile(
  content: string,
  opts: ExportTextFileOptions,
): Promise<boolean> {
  if (isTauri()) {
    return invokeStorage<boolean>("export_text_file", {
      content,
      title: opts.title,
      defaultFileName: opts.defaultFileName,
    });
  }
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = opts.defaultFileName;
  anchor.click();
  URL.revokeObjectURL(url);
  return true;
}

export interface CsvVtCheckpoint {
  fileName: string;
  parseInfo: string;
  results: unknown[];
  savedAt: string;
}

export async function saveCsvVtCheckpoint(data: CsvVtCheckpoint): Promise<void> {
  const json = JSON.stringify(data);
  if (isTauri()) {
    await invokeStorage("save_csv_vt_checkpoint", json);
    return;
  }
  localStorage.setItem(BROWSER_CSV_VT_CHECKPOINT, json);
}

export async function loadCsvVtCheckpoint(): Promise<CsvVtCheckpoint | null> {
  if (isTauri()) {
    try {
      const raw = await invokeStorage<string | null>("load_csv_vt_checkpoint");
      if (!raw) return null;
      return JSON.parse(raw) as CsvVtCheckpoint;
    } catch {
      return null;
    }
  }
  try {
    const raw = localStorage.getItem(BROWSER_CSV_VT_CHECKPOINT);
    if (!raw) return null;
    return JSON.parse(raw) as CsvVtCheckpoint;
  } catch {
    return null;
  }
}

export async function clearCsvVtCheckpoint(): Promise<void> {
  if (isTauri()) {
    await invokeStorage("clear_csv_vt_checkpoint");
    return;
  }
  localStorage.removeItem(BROWSER_CSV_VT_CHECKPOINT);
}

export async function importVtKeysFromFile(): Promise<OsintKeysStatus> {
  if (!isTauri()) {
    throw new Error("Import file disponibile solo nell'app desktop.");
  }
  const status = await invokeStorage<OsintKeysStatus>("import_vt_keys_from_file");
  return normalizeStatus(status);
}

export interface VtKeyPoolStatus {
  total: number;
  active: number;
  cooled: number;
}

export async function loadVtKeyPoolStatus(): Promise<VtKeyPoolStatus> {
  if (!isTauri()) {
    return { total: 0, active: 0, cooled: 0 };
  }
  try {
    return await invokeStorage<VtKeyPoolStatus>("vt_key_pool_status");
  } catch {
    return { total: 0, active: 0, cooled: 0 };
  }
}

const BROWSER_BULK_OSINT_CHECKPOINT = "soc-hub-bulk-osint-checkpoint";

export interface BulkOsintCheckpoint {
  fileName: string;
  parseInfo: string;
  results: unknown[];
  savedAt: string;
}

export async function saveBulkOsintCheckpoint(data: BulkOsintCheckpoint): Promise<void> {
  const json = JSON.stringify(data);
  if (isTauri()) {
    await invokeStorage("save_bulk_osint_checkpoint", json);
    return;
  }
  localStorage.setItem(BROWSER_BULK_OSINT_CHECKPOINT, json);
}

export async function loadBulkOsintCheckpoint(): Promise<BulkOsintCheckpoint | null> {
  if (isTauri()) {
    try {
      const raw = await invokeStorage<string | null>("load_bulk_osint_checkpoint");
      if (!raw) return null;
      return JSON.parse(raw) as BulkOsintCheckpoint;
    } catch {
      return null;
    }
  }
  try {
    const raw = localStorage.getItem(BROWSER_BULK_OSINT_CHECKPOINT);
    if (!raw) return null;
    return JSON.parse(raw) as BulkOsintCheckpoint;
  } catch {
    return null;
  }
}

export async function clearBulkOsintCheckpoint(): Promise<void> {
  if (isTauri()) {
    await invokeStorage("clear_bulk_osint_checkpoint");
    return;
  }
  localStorage.removeItem(BROWSER_BULK_OSINT_CHECKPOINT);
}
