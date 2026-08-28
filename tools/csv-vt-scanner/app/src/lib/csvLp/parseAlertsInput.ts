import type { CsvLpTable } from "./parseExport";
import { parseLogpointExport } from "./parseExport";

function cellValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value).trim();
}

function rowFromObject(obj: Record<string, unknown>): Record<string, string> {
  const row: Record<string, string> = {};
  for (const [key, value] of Object.entries(obj)) {
    row[key] = cellValue(value);
  }
  return row;
}

function headersFromRows(rows: Record<string, string>[]): string[] {
  const set = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row)) set.add(key);
  }
  return [...set];
}

function parseJsonAlerts(text: string): CsvLpTable {
  const parsed: unknown = JSON.parse(text);
  let rawRows: Record<string, unknown>[] = [];

  if (Array.isArray(parsed)) {
    rawRows = parsed.filter((x) => x && typeof x === "object") as Record<string, unknown>[];
  } else if (parsed && typeof parsed === "object") {
    const obj = parsed as Record<string, unknown>;
    const nested =
      obj.records ?? obj.rows ?? obj.events ?? obj.alerts ?? obj.data ?? obj.results;
    if (Array.isArray(nested)) {
      rawRows = nested.filter((x) => x && typeof x === "object") as Record<string, unknown>[];
    } else {
      rawRows = [obj];
    }
  }

  const rows = rawRows.map(rowFromObject);
  const headers = headersFromRows(rows);
  return { headers, rows, delimiter: ",", rowCount: rows.length };
}

/** Parse SIEM alert export from CSV or JSON (array / {records|rows|events|alerts}). */
export function parseAlertsInput(text: string): CsvLpTable {
  const trimmed = text.trim();
  if (!trimmed) {
    return { headers: [], rows: [], delimiter: ",", rowCount: 0 };
  }
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      return parseJsonAlerts(trimmed);
    } catch {
      return { headers: [], rows: [], delimiter: ",", rowCount: 0 };
    }
  }
  return parseLogpointExport(trimmed);
}
