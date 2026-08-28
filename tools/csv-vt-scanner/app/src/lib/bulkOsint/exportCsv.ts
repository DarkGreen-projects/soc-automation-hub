import { exportTextFile } from "@/lib/portableStore";
import type { BulkScanRow } from "./types";

function csvEscape(value: string): string {
  if (/[",\r\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

function todayStamp(): string {
  const d = new Date();
  return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}`;
}

const HEADER = ["value", "kind", "category", "vt_malicious", "vt_total", "vt_ratio", "vt_permalink", "error"];

function cols(r: BulkScanRow): string[] {
  return [
    r.value,
    r.kind,
    r.category,
    r.vt?.malicious != null ? String(r.vt.malicious) : "",
    r.vt?.total != null ? String(r.vt.total) : "",
    r.vt?.detectionRatio ?? "",
    r.vt?.permalink ?? "",
    r.error ?? "",
  ];
}

export function buildBulkMaliciousCsv(results: BulkScanRow[]): string {
  const lines = [HEADER.map(csvEscape).join(",")];
  for (const r of results) {
    if (r.category !== "malicious") continue;
    lines.push(cols(r).map(csvEscape).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}

export function buildBulkAllCsv(results: BulkScanRow[]): string {
  const lines = [HEADER.map(csvEscape).join(",")];
  for (const r of results) {
    lines.push(cols(r).map(csvEscape).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}

export async function exportBulkMaliciousCsv(results: BulkScanRow[]): Promise<boolean> {
  return exportTextFile(buildBulkMaliciousCsv(results), {
    title: "Esporta IOC malevoli",
    defaultFileName: `malicious-iocs-${todayStamp()}.csv`,
  });
}

export async function exportBulkAllCsv(results: BulkScanRow[]): Promise<boolean> {
  return exportTextFile(buildBulkAllCsv(results), {
    title: "Esporta risultati Bulk OSINT",
    defaultFileName: `bulk-osint-all-${todayStamp()}.csv`,
  });
}
