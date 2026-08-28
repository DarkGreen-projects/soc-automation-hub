import { exportTextFile } from "@/lib/portableStore";
import type { ScanRowResult } from "./types";

function csvEscape(value: string): string {
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function rowLine(cols: string[]): string {
  return cols.map(csvEscape).join(",");
}

function todayStamp(): string {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

function resultCols(r: ScanRowResult): string[] {
  return [
    r.ip,
    r.country,
    r.count,
    r.eventType,
    r.category,
    r.vt?.malicious != null ? String(r.vt.malicious) : "",
    r.vt?.total != null ? String(r.vt.total) : "",
    r.vt?.detectionRatio ?? "",
    r.vt?.permalink ?? "",
    r.error ?? "",
  ];
}

const HEADER = [
  "ip",
  "country",
  "count",
  "event_type",
  "category",
  "vt_malicious",
  "vt_total",
  "vt_ratio",
  "vt_permalink",
  "error",
];

export function buildMaliciousCsv(results: ScanRowResult[]): string {
  const lines = [rowLine(HEADER)];
  for (const r of results) {
    if (r.category !== "malicious") continue;
    lines.push(rowLine(resultCols(r)));
  }
  return lines.join("\r\n") + "\r\n";
}

export function buildAllResultsCsv(results: ScanRowResult[]): string {
  const lines = [rowLine(HEADER)];
  for (const r of results) {
    lines.push(rowLine(resultCols(r)));
  }
  return lines.join("\r\n") + "\r\n";
}

/** Returns true if the file was saved (false if user cancelled). */
export async function exportMaliciousCsv(results: ScanRowResult[]): Promise<boolean> {
  const name = `malicious-ips-${todayStamp()}.csv`;
  return exportTextFile(buildMaliciousCsv(results), {
    title: "Esporta IP malevoli",
    defaultFileName: name,
  });
}

/** Returns true if the file was saved (false if user cancelled). */
export async function exportAllResultsCsv(results: ScanRowResult[]): Promise<boolean> {
  const name = `vt-scan-all-${todayStamp()}.csv`;
  return exportTextFile(buildAllResultsCsv(results), {
    title: "Esporta tutti i risultati VT",
    defaultFileName: name,
  });
}
