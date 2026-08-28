import type { VtLookupResult } from "@/lib/decoder/osint";
import type { BulkIocKind } from "./parseIocs";

export type ScanCategory =
  | "malicious"
  | "clean"
  | "not_found"
  | "error"
  | "skipped"
  | "pending";

export interface BulkScanRow {
  value: string;
  kind: BulkIocKind;
  skipped: boolean;
  skipReason?: string;
  line: number;
  category: ScanCategory;
  vt?: VtLookupResult;
  error?: string;
}

export interface BulkScanStats {
  total: number;
  malicious: number;
  clean: number;
  notFound: number;
  error: number;
  skipped: number;
  pending: number;
  done: number;
}

export function classifyVtResult(vt: VtLookupResult | undefined, error?: string): ScanCategory {
  if (error && !vt) return "error";
  if (!vt) return "error";
  if (vt.status === "not_found") return "not_found";
  if (vt.status === "error") return "error";
  if (vt.status === "success") {
    const malicious = vt.malicious ?? 0;
    return malicious >= 1 ? "malicious" : "clean";
  }
  return "error";
}

export function initialBulkResults(
  rows: { value: string; kind: BulkIocKind; skipped: boolean; skipReason?: string; line: number }[],
): BulkScanRow[] {
  return rows.map((row) => ({
    ...row,
    category: row.skipped ? ("skipped" as const) : ("pending" as const),
  }));
}

export function computeBulkStats(results: BulkScanRow[]): BulkScanStats {
  const stats: BulkScanStats = {
    total: results.length,
    malicious: 0,
    clean: 0,
    notFound: 0,
    error: 0,
    skipped: 0,
    pending: 0,
    done: 0,
  };
  for (const r of results) {
    switch (r.category) {
      case "malicious":
        stats.malicious += 1;
        stats.done += 1;
        break;
      case "clean":
        stats.clean += 1;
        stats.done += 1;
        break;
      case "not_found":
        stats.notFound += 1;
        stats.done += 1;
        break;
      case "error":
        stats.error += 1;
        stats.done += 1;
        break;
      case "skipped":
        stats.skipped += 1;
        stats.done += 1;
        break;
      case "pending":
        stats.pending += 1;
        break;
    }
  }
  return stats;
}

export const PIE_COLORS: Record<Exclude<ScanCategory, "pending">, string> = {
  malicious: "#c44",
  clean: "#3a8",
  not_found: "#888",
  error: "#c80",
  skipped: "#668",
};

export function categoryLabel(cat: ScanCategory): string {
  switch (cat) {
    case "malicious":
      return "Malevoli";
    case "clean":
      return "Puliti";
    case "not_found":
      return "Non trovati";
    case "error":
      return "Errori";
    case "skipped":
      return "Saltati";
    case "pending":
      return "In coda";
  }
}
