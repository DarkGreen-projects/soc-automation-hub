import type { VtLookupResult } from "@/lib/osint";
import type {
  CsvIpRow,
  ScanCategory,
  ScanRowResult,
  ScanStats,
  ScanStatsPercents,
} from "./types";

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

export function initialResults(rows: CsvIpRow[]): ScanRowResult[] {
  return rows.map((row) => {
    if (row.skipped) {
      return { ...row, category: "skipped" as const };
    }
    return { ...row, category: "pending" as const };
  });
}

export function computeStats(results: ScanRowResult[]): ScanStats {
  const stats: ScanStats = {
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

function pct(n: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((n / total) * 1000) / 10;
}

/** Percentages over all rows (including skipped). Sum may be ~100 due to rounding. */
export function computePercents(stats: ScanStats): ScanStatsPercents {
  const { total } = stats;
  return {
    malicious: pct(stats.malicious, total),
    clean: pct(stats.clean, total),
    notFound: pct(stats.notFound, total),
    error: pct(stats.error, total),
    skipped: pct(stats.skipped, total),
  };
}

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

export const PIE_COLORS: Record<Exclude<ScanCategory, "pending">, string> = {
  malicious: "#c44c4c",
  clean: "#3d8b5e",
  not_found: "#8a8a8a",
  error: "#c47a2a",
  skipped: "#5a6a8a",
};
