import { isTransientVtFailure, lookupVirusTotal } from "@/lib/decoder/osint";
import { classifyVtResult, type BulkScanRow } from "./types";

export interface BulkScanProgress {
  current: number;
  total: number;
  value: string;
  results: BulkScanRow[];
  lastError?: string;
}

export type BulkScanMode = "fresh" | "resume";

export interface RunBulkOsintOptions {
  rows: BulkScanRow[];
  signal: AbortSignal;
  onProgress: (progress: BulkScanProgress) => void;
  concurrency?: number;
  mode?: BulkScanMode;
}

function prepare(rows: BulkScanRow[], mode: BulkScanMode): BulkScanRow[] {
  if (mode === "fresh") {
    return rows.map((row) => {
      if (row.skipped) {
        return { ...row, category: "skipped" as const, vt: undefined, error: undefined };
      }
      return { ...row, category: "pending" as const, vt: undefined, error: undefined };
    });
  }
  return rows.map((row) => {
    if (row.skipped) return { ...row, category: "skipped" as const };
    if (row.category === "error" || row.category === "pending") {
      return { ...row, category: "pending" as const, vt: undefined, error: undefined };
    }
    return row;
  });
}

export async function runBulkOsintScan(options: RunBulkOsintOptions): Promise<BulkScanRow[]> {
  const { signal, onProgress } = options;
  const mode = options.mode ?? "fresh";
  const concurrency = Math.max(1, Math.floor(options.concurrency ?? 1));
  const results = prepare(options.rows, mode);

  const toScan = results
    .map((r, index) => ({ r, index }))
    .filter(({ r }) => r.category === "pending")
    .reverse();
  const total = toScan.length;
  let current = 0;
  let nextJob = 0;
  let latest = "";
  let lastError = "";

  const emit = () => {
    onProgress({
      current,
      total,
      value: latest,
      results: [...results],
      lastError: lastError || undefined,
    });
  };

  const scanOne = async (jobIndex: number) => {
    const job = toScan[jobIndex];
    if (!job) return;
    const { r, index } = job;
    latest = r.value;
    try {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const vt = await lookupVirusTotal(r.kind, r.value);
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const category = classifyVtResult(vt);
      results[index] = { ...r, category, vt, error: undefined };
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") throw e;
      const msg = e instanceof Error ? e.message : String(e);
      lastError = msg;
      const transient = isTransientVtFailure(msg);
      results[index] = {
        ...r,
        category: "error",
        error: transient ? `${msg} (riprova)` : msg,
      };
    } finally {
      current += 1;
      emit();
    }
  };

  emit();

  if (toScan.length === 0) return results;

  // Warm-up first item sequentially
  await scanOne(0);
  nextJob = 1;

  const workers = Array.from({ length: Math.min(concurrency, toScan.length - 1) }, async (_, w) => {
    await new Promise((r) => setTimeout(r, w * 120));
    while (true) {
      if (signal.aborted) return;
      const jobIndex = nextJob;
      nextJob += 1;
      if (jobIndex >= toScan.length) return;
      await scanOne(jobIndex);
    }
  });

  await Promise.all(workers);
  return results;
}

export function countResumable(results: BulkScanRow[]): number {
  return results.filter((r) => r.category === "pending" || r.category === "error").length;
}

export function countClassified(results: BulkScanRow[]): number {
  return results.filter(
    (r) =>
      r.category === "malicious" ||
      r.category === "clean" ||
      r.category === "not_found",
  ).length;
}
