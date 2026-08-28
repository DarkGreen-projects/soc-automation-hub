import { isTransientVtFailure, lookupVirusTotal } from "@/lib/osint";
import { classifyVtResult } from "./stats";
import type { ScanRowResult } from "./types";

export interface ScanProgress {
  current: number;
  total: number;
  ip: string;
  results: ScanRowResult[];
  lastError?: string;
}

export type ScanMode = "fresh" | "resume";

export interface RunCsvVtScanOptions {
  rows: ScanRowResult[];
  signal: AbortSignal;
  onProgress: (progress: ScanProgress) => void;
  /** Parallel workers (= number of VT API keys). Default 1. */
  concurrency?: number;
  /**
   * fresh = reset all public IPs to pending.
   * resume = keep done results; only scan pending + error.
   */
  mode?: ScanMode;
}

function prepareResults(rows: ScanRowResult[], mode: ScanMode): ScanRowResult[] {
  if (mode === "fresh") {
    return rows.map((row) => {
      if (row.skipped) {
        return { ...row, category: "skipped" as const, vt: undefined, error: undefined };
      }
      return {
        ...row,
        category: "pending" as const,
        vt: undefined,
        error: undefined,
      };
    });
  }
  return rows.map((row) => {
    if (row.skipped) {
      return { ...row, category: "skipped" as const };
    }
    if (row.category === "error" || row.category === "pending") {
      return {
        ...row,
        category: "pending" as const,
        vt: undefined,
        error: undefined,
      };
    }
    return row;
  });
}

/**
 * VirusTotal IP scan with optional parallelism and resume.
 * First IP is sequential (warm-up), then parallel with staggered starts.
 * Timeout / 429 → retry with other API keys (lookupVirusTotal failover).
 */
export async function runCsvVtScan(options: RunCsvVtScanOptions): Promise<ScanRowResult[]> {
  const { signal, onProgress } = options;
  const mode = options.mode ?? "fresh";
  const concurrency = Math.max(1, Math.floor(options.concurrency ?? 1));
  const results = prepareResults(options.rows, mode);

  const toScan = results
    .map((r, index) => ({ r, index }))
    .filter(({ r }) => r.category === "pending")
    // Bottom of CSV first (last rows in file).
    .reverse();
  const total = toScan.length;
  let current = 0;
  let nextJob = 0;
  let latestIp = "";
  let lastError = "";

  const emit = () => {
    onProgress({
      current,
      total,
      ip: latestIp,
      results,
      lastError: lastError || undefined,
    });
  };

  emit();

  if (total === 0) {
    return results;
  }

  const processOne = async (jobIndex: number) => {
    if (signal.aborted) return;
    const { r, index } = toScan[jobIndex];
    latestIp = r.ip;
    emit();

    try {
      // Attempts scale with key count so Timeout/429 rotate across the pool.
      const vt = await lookupVirusTotal("ip", r.ip, {
        maxAttempts: Math.max(concurrency + 2, 5),
      });
      if (signal.aborted) return;

      let category = classifyVtResult(vt);
      // If still transient after backend+frontend failover, one last pause+retry.
      if (
        category === "error" &&
        isTransientVtFailure(vt.error ?? vt.summary) &&
        !signal.aborted
      ) {
        lastError = `${vt.error ?? vt.summary} → ritento con altra key…`;
        emit();
        await new Promise((res) => setTimeout(res, 1500));
        if (!signal.aborted) {
          const vt2 = await lookupVirusTotal("ip", r.ip, {
            maxAttempts: Math.max(concurrency + 1, 4),
          });
          category = classifyVtResult(vt2);
          results[index] = { ...r, category, vt: vt2 };
          if (category === "error" && vt2.error) lastError = vt2.error;
        } else {
          results[index] = { ...r, category, vt };
        }
      } else {
        results[index] = { ...r, category, vt };
        if (category === "error" && vt.error) lastError = vt.error;
      }
    } catch (err) {
      if (signal.aborted) return;
      const message = err instanceof Error ? err.message : String(err);
      lastError = message;
      // Last chance: if timeout thrown, one more full failover pass.
      if (isTransientVtFailure(message) && !signal.aborted) {
        try {
          await new Promise((res) => setTimeout(res, 1000));
          const vt = await lookupVirusTotal("ip", r.ip, {
            maxAttempts: Math.max(concurrency + 1, 4),
          });
          const category = classifyVtResult(vt);
          results[index] = { ...r, category, vt };
          if (category === "error" && vt.error) lastError = vt.error;
          else lastError = "";
        } catch (err2) {
          const message2 = err2 instanceof Error ? err2.message : String(err2);
          lastError = message2;
          results[index] = { ...r, category: "error", error: message2 };
        }
      } else {
        results[index] = { ...r, category: "error", error: message };
      }
    }

    current += 1;
    latestIp = r.ip;
    emit();
  };

  await processOne(0);
  if (signal.aborted) return results;
  nextJob = 1;

  const worker = async (workerId: number) => {
    // Stagger by ~15s/concurrency so we don't 429 every key in the same second.
    const staggerMs = Math.max(200, Math.floor(15_000 / Math.max(1, concurrency)));
    if (workerId > 0) {
      await new Promise((r) => setTimeout(r, workerId * staggerMs));
    }
    while (true) {
      if (signal.aborted) return;
      const jobIndex = nextJob;
      nextJob += 1;
      if (jobIndex >= toScan.length) return;
      await processOne(jobIndex);
    }
  };

  const parallel = Math.min(concurrency, Math.max(0, total - 1));
  if (parallel > 0 && nextJob < toScan.length) {
    const workers = Array.from({ length: parallel }, (_, id) => worker(id));
    await Promise.all(workers);
  }

  return results;
}

/** ETA with N keys running in parallel (~15s per key). */
export function estimateEtaSeconds(
  remaining: number,
  intervalSeconds = 15,
  keyCount = 1,
): number {
  if (remaining <= 0) return 0;
  const keys = Math.max(1, keyCount);
  return Math.ceil((remaining * intervalSeconds) / keys);
}

export function formatEta(seconds: number): string {
  if (seconds <= 0) return "—";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m <= 0) return `${s}s`;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}h ${rm}m`;
}

export function countResumable(results: ScanRowResult[]): number {
  return results.filter((r) => r.category === "pending" || r.category === "error").length;
}

/** VT outcomes only (excludes skipped/pending — skipped alone must not imply "restart"). */
export function countClassified(results: ScanRowResult[]): number {
  return results.filter(
    (r) =>
      r.category === "malicious" ||
      r.category === "clean" ||
      r.category === "not_found" ||
      r.category === "error",
  ).length;
}
