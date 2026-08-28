import { classifyVtResult } from "./stats";
import type { ScanRowResult } from "./types";
import type { ScanProgress } from "./scan";

export interface RunDemoScanOptions {
  rows: ScanRowResult[];
  signal: AbortSignal;
  onProgress: (progress: ScanProgress) => void;
}

function demoVtForIp(ip: string) {
  const last = Number(ip.split(".").pop() ?? "0");
  const bucket = last % 10;
  if (bucket <= 1) {
    return {
      status: "success" as const,
      summary: "Demo: rilevato come malevolo",
      malicious: 3 + (last % 5),
      total: 70,
      detectionRatio: `${3 + (last % 5)}/70`,
      permalink: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
    };
  }
  if (bucket <= 6) {
    return {
      status: "success" as const,
      summary: "Demo: pulito",
      malicious: 0,
      total: 70,
      detectionRatio: "0/70",
      permalink: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
    };
  }
  if (bucket <= 8) {
    return {
      status: "not_found" as const,
      summary: "Demo: non presente in VT",
      permalink: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
    };
  }
  return {
    status: "error" as const,
    summary: "Demo: errore simulato",
    error: "Simulated API timeout",
  };
}

/** Web demo: simulates VT classification without network calls. */
export async function runDemoScan(options: RunDemoScanOptions): Promise<ScanRowResult[]> {
  const { signal, onProgress } = options;
  const results: ScanRowResult[] = options.rows.map((row) => {
    if (row.skipped) return { ...row, category: "skipped" as const };
    return { ...row, category: "pending" as const, vt: undefined, error: undefined };
  });

  const toScan = results
    .map((r, index) => ({ r, index }))
    .filter(({ r }) => r.category === "pending")
    .reverse();

  const total = toScan.length;
  let current = 0;

  const emit = (ip = "") => {
    onProgress({ current, total, ip, results });
  };

  emit();
  if (total === 0) return results;

  for (const { r, index } of toScan) {
    if (signal.aborted) break;
    await new Promise((res) => setTimeout(res, 35));
    if (signal.aborted) break;

    const vt = demoVtForIp(r.ip);
    const category = classifyVtResult(vt);
    results[index] = { ...r, category, vt, error: vt.error ?? undefined };
    current += 1;
    emit(r.ip);
  }

  return results;
}
