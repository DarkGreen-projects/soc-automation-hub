import type { VtLookupResult } from "@/lib/decoder/osint";
import { classifyVtResult, type BulkScanRow } from "./types";
import type { BulkScanProgress } from "./scan";

export interface RunBulkDemoScanOptions {
  rows: BulkScanRow[];
  signal: AbortSignal;
  onProgress: (progress: BulkScanProgress) => void;
}

function demoVtForValue(kind: BulkScanRow["kind"], value: string): VtLookupResult {
  const seed = value.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const bucket = seed % 10;
  const permalinkBase =
    kind === "ip"
      ? `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(value)}`
      : kind === "domain"
        ? `https://www.virustotal.com/gui/domain/${encodeURIComponent(value)}`
        : kind === "url"
          ? `https://www.virustotal.com/gui/url/${encodeURIComponent(value)}`
          : `https://www.virustotal.com/gui/file/${encodeURIComponent(value)}`;

  if (bucket <= 1) {
    return {
      status: "success",
      summary: "Demo: rilevato come malevolo",
      malicious: 2 + (seed % 4),
      total: 70,
      detectionRatio: `${2 + (seed % 4)}/70`,
      permalink: permalinkBase,
    };
  }
  if (bucket <= 6) {
    return {
      status: "success",
      summary: "Demo: pulito",
      malicious: 0,
      total: 70,
      detectionRatio: "0/70",
      permalink: permalinkBase,
    };
  }
  if (bucket <= 8) {
    return {
      status: "not_found",
      summary: "Demo: non presente in VT",
      permalink: permalinkBase,
    };
  }
  return {
    status: "error",
    summary: "Demo: errore simulato",
    error: "Simulated API timeout",
  };
}

/** Web demo: simulates VT classification for mixed IOC types without network calls. */
export async function runBulkDemoScan(options: RunBulkDemoScanOptions): Promise<BulkScanRow[]> {
  const { signal, onProgress } = options;
  const results = options.rows.map((row) => ({ ...row }));

  const toScan = results
    .map((r, index) => ({ r, index }))
    .filter(({ r }) => r.category === "pending" && !r.skipped);

  const total = toScan.length;
  let current = 0;

  const emit = (value: string, lastError?: string) => {
    onProgress({
      current,
      total,
      value,
      results: [...results],
      lastError,
    });
  };

  emit("");

  for (const { r, index } of toScan) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    await new Promise((resolve) => setTimeout(resolve, 40));
    const vt = demoVtForValue(r.kind, r.value);
    const category = classifyVtResult(vt);
    results[index] = { ...r, category, vt, error: undefined };
    current += 1;
    emit(r.value);
  }

  return results;
}
