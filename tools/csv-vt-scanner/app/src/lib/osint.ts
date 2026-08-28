import { isTauri } from "@/lib/portableStore";

export interface VtLookupResult {
  status: "success" | "not_found" | "error" | string;
  summary: string;
  detectionRatio?: string;
  malicious?: number | null;
  total?: number | null;
  country?: string | null;
  asOwner?: string | null;
  permalink?: string | null;
  error?: string | null;
}

function asNum(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return 0;
}

function pick(raw: Record<string, unknown>, camel: string, snake: string): unknown {
  return raw[camel] ?? raw[snake];
}

export function normalizeVt(raw: unknown): VtLookupResult {
  const obj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const malicious = pick(obj, "malicious", "malicious");
  const total = pick(obj, "total", "total");
  const detectionRatio = pick(obj, "detectionRatio", "detection_ratio");
  return {
    status: String(obj.status ?? "error"),
    summary: String(obj.summary ?? ""),
    detectionRatio: detectionRatio != null ? String(detectionRatio) : undefined,
    malicious: malicious == null ? null : asNum(malicious),
    total: total == null ? null : asNum(total),
    country: (pick(obj, "country", "country") as string | null) ?? null,
    asOwner: (pick(obj, "asOwner", "as_owner") as string | null) ?? null,
    permalink: (pick(obj, "permalink", "permalink") as string | null) ?? null,
    error: (pick(obj, "error", "error") as string | null) ?? null,
  };
}

export function isTransientVtFailure(message?: string | null): boolean {
  const e = (message ?? "").toLowerCase();
  return (
    e.includes("toomanyrequests") ||
    e.includes("too many") ||
    e.includes("timeout") ||
    e.includes("429") ||
    e.includes("noavailablekeys") ||
    e.includes("cooldown") ||
    e.includes("errore di rete") ||
    e.includes("network")
  );
}

async function invokeOsint<T>(cmd: string, payload: unknown): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  try {
    return await invoke<T>(cmd, { payload });
  } catch {
    return invoke<T>(cmd, payload as Record<string, unknown>);
  }
}

const vtCache = new Map<string, VtLookupResult>();

export async function lookupVirusTotal(
  kind: string,
  value: string,
  options?: { maxAttempts?: number },
): Promise<VtLookupResult> {
  if (!isTauri()) {
    throw new Error("VirusTotal è disponibile solo nell'app desktop.");
  }
  const cacheKey = `${kind}|${value}`;
  const cached = vtCache.get(cacheKey);
  if (cached && cached.status !== "error") return cached;

  const maxAttempts = Math.max(1, options?.maxAttempts ?? 5);
  const perAttemptMs = 22_000;
  let lastError = "VirusTotal: tentativi esauriti";

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const raw = await Promise.race([
        invokeOsint<unknown>("vt_lookup", { kind, value }),
        new Promise<never>((_, reject) => {
          window.setTimeout(() => {
            reject(
              new Error(
                `Timeout VirusTotal (${perAttemptMs / 1000}s) su ${value} [tentativo ${attempt + 1}/${maxAttempts}]`,
              ),
            );
          }, perAttemptMs);
        }),
      ]);
      const result = normalizeVt(raw);
      if (
        result.status === "error" &&
        isTransientVtFailure(result.error ?? result.summary) &&
        attempt < maxAttempts - 1
      ) {
        lastError = result.error || result.summary || lastError;
        await new Promise((r) => setTimeout(r, 600 + attempt * 400));
        continue;
      }
      if (result.status !== "error") vtCache.set(cacheKey, result);
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      lastError = message;
      if (isTransientVtFailure(message) && attempt < maxAttempts - 1) {
        await new Promise((r) => setTimeout(r, 600 + attempt * 400));
        continue;
      }
      throw err instanceof Error ? err : new Error(message);
    }
  }

  return {
    status: "error",
    summary: "VirusTotal: failover esaurito",
    error: lastError,
  };
}
