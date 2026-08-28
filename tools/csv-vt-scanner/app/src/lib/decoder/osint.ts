import { isTauri } from "@/lib/portableStore";
import type { Artifact, ArtifactScope } from "./types";

export const VT_ARTIFACT_TYPES = [
  "ip",
  "hash_sha256",
  "hash_sha1",
  "hash_md5",
  "domain",
  "url",
] as const;

export type Reliability = "alto" | "medio" | "basso" | "sconosciuto" | "interno";

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

export interface AbuseLookupResult {
  status: "success" | "not_found" | "error" | string;
  summary: string;
  abuseConfidenceScore?: number | null;
  totalReports?: number | null;
  countryCode?: string | null;
  isp?: string | null;
  permalink?: string | null;
  error?: string | null;
}

export interface ArtifactEnrichment {
  status: "idle" | "loading" | "done" | "error" | "skipped";
  vt?: VtLookupResult;
  abuse?: AbuseLookupResult;
  reliability: Reliability;
  error?: string;
}

export interface OsintPermalinks {
  vt?: string;
  abuse?: string;
}

export function artifactKey(art: Artifact): string {
  return `${art.type}|${art.normalizedValue}`;
}

export function osintEligible(art: Artifact): boolean {
  if (art.scope === "internal") return false;
  return (VT_ARTIFACT_TYPES as readonly string[]).includes(art.type);
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

export function normalizeAbuse(raw: unknown): AbuseLookupResult {
  const obj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const score = pick(obj, "abuseConfidenceScore", "abuse_confidence_score");
  const reports = pick(obj, "totalReports", "total_reports");
  return {
    status: String(obj.status ?? "error"),
    summary: String(obj.summary ?? ""),
    abuseConfidenceScore: score == null ? null : asNum(score),
    totalReports: reports == null ? null : asNum(reports),
    countryCode: (pick(obj, "countryCode", "country_code") as string | null) ?? null,
    isp: (obj.isp as string | null) ?? null,
    permalink: (obj.permalink as string | null) ?? null,
    error: (obj.error as string | null) ?? null,
  };
}

export function combineReliability(
  scope: ArtifactScope,
  vt?: VtLookupResult,
  abuse?: AbuseLookupResult,
): Reliability {
  if (scope === "internal") return "interno";

  const malicious = vt?.status === "success" ? asNum(vt.malicious) : 0;
  const abuseScore = abuse?.status === "success" ? asNum(abuse.abuseConfidenceScore) : 0;
  const vtOk = vt?.status === "success";
  const abuseOk = abuse?.status === "success";

  if (malicious >= 5 || abuseScore >= 50) return "alto";
  if (malicious >= 1 || abuseScore >= 25) return "medio";
  if (vtOk && malicious === 0) return "basso";
  if (abuseOk && abuseScore === 0 && vtOk) return "basso";
  if (vt?.status === "not_found" && !abuseOk) return "sconosciuto";
  if (!vt && !abuse) return "sconosciuto";
  if (abuseOk && abuseScore === 0) return "basso";
  return "sconosciuto";
}

export const RELIABILITY_LABEL: Record<Reliability, string> = {
  alto: "Alto",
  medio: "Medio",
  basso: "Basso",
  sconosciuto: "Sconosciuto",
  interno: "Interno",
};

function vtUrlId(url: string): string {
  const bytes = new TextEncoder().encode(url);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function osintPermalinks(art: Artifact): OsintPermalinks {
  if (art.scope === "internal") return {};
  const v = art.normalizedValue;
  switch (art.type) {
    case "ip":
      return {
        vt: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}`,
        abuse: `https://www.abuseipdb.com/check/${encodeURIComponent(v)}`,
      };
    case "hash_sha256":
    case "hash_sha1":
    case "hash_md5":
      return { vt: `https://www.virustotal.com/gui/file/${encodeURIComponent(v)}` };
    case "domain":
      return { vt: `https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}` };
    case "url":
      return { vt: `https://www.virustotal.com/gui/url/${vtUrlId(v)}` };
    default:
      return {};
  }
}

export async function openExternalUrl(url: string): Promise<void> {
  if (isTauri()) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("open_external_url", { url });
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
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
const abuseCache = new Map<string, AbuseLookupResult>();

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

export async function lookupAbuseIpdb(ip: string): Promise<AbuseLookupResult> {
  if (!isTauri()) {
    throw new Error("AbuseIPDB è disponibile solo nell'app desktop.");
  }
  const cached = abuseCache.get(ip);
  if (cached && cached.status !== "error") return cached;
  const result = normalizeAbuse(await invokeOsint<unknown>("abuseipdb_lookup", { ip }));
  if (result.status !== "error") abuseCache.set(ip, result);
  return result;
}

export function emptyEnrichment(scope: ArtifactScope): ArtifactEnrichment {
  return {
    status: scope === "internal" ? "skipped" : "idle",
    reliability: scope === "internal" ? "interno" : "sconosciuto",
  };
}

export async function enrichPublicArtifacts(
  artifacts: Artifact[],
  keys: { vtConfigured: boolean; abuseConfigured: boolean },
  onProgress: (update: {
    key: string;
    data: ArtifactEnrichment;
    current: number;
    total: number;
  }) => void,
): Promise<void> {
  const jobs = artifacts.filter((art) => {
    if (!osintEligible(art)) return false;
    const wantVt = keys.vtConfigured;
    const wantAbuse = keys.abuseConfigured && art.type === "ip";
    return wantVt || wantAbuse;
  });
  const total = jobs.length;
  let current = 0;

  for (const art of artifacts) {
    const key = artifactKey(art);
    if (!osintEligible(art)) {
      onProgress({
        key,
        data: {
          status: "skipped",
          reliability: art.scope === "internal" ? "interno" : "sconosciuto",
        },
        current,
        total,
      });
      continue;
    }
    const wantVt = keys.vtConfigured;
    const wantAbuse = keys.abuseConfigured && art.type === "ip";
    if (!wantVt && !wantAbuse) continue;

    onProgress({
      key,
      data: { status: "loading", reliability: "sconosciuto" },
      current,
      total,
    });
    try {
      const vt = wantVt ? await lookupVirusTotal(art.type, art.normalizedValue) : undefined;
      const abuse = wantAbuse ? await lookupAbuseIpdb(art.normalizedValue) : undefined;
      const links = osintPermalinks(art);
      current += 1;
      onProgress({
        key,
        data: {
          status: "done",
          vt: vt ? { ...vt, permalink: vt.permalink || links.vt || vt.permalink } : undefined,
          abuse: abuse
            ? { ...abuse, permalink: abuse.permalink || links.abuse || abuse.permalink }
            : undefined,
          reliability: combineReliability(art.scope, vt, abuse),
        },
        current,
        total,
      });
    } catch (err) {
      current += 1;
      onProgress({
        key,
        data: {
          status: "error",
          reliability: "sconosciuto",
          error: err instanceof Error ? err.message : String(err),
        },
        current,
        total,
      });
    }
  }
}
