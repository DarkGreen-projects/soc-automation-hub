import {
  DOMAIN_RE,
  IPV4_RE,
  MD5_RE,
  SHA1_RE,
  SHA256_RE,
  URL_RE,
  isPrivateIpv4,
  looksLikeIpv4,
  matchAll,
  normalizeDomain,
  normalizeHash,
  shouldSkipDomain,
} from "./patterns";
import type { Artifact, ArtifactScope, ArtifactType } from "./types";

export const MAX_ARTIFACTS = 200;
export const MAX_WALK_NODES = 8000;

export function makeArtifact(
  type: ArtifactType,
  value: string,
  provenance: string,
): Artifact | null {
  const text = value.trim();
  if (!text || text === "-" || text.toLowerCase() === "null" || text === "N/A") {
    return null;
  }
  if (type === "username" && /^S-\d-/i.test(text)) {
    return null;
  }
  let normalized = text;
  let scope: ArtifactScope = "public";
  if (type === "ip") {
    if (!looksLikeIpv4(text)) return null;
    normalized = text;
    scope = isPrivateIpv4(text) ? "internal" : "public";
  } else if (type === "hash_sha256" || type === "hash_sha1" || type === "hash_md5") {
    normalized = normalizeHash(text);
  } else if (type === "domain") {
    if (shouldSkipDomain(text)) return null;
    normalized = normalizeDomain(text);
  } else if (type === "url") {
    normalized = text.replace(/[),.;]+$/, "");
  }
  return { type, value: text, normalizedValue: normalized, scope, provenance };
}

export function dedupeArtifacts(items: Artifact[]): Artifact[] {
  const seen = new Set<string>();
  const out: Artifact[] = [];
  for (const item of items) {
    const key = `${item.type}|${item.normalizedValue}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
    if (out.length >= MAX_ARTIFACTS) break;
  }
  return out;
}

function artifactsFromString(text: string, path: string): Artifact[] {
  const found: Artifact[] = [];
  const push = (type: ArtifactType, value: string) => {
    const art = makeArtifact(type, value, path);
    if (art) found.push(art);
  };
  for (const v of matchAll(URL_RE, text)) push("url", v);
  const sha256 = matchAll(SHA256_RE, text);
  for (const v of sha256) push("hash_sha256", v);
  const covered = new Set(sha256.map((h) => h.toLowerCase()));
  for (const v of matchAll(SHA1_RE, text)) {
    if (![...covered].some((h) => h.includes(v.toLowerCase()))) push("hash_sha1", v);
  }
  for (const v of matchAll(MD5_RE, text)) {
    if (![...covered].some((h) => h.includes(v.toLowerCase()))) push("hash_md5", v);
  }
  for (const v of matchAll(IPV4_RE, text)) push("ip", v);
  for (const v of matchAll(DOMAIN_RE, text)) {
    if (!v.includes("://")) push("domain", v);
  }
  return found;
}

const HASH_HINTS = ["sha256", "sha1", "md5", "hash", "checksum", "filehash"];
const IP_HINTS = ["ip", "hostip", "srcip", "dstip", "address"];
const PATH_HINTS = ["path", "filepath", "filename"];
const DOMAIN_HINTS = ["domain", "hostname", "fqdn"];
const URL_HINTS = ["url", "uri"];
const USER_HINTS = ["user", "username", "account"];

function fieldMatches(name: string, hints: string[]): boolean {
  const lower = name.toLowerCase().replace(/[\s_-]/g, "");
  return hints.some((h) => lower.includes(h));
}

export function extractGeneric(data: unknown, basePath = "root"): Artifact[] {
  const out: Artifact[] = [];
  let nodes = 0;

  const walk = (obj: unknown, path: string) => {
    nodes += 1;
    if (nodes > MAX_WALK_NODES || out.length >= MAX_ARTIFACTS) return;
    if (typeof obj === "string") {
      out.push(...artifactsFromString(obj, path));
      return;
    }
    if (Array.isArray(obj)) {
      obj.slice(0, 50).forEach((item, i) => walk(item, `${path}[${i}]`));
      return;
    }
    if (obj && typeof obj === "object") {
      for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        const child = `${path}.${key}`;
        if (typeof value === "string") {
          const text = value.trim();
          if (fieldMatches(key, HASH_HINTS) && /^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/.test(text)) {
            const type: ArtifactType =
              text.length === 64 ? "hash_sha256" : text.length === 40 ? "hash_sha1" : "hash_md5";
            const art = makeArtifact(type, text, child);
            if (art) out.push(art);
          } else if (fieldMatches(key, IP_HINTS)) {
            const art = makeArtifact("ip", text, child);
            if (art) out.push(art);
          } else if (fieldMatches(key, URL_HINTS) && /^https?:\/\//i.test(text)) {
            const art = makeArtifact("url", text, child);
            if (art) out.push(art);
          } else if (fieldMatches(key, DOMAIN_HINTS) && text.includes(".") && !looksLikeIpv4(text)) {
            const art = makeArtifact(
              fieldMatches(key, ["hostname"]) ? "hostname" : "domain",
              text,
              child,
            );
            if (art) out.push(art);
          } else if (fieldMatches(key, PATH_HINTS) && !text.startsWith("http") && text.length > 2) {
            const art = makeArtifact("file_path", text, child);
            if (art) out.push(art);
          } else if (fieldMatches(key, USER_HINTS) && text.length < 80) {
            const art = makeArtifact("username", text, child);
            if (art) out.push(art);
          }
          out.push(...artifactsFromString(text, child));
        } else {
          walk(value, child);
        }
      }
    }
  };

  walk(data, basePath);
  return dedupeArtifacts(out);
}

export function extractFromPlainText(text: string, path = "text"): Artifact[] {
  return dedupeArtifacts(artifactsFromString(text, path));
}
