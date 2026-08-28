import {
  findCynetBlock,
  looksLikeCef,
  looksLikeFortigateKv,
  looksLikeIocList,
  looksLikeJson,
  normalizePastedText,
  parseFortigateKv,
  tryParseJson,
  unwrapNestedJsonStrings,
} from "./detect";
import { MAX_WALK_NODES } from "./extractGeneric";
import { looksLikeIpv4 } from "./patterns";
import type { Artifact, DecodeResult } from "./types";

export type FieldKind =
  | "ip"
  | "hash"
  | "url"
  | "domain"
  | "hostname"
  | "username"
  | "path"
  | "email"
  | "nested_json"
  | "empty"
  | "other";

export type JsonType = "string" | "number" | "boolean" | "object" | "array" | "null";

export interface SchemaField {
  path: string;
  jsonType: JsonType;
  kind: FieldKind;
}

export interface ArtifactStat {
  type: string;
  scope: string;
  count: number;
}

export interface SchemaSample {
  fingerprint: string;
  format: string;
  vendor: string | null;
  fields: SchemaField[];
  artifactStats: ArtifactStat[];
  contextKeys: string[];
  seenCount: number;
  lastSeenAt: string;
}

export interface SchemaCatalog {
  samples: SchemaSample[];
}

export const MAX_SCHEMA_FIELDS = 400;
export const MAX_CATALOG_SAMPLES = 500;

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

function lastSegment(path: string): string {
  const parts = path.split(".");
  return (parts[parts.length - 1] ?? path).replace(/\[\*]$/, "");
}

export function inferKind(key: string, value: string): FieldKind {
  const text = value.trim();
  if (!text || text === "-" || text.toLowerCase() === "null" || text === "N/A") {
    return "empty";
  }
  if (looksLikeIpv4(text)) return "ip";
  if (/^[A-Fa-f0-9]{32}$/.test(text) || /^[A-Fa-f0-9]{40}$/.test(text) || /^[A-Fa-f0-9]{64}$/.test(text)) {
    return "hash";
  }
  if (/^https?:\/\//i.test(text)) return "url";
  if (looksLikeJson(text)) return "nested_json";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) return "email";
  if (fieldMatches(key, HASH_HINTS)) return "hash";
  if (fieldMatches(key, IP_HINTS)) return "ip";
  if (fieldMatches(key, URL_HINTS)) return "url";
  if (fieldMatches(key, USER_HINTS)) return "username";
  if (fieldMatches(key, PATH_HINTS) && !text.startsWith("http")) return "path";
  if (fieldMatches(key, ["hostname"]) && text.includes(".")) return "hostname";
  if (fieldMatches(key, DOMAIN_HINTS) && text.includes(".") && !looksLikeIpv4(text)) {
    return "domain";
  }
  return "other";
}

function collectFields(root: unknown, prefix: string): SchemaField[] {
  const byPath = new Map<string, SchemaField>();
  let nodes = 0;

  const add = (path: string, jsonType: JsonType, kind: FieldKind) => {
    if (byPath.size >= MAX_SCHEMA_FIELDS) return;
    const existing = byPath.get(path);
    if (!existing) {
      byPath.set(path, { path, jsonType, kind });
      return;
    }
    if (existing.kind === "other" && kind !== "other") {
      existing.kind = kind;
    }
  };

  const walk = (obj: unknown, path: string) => {
    nodes += 1;
    if (nodes > MAX_WALK_NODES || byPath.size >= MAX_SCHEMA_FIELDS) return;
    if (obj === null || obj === undefined) {
      if (path) add(path, "null", "empty");
      return;
    }
    if (typeof obj === "string") {
      add(path, "string", inferKind(lastSegment(path), obj));
      return;
    }
    if (typeof obj === "number") {
      add(path, "number", "other");
      return;
    }
    if (typeof obj === "boolean") {
      add(path, "boolean", "other");
      return;
    }
    if (Array.isArray(obj)) {
      add(path, "array", "other");
      for (const item of obj.slice(0, 50)) {
        walk(item, `${path}[*]`);
      }
      return;
    }
    if (typeof obj === "object") {
      if (path) add(path, "object", "other");
      for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        const child = path ? `${path}.${key}` : key;
        walk(value, child);
      }
    }
  };

  walk(root, prefix);
  return [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
}

function artifactStats(artifacts: Artifact[]): ArtifactStat[] {
  const counts = new Map<string, ArtifactStat>();
  for (const art of artifacts) {
    const key = `${art.type}|${art.scope}`;
    const current = counts.get(key);
    if (current) {
      current.count += 1;
    } else {
      counts.set(key, { type: art.type, scope: art.scope, count: 1 });
    }
  }
  return [...counts.values()].sort((a, b) =>
    `${a.type}|${a.scope}`.localeCompare(`${b.type}|${b.scope}`),
  );
}

function contextKeysOf(result: DecodeResult): string[] {
  return Object.entries(result.context)
    .filter(([, value]) => Boolean(value && String(value).trim()))
    .map(([key]) => key)
    .sort();
}

export function schemaFingerprint(sample: {
  format: string;
  vendor: string | null;
  fields: SchemaField[];
  contextKeys: string[];
}): string {
  const fieldPart = sample.fields
    .map((f) => `${f.path}|${f.jsonType}|${f.kind}`)
    .sort()
    .join(";");
  const ctx = [...sample.contextKeys].sort().join(",");
  const raw = `${sample.format}|${sample.vendor ?? ""}|${fieldPart}|${ctx}`;
  let hash = 2166136261;
  for (let i = 0; i < raw.length; i += 1) {
    hash ^= raw.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function emptyCatalog(): SchemaCatalog {
  return { samples: [] };
}

export function captureSchema(raw: string, result: DecodeResult): SchemaSample | null {
  const text = normalizePastedText(raw);
  if (!text) return null;

  let fields: SchemaField[] = [];
  const prefix =
    result.vendor && result.vendor !== "generic"
      ? result.vendor
      : result.format === "ioc"
        ? "ioc"
        : looksLikeCef(text) || looksLikeFortigateKv(text)
          ? "FortiGate"
          : "json";

  if (looksLikeJson(text) || text.includes("{")) {
    const parsed = tryParseJson(text);
    if (parsed) {
      const data = unwrapNestedJsonStrings(parsed);
      const cynet = findCynetBlock(data);
      const root = result.vendor === "Cynet" && cynet ? cynet : data;
      fields = collectFields(root, prefix);
    }
  } else if (looksLikeCef(text) || looksLikeFortigateKv(text)) {
    fields = collectFields(parseFortigateKv(text), prefix);
  } else if (looksLikeIocList(text) || result.format === "ioc") {
    const kinds = new Set(result.artifacts.map((a) => a.type));
    fields = [...kinds].sort().map((type) => ({
      path: `ioc.${type}`,
      jsonType: "string" as const,
      kind: type.startsWith("hash")
        ? "hash"
        : type === "ip"
          ? "ip"
          : type === "url"
            ? "url"
            : type === "domain"
              ? "domain"
              : "other",
    }));
  } else if (result.artifacts.length > 0) {
    const kinds = new Set(result.artifacts.map((a) => a.type));
    fields = [...kinds].sort().map((type) => ({
      path: `paste.${type}`,
      jsonType: "string" as const,
      kind: type.startsWith("hash") ? "hash" : type === "ip" ? "ip" : "other",
    }));
  }

  if (fields.length === 0 && result.artifacts.length === 0) return null;

  const base = {
    format: result.format,
    vendor: result.vendor,
    fields,
    contextKeys: contextKeysOf(result),
  };

  return {
    ...base,
    fingerprint: schemaFingerprint(base),
    artifactStats: artifactStats(result.artifacts),
    seenCount: 1,
    lastSeenAt: new Date().toISOString(),
  };
}

export function mergeIntoCatalog(
  catalog: SchemaCatalog | null | undefined,
  sample: SchemaSample,
): SchemaCatalog {
  const next: SchemaCatalog = { samples: [...(catalog?.samples ?? [])] };
  const existing = next.samples.find((s) => s.fingerprint === sample.fingerprint);
  if (existing) {
    existing.seenCount += 1;
    existing.lastSeenAt = sample.lastSeenAt;
    return next;
  }
  next.samples.push(sample);
  if (next.samples.length > MAX_CATALOG_SAMPLES) {
    next.samples.sort((a, b) => a.seenCount - b.seenCount || a.lastSeenAt.localeCompare(b.lastSeenAt));
    next.samples = next.samples.slice(next.samples.length - MAX_CATALOG_SAMPLES);
  }
  return next;
}

export function catalogToJson(catalog: SchemaCatalog): string {
  return JSON.stringify(catalog, null, 2);
}

export function parseCatalogJson(json: string): SchemaCatalog {
  try {
    const parsed = JSON.parse(json) as SchemaCatalog;
    return { samples: Array.isArray(parsed.samples) ? parsed.samples : [] };
  } catch {
    return emptyCatalog();
  }
}

export interface SchemaFieldDef {
  name: string;
  type: "string";
  description: string;
  example: string;
}

/** Unique leaf field names from catalog samples → field defs for optional catalog UI. */
export function schemaFieldsToFieldDefs(catalog: SchemaCatalog): SchemaFieldDef[] {
  const map = new Map<string, { kind: FieldKind; vendors: Set<string> }>();
  for (const sample of catalog.samples) {
    const vendor = sample.vendor ?? "generic";
    for (const f of sample.fields) {
      if (!f.path || f.path.includes("[*]")) continue;
      const leaf = f.path.split(".").pop();
      if (!leaf || leaf.length < 2 || leaf === "json") continue;
      if (f.jsonType === "object" || f.jsonType === "array") continue;
      if (f.kind === "empty" || f.kind === "nested_json") continue;
      const prev = map.get(leaf);
      if (!prev) {
        map.set(leaf, { kind: f.kind, vendors: new Set([vendor]) });
      } else {
        prev.vendors.add(vendor);
        if (f.kind !== "other") prev.kind = f.kind;
      }
    }
  }
  return [...map.entries()]
    .map(([name, info]) => ({
      name,
      type: "string" as const,
      description: `schema: ${[...info.vendors].sort().join(", ")} (${info.kind})`,
      example: "",
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export { emptyCatalog };
