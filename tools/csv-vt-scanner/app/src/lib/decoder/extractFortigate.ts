import { extractGeneric, makeArtifact } from "./extractGeneric";
import { looksLikeIpv4 } from "./patterns";
import type { Artifact } from "./types";

const IP_KEYS = [
  "srcip",
  "dstip",
  "src",
  "dst",
  "FTNTFGTsrcip",
  "FTNTFGTdstip",
  "source_address",
  "destination_address",
];
const HOST_KEYS = ["hostname", "devname", "FTNTFGThostname", "shost", "dhost", "dvchost"];
const URL_KEYS = ["url", "FTNTFGTurl", "request"];
const DOMAIN_KEYS = ["domain", "FTNTFGTdomain"];
const USER_KEYS = ["user", "duser", "FTNTFGTdstuser", "suser"];

function add(
  out: Artifact[],
  type: Artifact["type"],
  value: unknown,
  provenance: string,
) {
  if (value == null) return;
  const art = makeArtifact(type, String(value), provenance);
  if (art) out.push(art);
}

export function extractFortigate(fields: Record<string, unknown>): Artifact[] {
  const out: Artifact[] = [];
  const base = "FortiGate";
  for (const key of IP_KEYS) {
    add(out, "ip", fields[key], `${base}.${key}`);
  }
  for (const key of HOST_KEYS) {
    const val = fields[key];
    if (typeof val === "string" && looksLikeIpv4(val)) {
      add(out, "ip", val, `${base}.${key}`);
    } else {
      add(out, "hostname", val, `${base}.${key}`);
    }
  }
  for (const key of URL_KEYS) add(out, "url", fields[key], `${base}.${key}`);
  for (const key of DOMAIN_KEYS) add(out, "domain", fields[key], `${base}.${key}`);
  for (const key of USER_KEYS) add(out, "username", fields[key], `${base}.${key}`);
  add(out, "other", fields.attack, `${base}.attack`);
  add(out, "other", fields.msg, `${base}.msg`);
  out.push(...extractGeneric(fields, base));
  return out;
}

export function fortigateContext(
  fields: Record<string, unknown>,
): Record<string, string | null> {
  return {
    incident_name: str(fields.attack) ?? str(fields.msg),
    host_name:
      str(fields.devname) ??
      str(fields.hostname) ??
      str(fields.shost) ??
      str(fields.dhost) ??
      str(fields.dvchost),
    severity: str(fields.log_severity) ?? str(fields.severity) ?? str(fields.level) ?? str(fields.FTNTFGTlevel),
    action: str(fields.action) ?? str(fields.act),
    subtype: str(fields.subtype) ?? str(fields.sub_category) ?? str(fields.FTNTFGTsubtype),
    srcip:
      str(fields.srcip) ??
      str(fields.source_address) ??
      str(fields.FTNTFGTsrcip) ??
      str(fields.src),
    dstip:
      str(fields.dstip) ??
      str(fields.destination_address) ??
      str(fields.FTNTFGTdstip) ??
      str(fields.dst),
    url: str(fields.url) ?? str(fields.FTNTFGTurl) ?? str(fields.request),
    user: str(fields.user) ?? str(fields.duser) ?? str(fields.suser) ?? str(fields.FTNTFGTdstuser),
    app: str(fields.app) ?? str(fields.application) ?? str(fields.FTNTFGTapp),
    appcat: str(fields.appcat) ?? str(fields.FTNTFGTappcat),
    service: str(fields.service),
    direction: cefDirection(fields.direction) ?? cefDirection(fields.deviceDirection),
  };
}

function cefDirection(value: unknown): string | null {
  const text = str(value);
  if (!text) return null;
  if (text === "0") return "incoming";
  if (text === "1") return "outgoing";
  return text;
}

function str(value: unknown): string | null {
  if (value == null) return null;
  const text = String(value).trim();
  return text || null;
}
