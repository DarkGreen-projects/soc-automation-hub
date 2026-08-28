import { extractGeneric, makeArtifact } from "./extractGeneric";
import type { Artifact } from "./types";

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

export function extractCynet(block: Record<string, unknown>): Artifact[] {
  const out: Artifact[] = [];
  const base = "Cynet";
  add(out, "ip", block.HostIp, `${base}.HostIp`);
  add(out, "hash_sha256", block.Sha256Hex, `${base}.Sha256Hex`);
  add(out, "file_path", block.Path, `${base}.Path`);
  add(out, "hostname", block.HostName, `${base}.HostName`);
  add(out, "username", block.UserName, `${base}.UserName`);
  add(out, "domain", block.AlertDomain, `${base}.AlertDomain`);
  add(out, "url", block.AlertUrl, `${base}.AlertUrl`);

  const desc = block.IncidentDescription;
  if (typeof desc === "string") {
    out.push(...extractGeneric(desc, `${base}.IncidentDescription`));
  }
  const nested = block.IncidentJsonDescription;
  if (nested && typeof nested === "object") {
    out.push(...extractGeneric(nested, `${base}.IncidentJsonDescription`));
  } else if (typeof nested === "string") {
    out.push(...extractGeneric(nested, `${base}.IncidentJsonDescription`));
  }
  out.push(...extractGeneric(block, base));
  return out;
}

export function cynetContext(block: Record<string, unknown>): Record<string, string | null> {
  return {
    incident_name: str(block.IncidentName),
    host_name: str(block.HostName),
    host_ip: str(block.HostIp),
    user_name: str(block.UserName),
    severity: str(block.Severity),
    file_path: str(block.Path),
    sha256: str(block.Sha256Hex),
  };
}

function str(value: unknown): string | null {
  if (value == null) return null;
  const text = String(value).trim();
  return text || null;
}
