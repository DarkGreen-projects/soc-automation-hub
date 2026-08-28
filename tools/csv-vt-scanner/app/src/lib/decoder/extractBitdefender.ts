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

function str(value: unknown): string | null {
  if (value == null) return null;
  const text = String(value).trim();
  return text || null;
}

export function extractBitdefender(fields: Record<string, unknown>): Artifact[] {
  const out: Artifact[] = [];
  const base = "Bitdefender";
  add(out, "hostname", fields.BitdefenderGZComputerFQDN, `${base}.ComputerFQDN`);
  add(out, "other", fields.BitdefenderGZDetectionName, `${base}.DetectionName`);
  add(out, "ip", fields.src, `${base}.src`);
  add(out, "ip", fields.dvc, `${base}.dvc`);
  add(out, "url", fields.request, `${base}.request`);
  add(out, "file_path", fields.sproc, `${base}.sproc`);
  add(out, "file_path", fields.filePath, `${base}.filePath`);
  add(out, "username", fields.suser, `${base}.suser`);
  const malwareHash = str(fields.BitdefenderGZMalwareHash);
  if (malwareHash) {
    if (/^[A-Fa-f0-9]{64}$/.test(malwareHash)) add(out, "hash_sha256", malwareHash, `${base}.MalwareHash`);
    else if (/^[A-Fa-f0-9]{40}$/.test(malwareHash)) add(out, "hash_sha1", malwareHash, `${base}.MalwareHash`);
    else if (/^[A-Fa-f0-9]{32}$/.test(malwareHash)) add(out, "hash_md5", malwareHash, `${base}.MalwareHash`);
    else add(out, "other", malwareHash, `${base}.MalwareHash`);
  }
  out.push(...extractGeneric(fields, base));
  return out;
}

export function bitdefenderContext(
  fields: Record<string, unknown>,
): Record<string, string | null> {
  return {
    host_name: str(fields.BitdefenderGZComputerFQDN) ?? str(fields.dvchost),
    incident_name: str(fields.BitdefenderGZDetectionName),
    host_ip: str(fields.src) ?? str(fields.dvc),
    file_path: str(fields.filePath) ?? str(fields.sproc),
    url: str(fields.request),
    sha256: str(fields.BitdefenderGZMalwareHash),
    user_name: str(fields.suser),
  };
}
