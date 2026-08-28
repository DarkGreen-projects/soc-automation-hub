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

function eventdata(block: Record<string, unknown>): Record<string, unknown> {
  const full = block.full_log;
  if (!full || typeof full !== "object") return {};
  const win = (full as Record<string, unknown>).win;
  if (!win || typeof win !== "object") return {};
  const data = (win as Record<string, unknown>).eventdata;
  return data && typeof data === "object" ? (data as Record<string, unknown>) : {};
}

function system(block: Record<string, unknown>): Record<string, unknown> {
  const full = block.full_log;
  if (!full || typeof full !== "object") return {};
  const win = (full as Record<string, unknown>).win;
  if (!win || typeof win !== "object") return {};
  const sys = (win as Record<string, unknown>).system;
  return sys && typeof sys === "object" ? (sys as Record<string, unknown>) : {};
}

function parseHashBlob(text: string, provenance: string): Artifact[] {
  const out: Artifact[] = [];
  const sha256 = text.match(/SHA256[=:]([A-Fa-f0-9]{64})/i);
  const sha1 = text.match(/SHA1[=:]([A-Fa-f0-9]{40})/i);
  const md5 = text.match(/MD5[=:]([A-Fa-f0-9]{32})/i);
  if (sha256?.[1]) add(out, "hash_sha256", sha256[1], provenance);
  if (sha1?.[1]) add(out, "hash_sha1", sha1[1], provenance);
  if (md5?.[1]) add(out, "hash_md5", md5[1], provenance);
  return out;
}

export function extractAgentX(block: Record<string, unknown>): Artifact[] {
  const out: Artifact[] = [];
  const base = "AgentX";
  const agent = block.agent && typeof block.agent === "object" ? (block.agent as Record<string, unknown>) : {};
  const ev = eventdata(block);
  const sys = system(block);
  add(out, "ip", agent.ip, `${base}.agent.ip`);
  add(out, "ip", ev.ipAddress, `${base}.ipAddress`);
  add(out, "hostname", agent.name, `${base}.agent.name`);
  add(out, "hostname", sys.computer, `${base}.computer`);
  add(out, "hostname", ev.workstation, `${base}.workstation`);
  add(out, "username", ev.user, `${base}.user`);
  add(out, "username", ev.targetUserName, `${base}.targetUserName`);
  add(out, "username", ev.subjectUserName, `${base}.subjectUserName`);
  add(out, "username", ev.parentUser, `${base}.parentUser`);
  add(out, "file_path", ev.image, `${base}.image`);
  add(out, "file_path", ev.newProcessName, `${base}.newProcessName`);
  add(out, "file_path", ev.processName, `${base}.processName`);
  add(out, "file_path", ev.parentImage, `${base}.parentImage`);
  add(out, "file_path", ev.parentProcessName, `${base}.parentProcessName`);
  add(out, "file_path", ev.originalFileName, `${base}.originalFileName`);
  add(out, "other", ev.commandLine, `${base}.commandLine`);
  if (typeof ev.hashes === "string") {
    out.push(...parseHashBlob(ev.hashes, `${base}.hashes`));
  }
  out.push(...extractGeneric(block, base));
  return out;
}

export function agentxContext(block: Record<string, unknown>): Record<string, string | null> {
  const agent = block.agent && typeof block.agent === "object" ? (block.agent as Record<string, unknown>) : {};
  const ev = eventdata(block);
  const sys = system(block);
  const hashes = typeof ev.hashes === "string" ? ev.hashes : "";
  const sha256 = hashes.match(/SHA256[=:]([A-Fa-f0-9]{64})/i)?.[1] ?? null;
  return {
    host_name: str(sys.computer) ?? str(agent.name) ?? str(ev.workstation),
    host_ip: str(ev.ipAddress) ?? str(agent.ip),
    user_name: str(ev.user) ?? str(ev.targetUserName) ?? str(ev.subjectUserName),
    file_path: str(ev.image) ?? str(ev.newProcessName) ?? str(ev.processName),
    sha256,
    command_line: str(ev.commandLine),
    parent_image: str(ev.parentImage) ?? str(ev.parentProcessName),
  };
}
