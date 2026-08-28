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

function firstActorId(block: Record<string, unknown>): string | null {
  if (!Array.isArray(block.Actor)) return null;
  for (const item of block.Actor) {
    if (item && typeof item === "object") {
      const id = str((item as Record<string, unknown>).ID);
      if (id) return id;
    }
  }
  return null;
}

export function extractM365(block: Record<string, unknown>): Artifact[] {
  const out: Artifact[] = [];
  const base = "Microsoft365";
  const userId = str(block.UserId);
  if (userId?.includes("@")) add(out, "email_address", userId, `${base}.UserId`);
  else add(out, "username", userId, `${base}.UserId`);
  add(out, "ip", block.ClientIP, `${base}.ClientIP`);
  add(out, "ip", block.ClientIPAddress, `${base}.ClientIPAddress`);
  add(out, "ip", block.ActorIpAddress, `${base}.ActorIpAddress`);
  add(out, "other", block.Operation, `${base}.Operation`);
  add(out, "file_path", block.SourceFileName, `${base}.SourceFileName`);
  add(out, "file_path", block.FileName, `${base}.FileName`);
  const mailboxUpn = str(block.MailboxOwnerUPN);
  if (mailboxUpn?.includes("@")) add(out, "email_address", mailboxUpn, `${base}.MailboxOwnerUPN`);
  else if (mailboxUpn) add(out, "username", mailboxUpn, `${base}.MailboxOwnerUPN`);
  if (typeof block.ObjectId === "string" && /^https?:\/\//i.test(block.ObjectId.trim())) {
    add(out, "url", block.ObjectId, `${base}.ObjectId`);
  }
  const actor = firstActorId(block);
  if (actor) {
    if (actor.includes("@")) add(out, "email_address", actor, `${base}.Actor`);
    else add(out, "username", actor, `${base}.Actor`);
  }
  out.push(...extractGeneric(block, base));
  return out;
}

export function m365Context(block: Record<string, unknown>): Record<string, string | null> {
  return {
    user_name: str(block.UserId) ?? str(block.MailboxOwnerUPN) ?? firstActorId(block),
    operation: str(block.Operation),
    workload: str(block.Workload),
    incident_name: str(block.Operation),
    host_ip: str(block.ClientIP) ?? str(block.ClientIPAddress) ?? str(block.ActorIpAddress),
    file_path: str(block.SourceFileName) ?? str(block.FileName),
  };
}
