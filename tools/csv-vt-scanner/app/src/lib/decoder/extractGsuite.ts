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

export function extractGsuite(block: Record<string, unknown>): Artifact[] {
  const out: Artifact[] = [];
  const base = "GSuite";
  const actor = block.actor && typeof block.actor === "object" ? (block.actor as Record<string, unknown>) : {};
  add(out, "email_address", actor.email, `${base}.actor.email`);
  add(out, "ip", block.ipAddress, `${base}.ipAddress`);
  out.push(...extractGeneric(block, base));
  return out;
}

export function gsuiteContext(block: Record<string, unknown>): Record<string, string | null> {
  const actor = block.actor && typeof block.actor === "object" ? (block.actor as Record<string, unknown>) : {};
  const id = block.id && typeof block.id === "object" ? (block.id as Record<string, unknown>) : {};
  let event_name: string | null = null;
  if (Array.isArray(block.events)) {
    const first = block.events[0];
    if (first && typeof first === "object") {
      event_name = str((first as Record<string, unknown>).name);
    }
  }
  return {
    user_name: str(actor.email),
    host_ip: str(block.ipAddress),
    application: str(id.applicationName),
    incident_name: event_name,
  };
}
