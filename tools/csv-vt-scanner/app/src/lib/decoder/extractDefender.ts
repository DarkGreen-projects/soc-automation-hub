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

function walkEvidence(evidence: unknown, visit: (item: Record<string, unknown>) => void) {
  if (!Array.isArray(evidence)) return;
  for (const item of evidence) {
    if (item && typeof item === "object") visit(item as Record<string, unknown>);
  }
}

export function extractDefender(block: Record<string, unknown>): Artifact[] {
  const out: Artifact[] = [];
  const base = "Defender";
  walkEvidence(block.evidence, (item) => {
    add(out, "hostname", item.hostName, `${base}.hostName`);
    add(out, "hostname", item.deviceDnsName, `${base}.deviceDnsName`);
    add(out, "ip", item.lastIpAddress, `${base}.lastIpAddress`);
    add(out, "ip", item.lastExternalIpAddress, `${base}.lastExternalIpAddress`);
    if (Array.isArray(item.ipInterfaces)) {
      for (const ip of item.ipInterfaces) add(out, "ip", ip, `${base}.ipInterfaces`);
    }
    const image = item.imageFile;
    if (image && typeof image === "object") {
      const file = image as Record<string, unknown>;
      add(out, "hash_sha256", file.sha256, `${base}.imageFile.sha256`);
      add(out, "hash_sha1", file.sha1, `${base}.imageFile.sha1`);
      add(out, "hash_md5", file.md5, `${base}.imageFile.md5`);
      add(out, "file_path", file.filePath, `${base}.imageFile.filePath`);
      add(out, "file_path", file.fileName, `${base}.imageFile.fileName`);
    }
    const parent = item.parentProcessImageFile;
    if (parent && typeof parent === "object") {
      const file = parent as Record<string, unknown>;
      add(out, "hash_sha256", file.sha256, `${base}.parentProcessImageFile.sha256`);
      add(out, "file_path", file.filePath, `${base}.parentProcessImageFile.filePath`);
      add(out, "file_path", file.fileName, `${base}.parentProcessImageFile.fileName`);
    }
    if (Array.isArray(item.loggedOnUsers)) {
      for (const logged of item.loggedOnUsers) {
        if (logged && typeof logged === "object") {
          const user = logged as Record<string, unknown>;
          add(out, "username", user.accountName, `${base}.loggedOnUsers`);
        }
      }
    }
    const account = item.userAccount;
    if (account && typeof account === "object") {
      const user = account as Record<string, unknown>;
      add(out, "username", user.accountName, `${base}.accountName`);
      add(out, "email_address", user.userPrincipalName, `${base}.userPrincipalName`);
    }
    add(out, "other", item.processCommandLine, `${base}.processCommandLine`);
  });
  out.push(...extractGeneric(block, base));
  return out;
}

export function defenderContext(block: Record<string, unknown>): Record<string, string | null> {
  let host_name: string | null = null;
  let host_ip: string | null = null;
  let external_ip: string | null = null;
  let user_name: string | null = null;
  let sha256: string | null = null;
  let file_path: string | null = null;
  let command_line: string | null = null;
  walkEvidence(block.evidence, (item) => {
    host_name = host_name ?? str(item.hostName) ?? str(item.deviceDnsName);
    host_ip = host_ip ?? str(item.lastIpAddress);
    external_ip = external_ip ?? str(item.lastExternalIpAddress);
    command_line = command_line ?? str(item.processCommandLine);
    const image = item.imageFile;
    if (image && typeof image === "object") {
      const file = image as Record<string, unknown>;
      sha256 = sha256 ?? str(file.sha256);
      file_path = file_path ?? str(file.filePath) ?? str(file.fileName);
    }
    const account = item.userAccount;
    if (account && typeof account === "object") {
      const user = account as Record<string, unknown>;
      user_name = user_name ?? str(user.userPrincipalName) ?? str(user.accountName);
    }
  });
  return {
    incident_name: str(block.title),
    host_name,
    host_ip,
    external_ip,
    user_name,
    sha256,
    file_path,
    command_line,
  };
}
