import { looksLikeIpv4, isPrivateIpv4 } from "@/lib/decoder/patterns";

export type BulkIocKind =
  | "ip"
  | "hash_sha256"
  | "hash_sha1"
  | "hash_md5"
  | "domain"
  | "url";

export interface BulkIocRow {
  value: string;
  kind: BulkIocKind;
  skipped: boolean;
  skipReason?: "private" | "invalid" | "unsupported";
  line: number;
}

function classifyToken(token: string): BulkIocKind | null {
  const t = token.trim();
  if (!t) return null;
  if (/^https?:\/\//i.test(t)) return "url";
  if (looksLikeIpv4(t)) return "ip";
  if (/^[A-Fa-f0-9]{64}$/.test(t)) return "hash_sha256";
  if (/^[A-Fa-f0-9]{40}$/.test(t)) return "hash_sha1";
  if (/^[A-Fa-f0-9]{32}$/.test(t)) return "hash_md5";
  if (/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(t)) return "domain";
  return null;
}

/** Parse free-text / CSV-ish IOC list into typed rows (deduped). */
export function parseBulkIocs(text: string): BulkIocRow[] {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const out: BulkIocRow[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    const tokens = line.split(/[\s,;|]+/).map((t) => t.trim()).filter(Boolean);
    for (const token of tokens) {
      const kind = classifyToken(token);
      if (!kind) {
        const key = `invalid|${token.toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          value: token,
          kind: "ip",
          skipped: true,
          skipReason: "invalid",
          line: i + 1,
        });
        continue;
      }
      const key = `${kind}|${token.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);

      if (kind === "ip" && isPrivateIpv4(token)) {
        out.push({
          value: token,
          kind,
          skipped: true,
          skipReason: "private",
          line: i + 1,
        });
        continue;
      }

      out.push({ value: token, kind, skipped: false, line: i + 1 });
    }
  }

  return out;
}
