import type { Allowlist } from "@/lib/allowlist";
import { applyAllowlistToQuery } from "@/lib/allowlist";
import { queryForArtifact } from "@/lib/decoder/pipeline";
import { makeArtifact } from "@/lib/decoder/extractGeneric";
import { looksLikeIpv4 } from "@/lib/decoder/patterns";

function quote(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

const IP_COLUMNS = new Set([
  "source_address",
  "destination_address",
  "device_ip",
  "srcip",
  "dstip",
  "src",
  "dst",
  "clientip",
  "clientipaddress",
  "actoripaddress",
  "ip",
  "ipaddress",
]);

const HASH_COLUMNS = new Set(["sha256", "sha1", "md5", "hash", "file_hash", "bitdefendergzmalwarehash"]);
const USER_COLUMNS = new Set(["user", "userid", "mailboxownerupn", "suser", "duser", "email"]);
const HOST_COLUMNS = new Set(["hostname", "computer", "device_name", "fqdn", "bitdefendergzcomputerfqdn"]);

export function pivotQueryForCell(
  column: string,
  value: string,
  allowlist?: Allowlist | null,
): string {
  const v = value.trim();
  if (!v) return "";
  const colLower = column.toLowerCase();

  let query: string;

  if (IP_COLUMNS.has(colLower) || looksLikeIpv4(v)) {
    const art = makeArtifact("ip", v, `csvLp.${column}`);
    query = art ? queryForArtifact(art) : `${column} = "${quote(v)}"`;
  } else if (HASH_COLUMNS.has(colLower) || /^[A-Fa-f0-9]{32}$/.test(v) || /^[A-Fa-f0-9]{40}$/.test(v) || /^[A-Fa-f0-9]{64}$/.test(v)) {
    const type =
      v.length === 64 ? "hash_sha256" : v.length === 40 ? "hash_sha1" : "hash_md5";
    const art = makeArtifact(type, v, `csvLp.${column}`);
    query = art ? queryForArtifact(art) : `${column} = "${quote(v)}"`;
  } else if (USER_COLUMNS.has(colLower)) {
    const art = makeArtifact(v.includes("@") ? "email_address" : "username", v, `csvLp.${column}`);
    query = art ? queryForArtifact(art) : `${column} = "${quote(v)}"`;
  } else if (HOST_COLUMNS.has(colLower)) {
    const art = makeArtifact("hostname", v, `csvLp.${column}`);
    query = art ? queryForArtifact(art) : `${column} = "${quote(v)}"`;
  } else if (colLower === "url" || /^https?:\/\//i.test(v)) {
    const art = makeArtifact("url", v, `csvLp.${column}`);
    query = art ? queryForArtifact(art) : `${column} = "${quote(v)}"`;
  } else if (colLower === "domain") {
    const art = makeArtifact("domain", v, `csvLp.${column}`);
    query = art ? queryForArtifact(art) : `${column} = "${quote(v)}"`;
  } else {
    query = `${column} = "${quote(v)}"`;
  }

  return allowlist ? applyAllowlistToQuery(query, allowlist) : query;
}
