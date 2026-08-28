/**
 * Curated LogPoint / vendor field aliases derived from schema-catalog samples
 * (FortiGate, AgentX, M365, Bitdefender, Defender/Graph, GSuite).
 * Leaf names only — no nested JSON paths or [*] wildcards.
 */

export const IP_FIELDS = [
  "source_address",
  "destination_address",
  "device_ip",
  "srcip",
  "dstip",
  "src",
  "dst",
  "ClientIP",
  "ClientIPAddress",
  "ActorIpAddress",
  "ipAddress",
  "ip",
  "transip",
  "tranip",
  "dvc",
  "FTNTFGTsrcip",
  "FTNTFGTdstip",
] as const;

/** FortiGate-focused IP fields (norm + raw CEF/KV). */
export const FORTIGATE_IP_FIELDS = [
  "source_address",
  "destination_address",
  "srcip",
  "dstip",
  "src",
  "dst",
  "transip",
  "FTNTFGTsrcip",
  "FTNTFGTdstip",
] as const;

export const HASH_FIELDS = [
  "hash",
  "file_hash",
  "sha256",
  "sha1",
  "md5",
  "checksum",
  "BitdefenderGZMalwareHash",
] as const;

export const DOMAIN_FIELDS = [
  "domain",
  "hostname",
  "url",
  "targetDomainName",
] as const;

export const URL_FIELDS = [
  "url",
  "request",
  "ObjectId",
  "SiteUrl",
  "SourceRelativeUrl",
  "FilePathUrl",
] as const;

export const HOSTNAME_FIELDS = [
  "hostname",
  "computer",
  "device_name",
  "BitdefenderGZComputerFQDN",
  "fqdn",
  "dvchost",
  "shost",
  "dhost",
] as const;

export const USER_FIELDS = [
  "user",
  "UserId",
  "suser",
  "duser",
  "targetUserName",
  "subjectUserName",
  "parentUser",
  "unauthuser",
  "FTNTFGTdstuser",
] as const;

export const EMAIL_FIELDS = [
  "user",
  "UserId",
  "user_principal_name",
  "email",
  "MailboxOwnerUPN",
  "UserKey",
  "actor",
] as const;

export const PATH_FIELDS = [
  "file_path",
  "path",
  "filePath",
  "SourceFileName",
  "originalFileName",
  "FileName",
  "process_name",
  "processName",
  "sproc",
] as const;

/** Build `field = "value" OR …` (exact match). */
export function equalsAny(fields: readonly string[], value: string): string {
  return fields.map((f) => `${f} = "${value}"`).join(" OR ");
}

/** Build `field = "*value*" OR …` (substring / contains). */
export function containsAny(fields: readonly string[], value: string): string {
  return fields.map((f) => `${f} = "*${value}*"`).join(" OR ");
}

export function fortigateIpClause(ip: string): string {
  return equalsAny(FORTIGATE_IP_FIELDS, ip);
}
