export type ArtifactType =
  | "ip"
  | "hash_sha256"
  | "hash_sha1"
  | "hash_md5"
  | "domain"
  | "url"
  | "file_path"
  | "hostname"
  | "username"
  | "email_address"
  | "malware_label"
  | "other";

export type ArtifactScope = "public" | "internal";

export type DecodeFormat = "json" | "fortigate" | "cef" | "ioc" | "generic";

export interface Artifact {
  type: ArtifactType;
  value: string;
  normalizedValue: string;
  scope: ArtifactScope;
  provenance: string;
}

export interface DecodeResult {
  format: DecodeFormat;
  vendor: string | null;
  context: Record<string, string | null>;
  artifacts: Artifact[];
  error?: string;
}
