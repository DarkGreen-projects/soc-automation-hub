export const SHA256_RE = /\b[A-Fa-f0-9]{64}\b/g;
export const SHA1_RE = /\b[A-Fa-f0-9]{40}\b/g;
export const MD5_RE = /\b[A-Fa-f0-9]{32}\b/g;
export const IPV4_RE =
  /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
export const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
export const DOMAIN_RE =
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;

const DOMAIN_SKIP = new Set([
  "json",
  "exe",
  "dll",
  "pdf",
  "png",
  "jpg",
  "gif",
  "css",
  "html",
  "txt",
  "log",
  "xml",
  "com",
]);

export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

export function looksLikeIpv4(value: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(
    value.trim(),
  );
}

export function normalizeHash(value: string): string {
  return value.trim().toLowerCase();
}

export function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

export function shouldSkipDomain(value: string): boolean {
  const lower = normalizeDomain(value);
  const tld = lower.split(".").pop() ?? "";
  if (DOMAIN_SKIP.has(tld)) return true;
  if (looksLikeIpv4(lower)) return true;
  return false;
}

export function matchAll(re: RegExp, text: string): string[] {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  const copy = new RegExp(re.source, flags);
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = copy.exec(text))) {
    out.push(m[0]);
  }
  return out;
}
