import { IPV4_RE, isPrivateIpv4, looksLikeIpv4, matchAll } from "@/lib/patterns";
import type { CsvIpRow } from "./types";

const HEADER_HINTS = new Set([
  "ip",
  "ip_address",
  "ipaddress",
  "address",
  "src_ip",
  "dst_ip",
  "source_ip",
  "destination_ip",
]);

function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === "," && !inQuotes) {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function looksLikeHeader(firstCell: string): boolean {
  return HEADER_HINTS.has(firstCell.trim().toLowerCase());
}

function makeRow(
  ip: string,
  country: string,
  count: string,
  eventType: string,
): CsvIpRow {
  if (!looksLikeIpv4(ip)) {
    return { ip, country, count, eventType, skipped: true, skipReason: "invalid" };
  }
  if (isPrivateIpv4(ip)) {
    return { ip, country, count, eventType, skipped: true, skipReason: "private" };
  }
  return { ip, country, count, eventType, skipped: false };
}

/** Extract every IPv4 on the line; enrich with CSV cols when structured. */
function rowsFromLine(line: string): CsvIpRow[] {
  const ips = matchAll(IPV4_RE, line);
  if (ips.length === 0) return [];

  const cols = splitCsvLine(line);
  const structuredIp = (cols[0] ?? "").trim();
  const country = (cols[1] ?? "").trim();
  const count = (cols[2] ?? "").trim();
  const eventType = (cols[3] ?? "").trim();
  const isStructured = looksLikeIpv4(structuredIp);

  const out: CsvIpRow[] = [];
  const seenOnLine = new Set<string>();

  for (const raw of ips) {
    const ip = raw.trim();
    if (seenOnLine.has(ip)) continue;
    seenOnLine.add(ip);

    if (isStructured && ip === structuredIp) {
      out.push(makeRow(ip, country, count, eventType));
    } else {
      out.push(makeRow(ip, "", "", ""));
    }
  }
  return out;
}

export interface ParseCsvResult {
  rows: CsvIpRow[];
  /** Unique IPs kept after dedup (including skipped) */
  uniqueCount: number;
  /** Rows discarded as empty / duplicate / header / no IP */
  skippedLines: number;
  hadHeader: boolean;
}

/**
 * Parse LogPoint-style CSV (ip,country,count,event_type) and/or free-text lines:
 * every IPv4 on each line is queued (deduped). Structured first column gets metadata.
 */
export function parseLogpointIpCsv(text: string): ParseCsvResult {
  const lines = text
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length === 0) {
    return { rows: [], uniqueCount: 0, skippedLines: 0, hadHeader: false };
  }

  let start = 0;
  let hadHeader = false;
  const firstCols = splitCsvLine(lines[0]);
  if (looksLikeHeader(firstCols[0] ?? "")) {
    hadHeader = true;
    start = 1;
  }

  const seen = new Set<string>();
  const rows: CsvIpRow[] = [];
  let skippedLines = hadHeader ? 1 : 0;

  for (let i = start; i < lines.length; i += 1) {
    const extracted = rowsFromLine(lines[i]);
    if (extracted.length === 0) {
      skippedLines += 1;
      continue;
    }
    let added = 0;
    for (const row of extracted) {
      if (seen.has(row.ip)) continue;
      seen.add(row.ip);
      rows.push(row);
      added += 1;
    }
    if (added === 0) skippedLines += 1;
  }

  return {
    rows,
    uniqueCount: rows.length,
    skippedLines,
    hadHeader,
  };
}

/** Rows that will be sent to VirusTotal */
export function scannableRows(rows: CsvIpRow[]): CsvIpRow[] {
  return rows.filter((r) => !r.skipped);
}
