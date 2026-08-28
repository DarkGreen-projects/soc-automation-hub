import type { VtLookupResult } from "@/lib/osint";

export interface CsvIpRow {
  ip: string;
  country: string;
  count: string;
  eventType: string;
  /** True if private/reserved or not a valid IPv4 */
  skipped: boolean;
  skipReason?: "private" | "invalid";
}

export type ScanCategory =
  | "malicious"
  | "clean"
  | "not_found"
  | "error"
  | "skipped"
  | "pending";

export interface ScanRowResult extends CsvIpRow {
  category: ScanCategory;
  vt?: VtLookupResult;
  error?: string;
}

export interface ScanStats {
  total: number;
  malicious: number;
  clean: number;
  notFound: number;
  error: number;
  skipped: number;
  pending: number;
  done: number;
}

export interface ScanStatsPercents {
  malicious: number;
  clean: number;
  notFound: number;
  error: number;
  skipped: number;
}
