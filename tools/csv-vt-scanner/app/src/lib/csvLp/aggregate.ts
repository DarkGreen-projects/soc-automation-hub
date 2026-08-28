import type { CsvLpTable } from "./parseExport";

export interface TopValue {
  value: string;
  count: number;
}

export interface TimeBucket {
  bucket: string;
  count: number;
}

export function topByColumn(
  table: CsvLpTable,
  column: string,
  limit = 25,
): TopValue[] {
  const counts = new Map<string, number>();
  for (const row of table.rows) {
    const raw = (row[column] ?? "").trim();
    if (!raw) continue;
    counts.set(raw, (counts.get(raw) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, limit);
}

/** Coarse hourly buckets from log_ts-like strings. */
export function timeBuckets(table: CsvLpTable, column: string, limit = 48): TimeBucket[] {
  const counts = new Map<string, number>();
  for (const row of table.rows) {
    const raw = (row[column] ?? "").trim();
    if (!raw) continue;
    const d = new Date(raw);
    let key: string;
    if (!Number.isNaN(d.getTime())) {
      const y = d.getUTCFullYear();
      const m = String(d.getUTCMonth() + 1).padStart(2, "0");
      const day = String(d.getUTCDate()).padStart(2, "0");
      const h = String(d.getUTCHours()).padStart(2, "0");
      key = `${y}-${m}-${day} ${h}:00Z`;
    } else {
      key = raw.slice(0, 13);
    }
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([bucket, count]) => ({ bucket, count }))
    .sort((a, b) => a.bucket.localeCompare(b.bucket))
    .slice(0, limit);
}

export function buildSummaryCsv(
  _column: string,
  tops: TopValue[],
): string {
  const lines = ["value,count"];
  for (const t of tops) {
    const v = /[",\r\n]/.test(t.value) ? `"${t.value.replace(/"/g, '""')}"` : t.value;
    lines.push(`${v},${t.count}`);
  }
  return lines.join("\r\n") + "\r\n";
}
