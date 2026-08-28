export interface CsvLpTable {
  headers: string[];
  rows: Record<string, string>[];
  delimiter: "," | ";";
  rowCount: number;
}

const KNOWN_COLS = [
  "source_address",
  "destination_address",
  "device_ip",
  "srcip",
  "dstip",
  "user",
  "UserId",
  "hostname",
  "computer",
  "action",
  "label",
  "log_ts",
  "msg",
  "url",
  "domain",
  "sha256",
  "process_name",
  "file_path",
  "severity",
  "log_severity",
  "col_type",
  "device_name",
  "norm_id",
  "ClientIP",
  "Operation",
  "Workload",
];

function splitCsvLine(line: string, delimiter: "," | ";"): string[] {
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
    if (ch === delimiter && !inQuotes) {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function detectDelimiter(headerLine: string): "," | ";" {
  let commas = 0;
  let semis = 0;
  let inQuotes = false;
  for (let i = 0; i < headerLine.length; i += 1) {
    const ch = headerLine[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (inQuotes) continue;
    if (ch === ",") commas += 1;
    if (ch === ";") semis += 1;
  }
  return semis > commas ? ";" : ",";
}

function normalizeHeader(name: string): string {
  return name.replace(/^\uFEFF/, "").trim();
}

/** Parse LogPoint Search export / generic CSV with header row. */
export function parseLogpointExport(text: string): CsvLpTable {
  const lines = text
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .split("\n")
    .filter((l) => l.trim().length > 0);
  if (lines.length === 0) {
    return { headers: [], rows: [], delimiter: ",", rowCount: 0 };
  }

  const delimiter = detectDelimiter(lines[0]);
  const headers = splitCsvLine(lines[0], delimiter).map(normalizeHeader);
  const rows: Record<string, string>[] = [];

  for (let i = 1; i < lines.length; i += 1) {
    const cols = splitCsvLine(lines[i], delimiter);
    const row: Record<string, string> = {};
    for (let c = 0; c < headers.length; c += 1) {
      row[headers[c]] = (cols[c] ?? "").trim();
    }
    rows.push(row);
  }

  return { headers, rows, delimiter, rowCount: rows.length };
}

export function preferredColumns(headers: string[]): string[] {
  const set = new Set(headers.map((h) => h.toLowerCase()));
  const preferred = KNOWN_COLS.filter((k) =>
    headers.some((h) => h === k || h.toLowerCase() === k.toLowerCase()),
  );
  const rest = headers.filter(
    (h) => !preferred.some((p) => p.toLowerCase() === h.toLowerCase()),
  );
  void set;
  return [...preferred, ...rest];
}

export function resolveColumn(headers: string[], wanted: string): string | null {
  const exact = headers.find((h) => h === wanted);
  if (exact) return exact;
  const ci = headers.find((h) => h.toLowerCase() === wanted.toLowerCase());
  return ci ?? null;
}
