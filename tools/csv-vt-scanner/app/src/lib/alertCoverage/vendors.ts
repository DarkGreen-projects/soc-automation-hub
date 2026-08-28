import type { CsvLpTable } from "@/lib/csvLp/parseExport";

export type VendorFamily =
  | "fortigate"
  | "agentx"
  | "cynet"
  | "windows"
  | "bitdefender"
  | "defender"
  | "m365"
  | "generic";

export const VENDOR_LABELS: Record<VendorFamily, string> = {
  fortigate: "FortiGate",
  agentx: "AgentX",
  cynet: "Cynet",
  windows: "Windows",
  bitdefender: "Bitdefender",
  defender: "Defender/Graph",
  m365: "Microsoft 365",
  generic: "Generic",
};

function col(row: Record<string, string>, ...names: string[]): string {
  const keys = Object.keys(row);
  for (const name of names) {
    if (row[name]?.trim()) return row[name].trim();
    const found = keys.find((k) => k.toLowerCase() === name.toLowerCase());
    if (found && row[found]?.trim()) return row[found].trim();
  }
  return "";
}

function blob(row: Record<string, string>): string {
  return [
    col(row, "norm_id"),
    col(row, "col_type"),
    col(row, "device_name"),
    col(row, "product"),
    col(row, "event_category", "type"),
    col(row, "sub_category", "subtype"),
    col(row, "label"),
    col(row, "msg"),
    col(row, "title"),
    col(row, "Workload"),
    col(row, "Operation"),
    col(row, "UserId"),
    col(row, "BitdefenderGZDetectionName"),
    col(row, "BitdefenderGZComputerFQDN"),
  ]
    .join(" ")
    .toLowerCase();
}

/** Detect vendor families present in a LogPoint export CSV. */
export function detectVendors(table: CsvLpTable): VendorFamily[] {
  const found = new Set<VendorFamily>();

  for (const row of table.rows) {
    const b = blob(row);
    const eventId = col(row, "event_id", "eventID");

    if (
      /forti|fortios|fortigate/.test(b) ||
      (/utm/.test(b) && /ips|webfilter|app-ctrl|virus|attack/.test(b))
    ) {
      found.add("fortigate");
    }
    if (/agentx/.test(b)) found.add("agentx");
    if (/cynet/.test(b)) found.add("cynet");
    if (
      /bitdefender|gravityzone|bitdefendergz/.test(b) ||
      col(row, "BitdefenderGZDetectionName", "BitdefenderGZComputerFQDN")
    ) {
      found.add("bitdefender");
    }
    if (/microsoftgraph|defender|mde\b/.test(b) && !/bitdefender/.test(b)) {
      found.add("defender");
    }
    if (col(row, "Workload") || col(row, "Operation") || col(row, "UserId") || col(row, "MailboxOwnerUPN")) {
      found.add("m365");
    }
    if (
      /^(4624|4625|4720|4740|1102|7040|4688)$/.test(eventId) ||
      (/windows|security|microsoft-windows/.test(b) && Boolean(eventId))
    ) {
      found.add("windows");
    }
  }

  if (found.size === 0) return ["generic"];
  return [...found].sort();
}

export function vendorsIntersect(
  a: readonly VendorFamily[] | undefined,
  b: readonly VendorFamily[],
): boolean {
  if (!a || a.length === 0 || b.length === 0) return false;
  return a.some((v) => b.includes(v));
}

export function formatVendors(vendors: VendorFamily[]): string {
  return vendors.map((v) => VENDOR_LABELS[v] ?? v).join(", ");
}
