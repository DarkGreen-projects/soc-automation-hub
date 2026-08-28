import type { AlertSeverity, CoveredTechnique } from "./parseTechniques";
import type { VendorFamily } from "./vendors";

export interface SignalRule {
  id: string;
  label: string;
  /** Techniques this signal suggests may be in play */
  techniques: string[];
  severity: AlertSeverity;
  /** Vendor families this signal belongs to */
  vendors: VendorFamily[];
  /** Return true if the CSV row matches */
  match: (row: Record<string, string>) => boolean;
}

function col(row: Record<string, string>, ...names: string[]): string {
  const keys = Object.keys(row);
  for (const name of names) {
    const exact = row[name];
    if (exact != null && String(exact).trim()) return String(exact).trim();
    const found = keys.find((k) => k.toLowerCase() === name.toLowerCase());
    if (found && row[found]?.trim()) return row[found].trim();
  }
  return "";
}

function includesAny(text: string, needles: string[]): boolean {
  const t = text.toLowerCase();
  return needles.some((n) => t.includes(n.toLowerCase()));
}

/** Curated LogPoint row → MITRE signal map (Guardsix-oriented). */
export const SIGNAL_RULES: SignalRule[] = [
  {
    id: "fg-ips-pass",
    label: "FortiGate IPS detected/pass",
    techniques: ["T1190", "T1046"],
    severity: "critical",
    vendors: ["fortigate"],
    match: (row) => {
      const sub = col(row, "sub_category", "subtype", "FTNTFGTsubtype");
      const action = col(row, "action", "act");
      const norm = col(row, "norm_id", "device_name", "col_type");
      const looksFg =
        /forti/i.test(norm) ||
        col(row, "srcip", "dstip") !== "" ||
        /utm/i.test(col(row, "event_category", "type"));
      return (
        looksFg &&
        /ips/i.test(sub) &&
        /^(detected|pass|allow)$/i.test(action)
      );
    },
  },
  {
    id: "fg-webfilter-malicious",
    label: "FortiGate webfilter malicious/spam/NOD",
    techniques: ["T1189", "T1071.001"],
    severity: "high",
    vendors: ["fortigate"],
    match: (row) => {
      const sub = col(row, "sub_category", "subtype");
      const cat = col(row, "category", "cat");
      const action = col(row, "action", "act");
      return (
        /webfilter/i.test(sub) &&
        /block/i.test(action) &&
        includesAny(cat, [
          "Malicious Websites",
          "Spam URLs",
          "Newly Observed Domain",
        ])
      );
    },
  },
  {
    id: "fg-proxy-avoidance",
    label: "FortiGate Proxy Avoidance / remote access category",
    techniques: ["T1090", "T1219"],
    severity: "medium",
    vendors: ["fortigate"],
    match: (row) => {
      const cat = col(row, "category", "cat", "app", "application");
      return includesAny(cat, [
        "Proxy Avoidance",
        "Proxy",
        "Remote Access",
        "TeamViewer",
        "AnyDesk",
      ]);
    },
  },
  {
    id: "auth-bruteforce",
    label: "Login failed / 4625",
    techniques: ["T1110", "T1110.001"],
    severity: "high",
    vendors: ["windows"],
    match: (row) => {
      const label = col(row, "label", "event_name", "msg");
      const eventId = col(row, "event_id", "eventID");
      return (
        eventId === "4625" ||
        includesAny(label, ["login failed", "authentication failure", "4625"])
      );
    },
  },
  {
    id: "account-create",
    label: "Local account create (4720 / T1136)",
    techniques: ["T1136.001"],
    severity: "high",
    vendors: ["windows"],
    match: (row) => {
      const eventId = col(row, "event_id", "eventID");
      const label = col(row, "label", "msg", "event_name");
      return (
        eventId === "4720" ||
        includesAny(label, ["user account created", "create account"])
      );
    },
  },
  {
    id: "service-stop",
    label: "Service stop / terminate",
    techniques: ["T1489"],
    severity: "high",
    vendors: ["windows"],
    match: (row) => {
      const label = col(row, "label", "msg", "event_name", "action");
      return includesAny(label, ["service stop", "stopped service", "7040"]);
    },
  },
  {
    id: "autostart",
    label: "Autostart / persistence registry-run",
    techniques: ["T1547"],
    severity: "high",
    vendors: ["agentx"],
    match: (row) => {
      const path = col(row, "file_path", "process_name", "msg", "TargetObject");
      return includesAny(path, [
        "\\currentversion\\run",
        "startup",
        "autostart",
        "schtasks",
      ]);
    },
  },
  {
    id: "masquerading",
    label: "Masquerading / lolbin-like process name",
    techniques: ["T1036"],
    severity: "medium",
    vendors: ["agentx", "cynet"],
    match: (row) => {
      const name = col(row, "process_name", "originalFileName", "file_path", "msg");
      return includesAny(name, [
        "svchost.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "wscript",
        "cscript",
      ]) && includesAny(col(row, "label", "msg"), ["suspicious", "alert", "detection"]);
    },
  },
  {
    id: "clear-logs",
    label: "Event log cleared / indicator removal",
    techniques: ["T1070.001"],
    severity: "high",
    vendors: ["windows"],
    match: (row) => {
      const eventId = col(row, "event_id", "eventID");
      const label = col(row, "label", "msg");
      return (
        eventId === "1102" ||
        includesAny(label, ["audit log cleared", "log cleared", "event log"])
      );
    },
  },
  {
    id: "impair-defenses",
    label: "Defender/AV disable / impair defenses",
    techniques: ["T1562.001", "T1562.006"],
    severity: "high",
    vendors: ["defender", "bitdefender"],
    match: (row) => {
      const label = col(row, "label", "msg", "title", "BitdefenderGZDetectionName");
      return includesAny(label, [
        "real-time protection",
        "disable",
        "tamper",
        "defender",
        "antivirus",
        "impair",
      ]);
    },
  },
  {
    id: "user-execution-malware",
    label: "Malware / user execution (EDR/AV)",
    techniques: ["T1204", "T1204.001"],
    severity: "high",
    vendors: ["bitdefender", "cynet", "fortigate"],
    match: (row) => {
      const label = col(
        row,
        "label",
        "msg",
        "threat_name",
        "BitdefenderGZDetectionName",
        "title",
      );
      return includesAny(label, [
        "malware",
        "trojan",
        "ransomware",
        "user execution",
        "phishing",
      ]);
    },
  },
  {
    id: "ransomware-impact",
    label: "Ransomware / encrypt impact",
    techniques: ["T1486"],
    severity: "critical",
    vendors: ["bitdefender", "cynet", "generic"],
    match: (row) => {
      const label = col(row, "label", "msg", "threat_name", "title");
      return includesAny(label, ["ransomware", "encrypt", "cipher"]);
    },
  },
  {
    id: "explicit-mitre-field",
    label: "Campo MITRE/technique nell'export",
    techniques: [],
    severity: "info",
    vendors: ["generic"],
    match: () => false, // handled separately in analyze
  },
];

export function severityRank(s: AlertSeverity): number {
  switch (s) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

export function maxSeverity(a: AlertSeverity, b: AlertSeverity): AlertSeverity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

export function techniqueSeverityFromSeed(
  id: string,
  seed: CoveredTechnique[],
  fallback: AlertSeverity,
): AlertSeverity {
  return seed.find((t) => t.id === id)?.severity ?? fallback;
}

/** Union of vendors tagged on signals that map to this technique. */
export function signalVendorsForTechnique(techniqueId: string): VendorFamily[] {
  const set = new Set<VendorFamily>();
  for (const rule of SIGNAL_RULES) {
    if (!rule.techniques.includes(techniqueId)) continue;
    for (const v of rule.vendors) set.add(v);
  }
  return [...set];
}
