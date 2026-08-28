import { applyAllowlistToQuery, getDefaultAllowlist } from "@/lib/allowlist";
import type { AlertSeverity } from "./parseTechniques";
import type { VendorFamily } from "./vendors";

export type RuleCondition = "simple" | "aggregation";

export interface AlertRuleSuggestion {
  techniqueId: string;
  techniqueName: string;
  severity: AlertSeverity;
  ruleName: string;
  description: string;
  tactic: string;
  risk: string;
  searchInterval: string;
  throttle: string;
  condition: RuleCondition;
  reposHint: string;
  query: string;
  jinjaTemplate: string;
  /** @deprecated use searchInterval */
  suggestedInterval: string;
  /** @deprecated use throttle */
  suggestedThrottle: string;
  checklist: string[];
  /** Labeled pack ready to paste into LogPoint Director */
  copyBlock: string;
}

const CHECKLIST = [
  "Query in una sola riga (niente a capo)",
  "Niente virgolette curve / tipografiche",
  "fields solo in fondo alla pipe, se serve",
  "Calibra soglia con timechart prima di mettere in produzione",
  "Imposta i repo del tenant (non lasciare vuoto se la query è vendor-specific)",
  "Incolla il Jinja nel template notifica/incident della rule",
];

const REPOS_HINT =
  "Scegli i repo del tenant allineati alla query (es. FortiOS / AgentX / Cynet / Windows Event). Non inventare nomi: usa quelli in Devices/Repos.";

type Template = {
  query: string;
  interval: string;
  throttle: string;
  tactic: string;
  shortName: string;
  what: string;
  /** Fields referenced in Jinja (row.*) — for chart queries use chart aliases */
  jinjaFields: string[];
  condition?: RuleCondition;
  vendors: VendorFamily[];
};

function severityToRisk(severity: AlertSeverity): string {
  switch (severity) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Info";
  }
}

function slugName(techniqueId: string, shortName: string): string {
  const slug = shortName
    .replace(/[^a-zA-Z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);
  return `AR-${techniqueId}-${slug || "Hunt"}`;
}

function detectCondition(query: string, explicit?: RuleCondition): RuleCondition {
  if (explicit) return explicit;
  return /\|\s*chart\b/i.test(query) ? "aggregation" : "simple";
}

function buildJinja(
  techniqueId: string,
  techniqueName: string,
  risk: string,
  fields: string[],
): string {
  const lines = fields.map((f) => `${f}={{ row.${f} }}`).join(" ");
  return [
    `{{ alert_name }} | MITRE ${techniqueId} ${techniqueName} | risk ${risk}`,
    "{% for row in rows %}",
    lines || "row={{ row }}",
    "{% endfor %}",
  ].join("\n");
}

function conditionLabel(condition: RuleCondition): string {
  return condition === "aggregation"
    ? "aggregation (soglia già nella query | chart … | search hits > N; alert se ci sono risultati)"
    : "simple (alert se Number of logs / results > 0)";
}

const TEMPLATES: Record<string, Template> = {
  T1190: {
    query:
      'norm_id=FortiOS event_category=utm sub_category=ips action IN ["detected", "pass"] -"log_severity"="low"',
    interval: "15m",
    throttle: "6h",
    tactic: "Initial Access",
    shortName: "Exploit-Public-Facing",
    what: "IPS FortiGate detected/pass (minaccia non droppata)",
    jinjaFields: [
      "log_ts",
      "source_address",
      "destination_address",
      "attack",
      "action",
      "log_severity",
      "msg",
    ],
    vendors: ["fortigate"],
  },
  T1046: {
    query:
      'norm_id=FortiOS event_category=utm sub_category=ips | chart count() as hits, distinct_count(destination_address) as dsts by source_address | search hits > 20',
    interval: "15m",
    throttle: "12h",
    tactic: "Discovery",
    shortName: "Network-Service-Discovery",
    what: "Burst IPS da stessa source (possibile scan/discovery)",
    jinjaFields: ["source_address", "hits", "dsts"],
    condition: "aggregation",
    vendors: ["fortigate"],
  },
  T1189: {
    query:
      'norm_id=FortiOS event_category=utm sub_category=webfilter action="blocked" category IN ["Malicious Websites", "Spam URLs", "Newly Observed Domain"] | chart count() as hits by source_address, category | search hits > 10',
    interval: "15m",
    throttle: "6h",
    tactic: "Initial Access",
    shortName: "Drive-by-Compromise",
    what: "Burst webfilter malicious/spam/NOD",
    jinjaFields: ["source_address", "category", "hits"],
    condition: "aggregation",
    vendors: ["fortigate"],
  },
  "T1071.001": {
    query:
      'norm_id=FortiOS event_category=utm sub_category=webfilter action="blocked" | chart count() as hits by source_address, category | search hits > 25',
    interval: "15m",
    throttle: "12h",
    tactic: "Command and Control",
    shortName: "Web-Protocols",
    what: "Volume webfilter blocked (C2 via web)",
    jinjaFields: ["source_address", "category", "hits"],
    condition: "aggregation",
    vendors: ["fortigate"],
  },
  T1071: {
    query:
      'norm_id=FortiOS (sub_category=app-ctrl OR sub_category=webfilter) | chart count() as hits by application, source_address | search hits > 50',
    interval: "15m",
    throttle: "12h",
    tactic: "Command and Control",
    shortName: "Application-Layer-Protocol",
    what: "Alto volume app-ctrl/webfilter per applicazione",
    jinjaFields: ["application", "source_address", "hits"],
    condition: "aggregation",
    vendors: ["fortigate"],
  },
  T1090: {
    query:
      'norm_id=FortiOS (category="Proxy Avoidance" OR application="*Proxy*" OR app="*Proxy*")',
    interval: "15m",
    throttle: "12h",
    tactic: "Command and Control",
    shortName: "Proxy",
    what: "Proxy Avoidance / proxy apps su FortiGate",
    jinjaFields: [
      "log_ts",
      "source_address",
      "destination_address",
      "category",
      "application",
      "app",
      "action",
    ],
    vendors: ["fortigate"],
  },
  T1219: {
    query:
      'norm_id=FortiOS (application IN ["TeamViewer", "AnyDesk", "RustDesk"] OR app IN ["TeamViewer", "AnyDesk"] OR category="*Remote Access*")',
    interval: "15m",
    throttle: "6h",
    tactic: "Command and Control",
    shortName: "Remote-Access-Software",
    what: "Remote access software (TeamViewer/AnyDesk/…)",
    jinjaFields: [
      "log_ts",
      "source_address",
      "destination_address",
      "application",
      "app",
      "user",
      "action",
    ],
    vendors: ["fortigate"],
  },
  T1110: {
    query:
      '(event_id=4625 OR label="login failed") | chart count() as hits by user, computer, source_address | search hits > 50',
    interval: "15m",
    throttle: "6h",
    tactic: "Credential Access",
    shortName: "Brute-Force",
    what: "Burst login failed / 4625 per user-host-source",
    jinjaFields: ["user", "computer", "source_address", "hits"],
    condition: "aggregation",
    vendors: ["windows"],
  },
  "T1110.001": {
    query:
      '(event_id=4625 OR label="login failed") | chart count() as hits, distinct_count(user) as users by source_address | search users > 10 hits > 20',
    interval: "15m",
    throttle: "6h",
    tactic: "Credential Access",
    shortName: "Password-Guessing",
    what: "Password spray: tanti user, stessa source",
    jinjaFields: ["source_address", "hits", "users"],
    condition: "aggregation",
    vendors: ["windows"],
  },
  "T1136.001": {
    query: '(event_id=4720 OR label="*user account created*")',
    interval: "5m",
    throttle: "1h",
    tactic: "Persistence",
    shortName: "Local-Account",
    what: "Creazione account locale (4720)",
    jinjaFields: ["log_ts", "user", "computer", "event_id", "label", "msg"],
    vendors: ["windows"],
  },
  T1489: {
    query: '(label="*service stop*" OR event_id=7040 OR msg="*stopped the*")',
    interval: "15m",
    throttle: "6h",
    tactic: "Impact",
    shortName: "Service-Stop",
    what: "Service stop / 7040",
    jinjaFields: ["log_ts", "hostname", "computer", "event_id", "label", "msg"],
    vendors: ["windows"],
  },
  T1547: {
    query:
      '(col_type=AgentX OR device_name="*AgentX*") AND (msg="*\\\\CurrentVersion\\\\Run*" OR file_path="*\\\\Startup*" OR process_name="*schtasks*")',
    interval: "15m",
    throttle: "12h",
    tactic: "Persistence",
    shortName: "Autostart-Execution",
    what: "Autostart / Run key / Startup / schtasks (AgentX)",
    jinjaFields: [
      "log_ts",
      "hostname",
      "computer",
      "user",
      "process_name",
      "file_path",
      "msg",
    ],
    vendors: ["agentx"],
  },
  T1036: {
    query:
      '(col_type=AgentX OR device_name="*Cynet*" OR product=Cynet) AND (process_name IN ["*svchost.exe*", "*rundll32*", "*mshta*"] OR label=detection)',
    interval: "15m",
    throttle: "6h",
    tactic: "Defense Evasion",
    shortName: "Masquerading",
    what: "Masquerading / lolbin-like process su AgentX/Cynet",
    jinjaFields: [
      "log_ts",
      "hostname",
      "computer",
      "user",
      "process_name",
      "file_path",
      "label",
      "msg",
    ],
    vendors: ["agentx", "cynet"],
  },
  "T1070.001": {
    query: '(event_id=1102 OR label="*audit log cleared*" OR msg="*cleared*")',
    interval: "5m",
    throttle: "1h",
    tactic: "Defense Evasion",
    shortName: "Clear-Event-Logs",
    what: "Clear Windows Event Logs (1102)",
    jinjaFields: ["log_ts", "hostname", "computer", "user", "event_id", "label", "msg"],
    vendors: ["windows"],
  },
  "T1562.001": {
    query:
      '(msg="*real-time protection*" OR msg="*disabled*" OR title="*Defender*" OR label="*tamper*") AND (label=alert OR label=detection OR severity=high OR severity=critical)',
    interval: "15m",
    throttle: "6h",
    tactic: "Defense Evasion",
    shortName: "Disable-or-Modify-Tools",
    what: "Disable/tamper AV/Defender tools",
    jinjaFields: ["log_ts", "hostname", "title", "label", "severity", "msg"],
    vendors: ["defender"],
  },
  "T1562.006": {
    query:
      '(device_name="*Bitdefender*" OR product=Bitdefender OR col_type=MicrosoftGraph OR device_name="*Defender*") AND (msg="*block*" OR msg="*indicator*" OR title="*impair*")',
    interval: "15m",
    throttle: "6h",
    tactic: "Defense Evasion",
    shortName: "Indicator-Blocking",
    what: "Impair defenses / indicator blocking (BD/Defender/Graph)",
    jinjaFields: [
      "log_ts",
      "hostname",
      "device_name",
      "title",
      "label",
      "BitdefenderGZDetectionName",
      "msg",
    ],
    vendors: ["bitdefender", "defender"],
  },
  T1204: {
    query:
      '(device_name="*Bitdefender*" OR product=Bitdefender OR product=Cynet OR col_type=Cynet) AND (threat_name="*" OR BitdefenderGZDetectionName="*" OR label=detection)',
    interval: "15m",
    throttle: "6h",
    tactic: "Execution",
    shortName: "User-Execution",
    what: "Malware / detection EDR-AV (user execution)",
    jinjaFields: [
      "log_ts",
      "hostname",
      "user",
      "threat_name",
      "BitdefenderGZDetectionName",
      "file_path",
      "label",
    ],
    vendors: ["bitdefender", "cynet"],
  },
  "T1204.001": {
    query:
      '(norm_id=FortiOS sub_category=webfilter category IN ["Malicious Websites", "Phishing"] OR label="*phish*")',
    interval: "15m",
    throttle: "6h",
    tactic: "Execution",
    shortName: "Malicious-Link",
    what: "Phishing / malicious link (webfilter o label)",
    jinjaFields: [
      "log_ts",
      "source_address",
      "url",
      "category",
      "user",
      "action",
      "label",
    ],
    vendors: ["fortigate"],
  },
  T1486: {
    query:
      '(threat_name="*ransom*" OR BitdefenderGZDetectionName="*ransom*" OR label="*ransomware*" OR msg="*encrypt*")',
    interval: "5m",
    throttle: "1h",
    tactic: "Impact",
    shortName: "Data-Encrypted-Impact",
    what: "Ransomware / encrypt impact",
    jinjaFields: [
      "log_ts",
      "hostname",
      "user",
      "threat_name",
      "BitdefenderGZDetectionName",
      "file_path",
      "label",
      "msg",
    ],
    vendors: ["bitdefender", "cynet", "generic"],
  },
};

const GENERIC: Template = {
  query: 'label=alert OR label=detection OR severity=high OR severity=critical',
  interval: "15m",
  throttle: "12h",
  tactic: "Collection",
  shortName: "Generic-Detection",
  what: "Detection/alert generica high-critical",
  jinjaFields: ["log_ts", "hostname", "user", "label", "severity", "msg"],
  vendors: ["generic"],
};

/** Vendors tagged on the rule pack template for a technique (falls back to generic). */
export function getTemplateVendors(techniqueId: string): VendorFamily[] {
  return TEMPLATES[techniqueId]?.vendors ?? GENERIC.vendors;
}

export function buildAlertRuleSuggestion(
  techniqueId: string,
  techniqueName: string,
  severity: AlertSeverity,
): AlertRuleSuggestion {
  const tpl = TEMPLATES[techniqueId] ?? GENERIC;
  const withAllowlist = applyAllowlistToQuery(tpl.query, getDefaultAllowlist());
  const query = withAllowlist.replace(/\s*\n\s*/g, " ").replace(/\s+/g, " ").trim();
  const risk = severityToRisk(severity);
  const condition = detectCondition(query, tpl.condition);
  const ruleName = slugName(techniqueId, tpl.shortName);
  const description = `MITRE ${techniqueId} (${techniqueName}). ${tpl.what}. Tactic: ${tpl.tactic}.`;
  const jinjaTemplate = buildJinja(techniqueId, techniqueName, risk, tpl.jinjaFields);

  const copyBlock = [
    `Name: ${ruleName}`,
    `Description: ${description}`,
    `MITRE: ${techniqueId} — ${techniqueName}`,
    `Tactic: ${tpl.tactic}`,
    `Risk: ${risk}`,
    `Repos: ${REPOS_HINT}`,
    `Search interval: ${tpl.interval}`,
    `Throttle: ${tpl.throttle}`,
    `Condition: ${conditionLabel(condition)}`,
    `Query:`,
    query,
    `Jinja template:`,
    jinjaTemplate,
    `Checklist:`,
    ...CHECKLIST.map((c) => `- ${c}`),
  ].join("\n");

  return {
    techniqueId,
    techniqueName,
    severity,
    ruleName,
    description,
    tactic: tpl.tactic,
    risk,
    searchInterval: tpl.interval,
    throttle: tpl.throttle,
    condition,
    reposHint: REPOS_HINT,
    query,
    jinjaTemplate,
    suggestedInterval: tpl.interval,
    suggestedThrottle: tpl.throttle,
    checklist: [...CHECKLIST],
    copyBlock,
  };
}
