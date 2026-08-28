export function normalizePastedText(text: string): string {
  let content = text.trim().replace(/^\uFEFF/, "");
  content = content.replace(/[\u00a0\u2007\u202f\u2009\u200a\ufeff]/g, " ");
  content = content.replace(/[\u201c\u201d]/g, '"').replace(/[\u2018\u2019]/g, "'");
  content = content.replace(/[^\S\n]+/g, " ");
  return content.trim();
}

export function looksLikeJson(text: string): boolean {
  const t = text.trim();
  return (t.startsWith("{") && t.includes("}")) || (t.startsWith("[") && t.includes("]"));
}

export function looksLikeCef(text: string): boolean {
  return /\bCEF:\d+\|/.test(text);
}

export function looksLikeFortigateKv(text: string): boolean {
  return (
    /\btype\s*=\s*"?utm"?/i.test(text) ||
    (/\bdate\s*=/.test(text) && /\b(srcip|dstip|subtype|devname)\s*=/.test(text))
  );
}

export function looksLikeIocList(text: string): boolean {
  const lines = text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (lines.length === 0 || lines.length > 200) return false;
  const iocish = lines.filter(
    (t) =>
      /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(t) ||
      /^[A-Fa-f0-9]{32}$/.test(t) ||
      /^[A-Fa-f0-9]{40}$/.test(t) ||
      /^[A-Fa-f0-9]{64}$/.test(t) ||
      /^https?:\/\//i.test(t) ||
      /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(t),
  );
  return iocish.length >= Math.max(1, Math.floor(lines.length * 0.6));
}

export function parseFortigateKv(text: string): Record<string, string> {
  const fields: Record<string, string> = {};
  const re = /(\w+)=(?:"([^"]*)"|(\S+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    fields[m[1]] = m[2] ?? m[3] ?? "";
  }
  return fields;
}

export function tryParseJson(text: string): unknown | null {
  const candidates = [text];
  const startObj = text.indexOf("{");
  const endObj = text.lastIndexOf("}");
  if (startObj >= 0 && endObj > startObj) {
    candidates.push(text.slice(startObj, endObj + 1));
  }
  for (const c of candidates) {
    try {
      return JSON.parse(c);
    } catch {
      try {
        return JSON.parse(c.replace(/""/g, '"'));
      } catch {
        continue;
      }
    }
  }
  return null;
}

export function unwrapNestedJsonStrings(value: unknown, depth = 0): unknown {
  if (depth > 4) return value;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (looksLikeJson(trimmed)) {
      const parsed = tryParseJson(trimmed);
      if (parsed && typeof parsed === "object") {
        return unwrapNestedJsonStrings(parsed, depth + 1);
      }
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => unwrapNestedJsonStrings(item, depth + 1));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = unwrapNestedJsonStrings(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function findCynetBlock(data: unknown): Record<string, unknown> | null {
  if (!data || typeof data !== "object") return null;
  const obj = data as Record<string, unknown>;
  if (obj.HostIp || obj.Sha256Hex || obj.IncidentName || obj.HostName) {
    return obj;
  }
  for (const value of Object.values(obj)) {
    if (value && typeof value === "object") {
      const nested = findCynetBlock(value);
      if (nested) return nested;
    }
  }
  return null;
}

function asRecord(data: unknown): Record<string, unknown> | null {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  return data as Record<string, unknown>;
}

function findByKey(
  data: unknown,
  match: (obj: Record<string, unknown>) => Record<string, unknown> | null,
): Record<string, unknown> | null {
  const obj = asRecord(data);
  if (!obj) return null;
  const hit = match(obj);
  if (hit) return hit;
  for (const value of Object.values(obj)) {
    const nested = findByKey(value, match);
    if (nested) return nested;
  }
  return null;
}

export function findMicrosoftGraph(data: unknown): Record<string, unknown> | null {
  return findByKey(data, (obj) => {
    const graph = asRecord(obj.MicrosoftGraph);
    if (graph) return graph;
    if (obj.evidence && (obj.title || obj.alertWebUrl)) return obj;
    return null;
  });
}

export function findAgentXBlock(data: unknown): Record<string, unknown> | null {
  const keys = ["AgentX_Alert_win", "AgentX_win", "AgentX_Alert_linux", "AgentX_linux"];
  return findByKey(data, (obj) => {
    for (const key of keys) {
      const block = asRecord(obj[key]);
      if (block) return block;
    }
    return null;
  });
}

export function findGSuiteBlock(data: unknown): Record<string, unknown> | null {
  return findByKey(data, (obj) => {
    const gsuite = asRecord(obj.GSuite);
    if (gsuite) return gsuite;
    if (asRecord(obj.actor) && (obj.ipAddress || obj.kind)) return obj;
    return null;
  });
}

export function looksLikeM365Audit(data: unknown): data is Record<string, unknown> {
  return findM365Block(data) !== null;
}

export function findM365Block(data: unknown): Record<string, unknown> | null {
  return findByKey(data, (obj) => (obj.UserId && obj.Operation ? obj : null));
}

export function looksLikeBitdefender(fields: Record<string, unknown>): boolean {
  return Object.keys(fields).some(
    (key) => key.startsWith("BitdefenderGZ") || /bitdefender/i.test(key),
  );
}
