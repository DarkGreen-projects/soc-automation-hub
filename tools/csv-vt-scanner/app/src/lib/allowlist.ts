import defaultAllowlist from "@/data/allowlist.default.json";

export interface Allowlist {
  attacks: string[];
  applications: string[];
  webfilterCategoriesExclude: string[];
  notes?: string;
}

export function getDefaultAllowlist(): Allowlist {
  return {
    attacks: [...defaultAllowlist.attacks],
    applications: [...defaultAllowlist.applications],
    webfilterCategoriesExclude: [...defaultAllowlist.webfilterCategoriesExclude],
    notes: defaultAllowlist.notes,
  };
}

function quoteList(values: string[]): string {
  return values.map((v) => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(", ");
}

export function applyAllowlistToQuery(query: string, list: Allowlist): string {
  let q = query.trim();
  if (!q) return q;

  const additions: string[] = [];

  if (list.attacks.length > 0 && /\battack\b/i.test(q) && !/-attack\s+IN/i.test(q)) {
    additions.push(`-attack IN [${quoteList(list.attacks)}]`);
  }

  if (
    list.applications.length > 0 &&
    /\b(application|app)\b/i.test(q) &&
    !/-application\s+IN/i.test(q)
  ) {
    additions.push(`-application IN [${quoteList(list.applications)}]`);
  }

  if (additions.length === 0) return q;

  const pipe = q.indexOf("|");
  if (pipe === -1) {
    return `${q} ${additions.join(" ")}`;
  }
  const head = q.slice(0, pipe).trimEnd();
  const tail = q.slice(pipe);
  return `${head} ${additions.join(" ")}${tail.startsWith(" ") ? "" : " "}${tail}`;
}
