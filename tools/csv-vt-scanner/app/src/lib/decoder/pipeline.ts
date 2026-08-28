import { extractAgentX, agentxContext } from "./extractAgentX";
import { extractBitdefender, bitdefenderContext } from "./extractBitdefender";
import { extractCynet, cynetContext } from "./extractCynet";
import { extractDefender, defenderContext } from "./extractDefender";
import {
  findAgentXBlock,
  findCynetBlock,
  findGSuiteBlock,
  findM365Block,
  findMicrosoftGraph,
  looksLikeBitdefender,
  looksLikeCef,
  looksLikeFortigateKv,
  looksLikeIocList,
  looksLikeJson,
  normalizePastedText,
  parseFortigateKv,
  tryParseJson,
  unwrapNestedJsonStrings,
} from "./detect";
import { extractFortigate, fortigateContext } from "./extractFortigate";
import { extractGsuite, gsuiteContext } from "./extractGsuite";
import { extractM365, m365Context } from "./extractM365";
import { dedupeArtifacts, extractFromPlainText, extractGeneric, makeArtifact } from "./extractGeneric";
import { looksLikeIpv4 } from "./patterns";
import {
  DOMAIN_FIELDS,
  EMAIL_FIELDS,
  HASH_FIELDS,
  HOSTNAME_FIELDS,
  IP_FIELDS,
  PATH_FIELDS,
  URL_FIELDS,
  USER_FIELDS,
  containsAny,
  equalsAny,
} from "./schemaQueryHints";
import type { Artifact, ArtifactType, DecodeResult } from "./types";

export const MAX_INPUT_CHARS = 512 * 1024;

function iocType(token: string): ArtifactType | null {
  if (looksLikeIpv4(token)) return "ip";
  if (/^[A-Fa-f0-9]{64}$/.test(token)) return "hash_sha256";
  if (/^[A-Fa-f0-9]{40}$/.test(token)) return "hash_sha1";
  if (/^[A-Fa-f0-9]{32}$/.test(token)) return "hash_md5";
  if (/^https?:\/\//i.test(token)) return "url";
  if (/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(token)) return "domain";
  return null;
}

function extractIocList(text: string): Artifact[] {
  const tokens = text.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean);
  const out: Artifact[] = [];
  for (const token of tokens) {
    const type = iocType(token);
    if (!type) continue;
    const art = makeArtifact(type, token, "ioc_list");
    if (art) out.push(art);
  }
  return dedupeArtifacts(out);
}

export function decodeSiemText(raw: string): DecodeResult {
  if (raw.length > MAX_INPUT_CHARS) {
    return {
      format: "generic",
      vendor: null,
      context: {},
      artifacts: [],
      error: `Input troppo grande (max ${MAX_INPUT_CHARS} caratteri).`,
    };
  }
  const text = normalizePastedText(raw);
  if (!text) {
    return {
      format: "generic",
      vendor: null,
      context: {},
      artifacts: [],
      error: "Incolla un JSON, un log FortiGate/CEF o una lista di IOC.",
    };
  }

  if (looksLikeJson(text) || text.includes("{")) {
    const parsed = tryParseJson(text);
    if (parsed) {
      const data = unwrapNestedJsonStrings(parsed);
      const cynet = findCynetBlock(data);
      if (cynet) {
        return {
          format: "json",
          vendor: "Cynet",
          context: cynetContext(cynet),
          artifacts: dedupeArtifacts(extractCynet(cynet)),
        };
      }
      const graph = findMicrosoftGraph(data);
      if (graph) {
        return {
          format: "json",
          vendor: "Defender",
          context: defenderContext(graph),
          artifacts: dedupeArtifacts(extractDefender(graph)),
        };
      }
      const agentx = findAgentXBlock(data);
      if (agentx) {
        return {
          format: "json",
          vendor: "AgentX",
          context: agentxContext(agentx),
          artifacts: dedupeArtifacts(extractAgentX(agentx)),
        };
      }
      const gsuite = findGSuiteBlock(data);
      if (gsuite) {
        return {
          format: "json",
          vendor: "GSuite",
          context: gsuiteContext(gsuite),
          artifacts: dedupeArtifacts(extractGsuite(gsuite)),
        };
      }
      const m365 = findM365Block(data);
      if (m365) {
        return {
          format: "json",
          vendor: "Microsoft365",
          context: m365Context(m365),
          artifacts: dedupeArtifacts(extractM365(m365)),
        };
      }
      const obj = data as Record<string, unknown>;
      if (obj && typeof obj === "object" && (obj.srcip || obj.subtype || obj.type === "utm")) {
        return {
          format: "fortigate",
          vendor: "FortiGate",
          context: fortigateContext(obj),
          artifacts: dedupeArtifacts(extractFortigate(obj)),
        };
      }
      return {
        format: "json",
        vendor: "generic",
        context: {},
        artifacts: extractGeneric(data, "json"),
      };
    }
  }

  if (looksLikeCef(text) || looksLikeFortigateKv(text)) {
    const fields = parseFortigateKv(text);
    if (looksLikeBitdefender(fields)) {
      return {
        format: looksLikeCef(text) ? "cef" : "generic",
        vendor: "Bitdefender",
        context: bitdefenderContext(fields),
        artifacts: dedupeArtifacts(extractBitdefender(fields)),
      };
    }
    return {
      format: looksLikeCef(text) ? "cef" : "fortigate",
      vendor: "FortiGate",
      context: fortigateContext(fields),
      artifacts: dedupeArtifacts(extractFortigate(fields)),
    };
  }

  if (looksLikeIocList(text)) {
    return {
      format: "ioc",
      vendor: null,
      context: {},
      artifacts: extractIocList(text),
    };
  }

  return {
    format: "generic",
    vendor: null,
    context: {},
    artifacts: extractFromPlainText(text, "paste"),
  };
}

export function queryForArtifact(art: Artifact): string {
  const v = art.normalizedValue;
  switch (art.type) {
    case "ip":
      return equalsAny(IP_FIELDS, v);
    case "hash_sha256":
    case "hash_sha1":
    case "hash_md5":
      // AgentX Sysmon stores "SHA256=…|SHA1=…" in `hashes`
      return `${equalsAny(HASH_FIELDS, v)} OR hashes = "*${v}*"`;
    case "domain": {
      const exact = DOMAIN_FIELDS.filter((f) => f !== "url");
      return `${equalsAny(exact, v)} OR url = "*${v}*"`;
    }
    case "url":
      return equalsAny(URL_FIELDS, v);
    case "hostname": {
      const exact = HOSTNAME_FIELDS.filter((f) => f !== "device_name");
      return `${equalsAny(exact, v)} OR device_name = "*${v}*"`;
    }
    case "username":
      return equalsAny(USER_FIELDS, v);
    case "email_address":
      return equalsAny(EMAIL_FIELDS, v);
    case "file_path": {
      const escaped = v.replace(/\\/g, "\\\\");
      return containsAny(PATH_FIELDS, escaped);
    }
    default:
      return `msg = "*${v}*"`;
  }
}

export function queryForAll(artifacts: Artifact[]): string {
  const useful = artifacts.filter((a) =>
    ["ip", "hash_sha256", "hash_sha1", "hash_md5", "domain", "url", "hostname"].includes(
      a.type,
    ),
  );
  if (useful.length === 0) return "";
  const parts = useful.slice(0, 12).map((a) => `(${queryForArtifact(a)})`);
  return parts.join(" OR ");
}
