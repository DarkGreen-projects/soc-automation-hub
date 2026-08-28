import { queryForArtifact, queryForAll } from "./pipeline";
import { EMAIL_FIELDS, equalsAny, fortigateIpClause } from "./schemaQueryHints";
import type { Allowlist } from "@/lib/allowlist";
import { applyAllowlistToQuery } from "@/lib/allowlist";
import type { Artifact, ArtifactType, DecodeResult } from "./types";

export interface InvestigationQuery {
  id: string;
  title: string;
  why: string;
  query: string;
}

const CYNET_BASE = '(device_name = "*Cynet*" OR col_type = Cynet OR product = Cynet)';
const CYNET_FIELDS =
  "fields log_ts, hostname, user, process_name, file_path, threat_name, action, severity, label, msg";
const AGENTX_BASE = '(col_type = AgentX OR device_name = "*AgentX*")';
const AGENTX_FIELDS =
  "fields log_ts, hostname, computer, user, targetUserName, subjectUserName, process_name, processName, file_path, originalFileName, source_address, destination_address, ipAddress, hashes, label, msg";
const DEFENDER_BASE =
  '(col_type = MicrosoftGraph OR device_name = "*Defender*" OR product = "*Defender*" OR label = MicrosoftGraph)';
const DEFENDER_FIELDS =
  "fields log_ts, hostname, computer, user, process_name, file_path, sha256, action, severity, title, label, msg";
const GSUITE_BASE = '(col_type = GSuite OR device_name = "*GSuite*" OR product = GSuite)';
const M365_BASE = "(Workload exists OR Operation exists OR UserId exists)";
const M365_FIELDS =
  "fields log_ts, UserId, MailboxOwnerUPN, Operation, Workload, ResultStatus, ClientIP, ClientIPAddress, ActorIpAddress, SourceFileName, ObjectId, label, msg";
const BD_BASE =
  '(device_name = "*Bitdefender*" OR product = Bitdefender OR col_type = Bitdefender OR msg = "*Bitdefender*")';
const BD_FIELDS =
  "fields log_ts, BitdefenderGZComputerFQDN, hostname, suser, BitdefenderGZDetectionName, BitdefenderGZMalwareHash, filePath, source_address, src, request, label, msg";
const FG_FIELDS =
  "fields log_ts, srcip, dstip, source_address, destination_address, user, suser, duser, url, app, action, subtype, attack, msg";

function quote(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function ctx(result: DecodeResult, key: string): string | null {
  const value = result.context[key];
  return value && value.trim() ? value.trim() : null;
}

function firstOf(artifacts: Artifact[], type: ArtifactType): Artifact | undefined {
  return artifacts.find((a) => a.type === type);
}

function allOf(artifacts: Artifact[], types: ArtifactType[]): Artifact[] {
  return artifacts.filter((a) => types.includes(a.type));
}

function publicIps(artifacts: Artifact[]): Artifact[] {
  return artifacts.filter((a) => a.type === "ip" && a.scope === "public");
}

function tiValues(artifacts: Artifact[]): string[] {
  return artifacts
    .filter(
      (a) =>
        a.scope === "public" &&
        ["ip", "hash_sha256", "hash_sha1", "hash_md5", "domain", "url"].includes(a.type),
    )
    .map((a) => a.normalizedValue)
    .slice(0, 8);
}

function push(
  out: InvestigationQuery[],
  id: string,
  title: string,
  why: string,
  query: string,
) {
  if (!query.trim()) return;
  out.push({ id, title, why, query });
}

function cynetPack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const host = ctx(result, "host_name") ?? firstOf(result.artifacts, "hostname")?.normalizedValue;
  const hostIp = ctx(result, "host_ip") ?? firstOf(result.artifacts, "ip")?.normalizedValue;
  const user = ctx(result, "user_name") ?? firstOf(result.artifacts, "username")?.normalizedValue;
  const hash =
    ctx(result, "sha256") ??
    firstOf(result.artifacts, "hash_sha256")?.normalizedValue ??
    firstOf(result.artifacts, "hash_sha1")?.normalizedValue ??
    firstOf(result.artifacts, "hash_md5")?.normalizedValue;
  const path = ctx(result, "file_path") ?? firstOf(result.artifacts, "file_path")?.normalizedValue;
  const pub = publicIps(result.artifacts);

  if (host) {
    const h = quote(host);
    push(
      out,
      "cynet-host-timeline",
      "Timeline Cynet sull'host",
      "Raccoglie gli eventi EDR della macchina per la cronologia da allegare alla segnalazione.",
      `${CYNET_BASE} AND hostname = "${h}" | ${CYNET_FIELDS}`,
    );
    push(
      out,
      "cynet-host-alerts",
      "Altri alert Cynet sullo stesso host",
      "Verifica se l'incidente è isolato o se ci sono altre detection sulla stessa macchina.",
      `${CYNET_BASE} AND hostname = "${h}" AND (label = alert OR label = detection OR label = prevention OR severity = high OR severity = critical) | ${CYNET_FIELDS}`,
    );
  }

  if (user) {
    const u = quote(user);
    push(
      out,
      "cynet-user",
      "Attività utente (Cynet + logon)",
      "Serve a capire se l'account è coinvolto in altri eventi o in autenticazioni sospette.",
      `(user = "${u}") AND (${CYNET_BASE} OR label = "login failed" OR label = "authentication failure" OR label = logon OR label = logoff)`,
    );
  }

  if (hash) {
    const art =
      result.artifacts.find((a) => a.normalizedValue.toLowerCase() === hash.toLowerCase()) ??
      ({
        type: "hash_sha256",
        value: hash,
        normalizedValue: hash,
        scope: "public",
        provenance: "context",
      } as Artifact);
    push(
      out,
      "cynet-hash",
      "Presenza dell'hash su altri host",
      "Controlla pivoting: lo stesso file/hash su altre macchine del cliente.",
      queryForArtifact(art),
    );
  }

  if (path) {
    const art =
      result.artifacts.find((a) => a.type === "file_path") ??
      ({
        type: "file_path",
        value: path,
        normalizedValue: path,
        scope: "internal",
        provenance: "context",
      } as Artifact);
    push(
      out,
      "cynet-path",
      "Path del file coinvolto",
      "Utile in segnalazione per indicare il percorso e cercare copie o esecuzioni successive.",
      queryForArtifact(art),
    );
  }

  if (hostIp) {
    const ip = quote(hostIp);
    push(
      out,
      "cynet-forti-hostip",
      "Traffico FortiGate dell'host",
      "Correla l'endpoint con il firewall: connessioni uscenti/entranti intorno all'incidente.",
      `norm_id=FortiOS AND (${fortigateIpClause(ip)}) | process geoip(source_address) as source_country | process geoip(destination_address) as destination_country | ${FG_FIELDS}`,
    );
  }

  if (pub.length > 0) {
    const parts = pub.slice(0, 6).map((a) => `(${fortigateIpClause(quote(a.normalizedValue))})`);
    push(
      out,
      "cynet-forti-public",
      "Traffico FortiGate verso IP pubblici estratti",
      "Verifica contatti C2/esterni visti dal firewall, da citare nella segnalazione.",
      `norm_id=FortiOS AND (${parts.join(" OR ")}) | process geoip(source_address) as source_country | process geoip(destination_address) as destination_country | ${FG_FIELDS}`,
    );
  }

  const iocs = tiValues(result.artifacts);
  if (iocs.length > 0) {
    const or = iocs.map((v) => `value = "${quote(v)}" OR ioc = "${quote(v)}"`).join(" OR ");
    push(
      out,
      "cynet-ti",
      "Match TI / MISP sugli IOC pubblici",
      "Controlla se gli IOC sono già in threat intelligence del tenant prima di segnalare.",
      `Table "threat_intelligence" (${or})`,
    );
  }

  return out;
}

function fortigatePack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const src =
    ctx(result, "srcip") ??
    result.artifacts.find((a) => a.type === "ip" && a.provenance.toLowerCase().includes("src"))
      ?.normalizedValue ??
    firstOf(result.artifacts, "ip")?.normalizedValue;
  const dst =
    ctx(result, "dstip") ??
    result.artifacts.find((a) => a.type === "ip" && a.provenance.toLowerCase().includes("dst"))
      ?.normalizedValue;
  const attack = ctx(result, "incident_name");
  const subtype = ctx(result, "subtype");
  const user = ctx(result, "user") ?? firstOf(result.artifacts, "username")?.normalizedValue;
  const url = ctx(result, "url") ?? firstOf(result.artifacts, "url")?.normalizedValue;
  const domain = firstOf(result.artifacts, "domain")?.normalizedValue;
  const app = ctx(result, "app");
  const service = ctx(result, "service");
  const direction = ctx(result, "direction");

  if (src || dst) {
    const parts: string[] = [];
    if (src) parts.push(`(${fortigateIpClause(quote(src))})`);
    if (dst && dst !== src) parts.push(`(${fortigateIpClause(quote(dst))})`);
    push(
      out,
      "fg-same-ips",
      "Stessi IP nel time-range",
      "Ricostruisce tutto il traffico tra gli IP dell'alert per volume, azione e direzione.",
      `norm_id=FortiOS AND (${parts.join(" OR ")}) | process geoip(source_address) as source_country | process geoip(destination_address) as destination_country | ${FG_FIELDS}`,
    );
  }

  if (attack && attack !== "-") {
    push(
      out,
      "fg-same-attack",
      "Stesso attacco / signature",
      "Quante altre volte la stessa signature ha colpito il tenant, e da quali sorgenti.",
      `norm_id=FortiOS AND (attack = "${quote(attack)}" OR msg = "*${quote(attack)}*") | chart count() as cnt by source_address, destination_address, action | order by cnt desc`,
    );
  }

  if (url) {
    push(
      out,
      "fg-url",
      "URL coinvolto",
      "Serve per la segnalazione: chi ha visitato/bloccato lo stesso URL.",
      `norm_id=FortiOS AND url = "${quote(url)}" | chart count() as cnt by source_address, action, category`,
    );
  } else if (domain) {
    push(
      out,
      "fg-domain",
      "Dominio coinvolto",
      "Cerca il dominio su URL/hostname FortiGate per coverage completa.",
      `norm_id=FortiOS AND (domain = "${quote(domain)}" OR hostname = "${quote(domain)}" OR url = "*${quote(domain)}*")`,
    );
  }

  if (user) {
    push(
      out,
      "fg-user",
      "Utente sul firewall",
      "Collega l'evento UTM all'identità da indicare al cliente.",
      `norm_id=FortiOS AND (user = "${quote(user)}" OR suser = "${quote(user)}" OR duser = "${quote(user)}" OR unauthuser = "${quote(user)}" OR FTNTFGTdstuser = "${quote(user)}") | ${FG_FIELDS}`,
    );
  }

  if (app) {
    const srcFilter = src ? ` AND (${fortigateIpClause(quote(src))})` : "";
    push(
      out,
      "fg-app",
      "Stessa applicazione",
      "Altri eventi app-ctrl/UTM della stessa app, per capire se è rumore o uso anomalo.",
      `norm_id=FortiOS AND (app = "${quote(app)}" OR application = "${quote(app)}")${srcFilter} | ${FG_FIELDS}`,
    );
  }

  if (service || direction) {
    const bits: string[] = ["norm_id=FortiOS"];
    if (src) bits.push(`(${fortigateIpClause(quote(src))})`);
    if (service) bits.push(`service = "${quote(service)}"`);
    if (direction) bits.push(`direction = "${quote(direction)}"`);
    push(
      out,
      "fg-service-direction",
      "Service / direction correlati",
      "Restringe il traffico FortiGate con service e direction visti nell'alert.",
      `${bits.join(" AND ")} | ${FG_FIELDS}`,
    );
  }

  if (src) {
    const ip = quote(src);
    const ipFilter = fortigateIpClause(ip);
    if (subtype === "ips" || !subtype) {
      push(
        out,
        "fg-ips-related",
        "IPS correlato sugli stessi IP",
        "Altre detection IPS (anche dropped) nello stesso intorno, da allegare come contesto.",
        `norm_id=FortiOS event_category=utm sub_category=ips AND (${ipFilter}) -attack IN ["Censys.io.Scanner", "Shodan.io.Scanner", "ZoomEye.Scanner"] | ${FG_FIELDS}`,
      );
    }
    if (subtype === "webfilter" || !subtype) {
      push(
        out,
        "fg-webfilter-related",
        "Webfilter correlato",
        "Verifica burst su categorie Malicious/Spam/NOD dallo stesso source, non solo l'evento singolo.",
        `norm_id=FortiOS event_category=utm sub_category=webfilter action="blocked" AND (source_address = "${ip}" OR srcip = "${ip}" OR src = "${ip}") category IN ["Malicious Websites", "Spam URLs", "Newly Observed Domain"] | chart count() as hits by url, category`,
      );
    }
    if (subtype === "virus") {
      push(
        out,
        "fg-virus-related",
        "AV correlato",
        "Altri eventi virus sullo stesso source, incluso passthrough.",
        `norm_id=FortiOS event_category=utm sub_category=virus AND (${ipFilter}) | ${FG_FIELDS}`,
      );
    }
  }

  const iocs = tiValues(result.artifacts);
  if (iocs.length > 0) {
    push(
      out,
      "fg-ti",
      "Enrich TI FortiGate",
      "Incrocia gli IP/URL dell'alert con la threat intelligence del tenant.",
      `norm_id=FortiOS | process ti(source_address, destination_address, hostname, url, filter)`,
    );
  }

  return out;
}

function genericPack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const useful = allOf(result.artifacts, [
    "ip",
    "hash_sha256",
    "hash_sha1",
    "hash_md5",
    "domain",
    "url",
    "hostname",
    "username",
    "email_address",
  ]);

  const byType = new Map<string, Artifact[]>();
  for (const art of useful) {
    const list = byType.get(art.type) ?? [];
    list.push(art);
    byType.set(art.type, list);
  }

  for (const [type, items] of byType) {
    const first = items[0];
    if (!first) continue;
    if (items.length === 1) {
      push(
        out,
        `generic-${type}`,
        `Ricerca ${type}`,
        "Query puntuale sull'IOC estratto, da lanciare nel time-range dell'incidente.",
        queryForArtifact(first),
      );
    } else {
      const parts = items.slice(0, 8).map((a) => `(${queryForArtifact(a)})`);
      push(
        out,
        `generic-${type}-or`,
        `Ricerca ${type} (OR)`,
        "Copre tutti gli IOC dello stesso tipo senza aprire una query per ciascuno.",
        parts.join(" OR "),
      );
    }
  }

  const all = queryForAll(result.artifacts);
  if (all && useful.length > 1) {
    push(
      out,
      "generic-all",
      "Hunt OR su tutti gli IOC",
      "Prima passata ampia: poi restringi con le query per tipo se il volume è alto.",
      all,
    );
  }

  const iocs = tiValues(result.artifacts);
  if (iocs.length > 0) {
    const or = iocs.map((v) => `value = "${quote(v)}" OR ioc = "${quote(v)}"`).join(" OR ");
    push(
      out,
      "generic-ti",
      "Match TI / MISP",
      "Verifica se gli IOC pubblici sono già noti in threat intelligence.",
      `Table "threat_intelligence" (${or})`,
    );
  }

  return out;
}

function hashOf(result: DecodeResult): string | null {
  return (
    ctx(result, "sha256") ??
    firstOf(result.artifacts, "hash_sha256")?.normalizedValue ??
    firstOf(result.artifacts, "hash_sha1")?.normalizedValue ??
    firstOf(result.artifacts, "hash_md5")?.normalizedValue ??
    null
  );
}

function pushTi(out: InvestigationQuery[], result: DecodeResult, id: string) {
  const iocs = tiValues(result.artifacts);
  if (iocs.length === 0) return;
  const or = iocs.map((v) => `value = "${quote(v)}" OR ioc = "${quote(v)}"`).join(" OR ");
  push(
    out,
    id,
    "Match TI / MISP sugli IOC pubblici",
    "Controlla se gli IOC sono già in threat intelligence del tenant prima di segnalare.",
    `Table "threat_intelligence" (${or})`,
  );
}

function pushFortiPublic(out: InvestigationQuery[], result: DecodeResult, id: string) {
  const pub = publicIps(result.artifacts);
  const extra = ctx(result, "external_ip");
  const values = extra && !pub.some((a) => a.normalizedValue === extra)
    ? [extra, ...pub.map((a) => a.normalizedValue)]
    : pub.map((a) => a.normalizedValue);
  if (values.length === 0) return;
  const parts = values.slice(0, 6).map((v) => `(${fortigateIpClause(quote(v))})`);
  push(
    out,
    id,
    "Traffico FortiGate verso IP pubblici",
    "Correla l'alert con il firewall sui contatti esterni da citare in segnalazione.",
    `norm_id=FortiOS AND (${parts.join(" OR ")}) | process geoip(source_address) as source_country | process geoip(destination_address) as destination_country | ${FG_FIELDS}`,
  );
}

function defenderPack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const host = ctx(result, "host_name") ?? firstOf(result.artifacts, "hostname")?.normalizedValue;
  const user = ctx(result, "user_name") ?? firstOf(result.artifacts, "email_address")?.normalizedValue
    ?? firstOf(result.artifacts, "username")?.normalizedValue;
  const hash = hashOf(result);
  const path = ctx(result, "file_path") ?? firstOf(result.artifacts, "file_path")?.normalizedValue;
  const title = ctx(result, "incident_name");

  if (host) {
    const h = quote(host);
    push(
      out,
      "def-host",
      "Eventi Defender / Graph sull'host",
      "Timeline MDE sulla macchina dell'evidence, da allegare alla segnalazione.",
      `${DEFENDER_BASE} AND (hostname = "${h}" OR computer = "${h}") | ${DEFENDER_FIELDS}`,
    );
  }
  if (user) {
    const u = quote(user);
    push(
      out,
      "def-user",
      "Utente Defender (UPN / account)",
      "Altri alert e logon dello stesso account.",
      `(${equalsAny(EMAIL_FIELDS, u)}) AND (${DEFENDER_BASE} OR label = "login failed" OR label = logon)`,
    );
  }
  if (hash) {
    push(
      out,
      "def-hash",
      "Hash del file su altri host",
      "Pivoting: lo stesso SHA visto da Defender/AgentX/Cynet.",
      queryForArtifact({
        type: "hash_sha256",
        value: hash,
        normalizedValue: hash,
        scope: "public",
        provenance: "context",
      }),
    );
  }
  if (path) {
    push(
      out,
      "def-path",
      "Path / process image",
      "Cerca esecuzioni dello stesso file o processo.",
      `${DEFENDER_BASE} AND (file_path = "*${quote(path.replace(/\\/g, "\\\\"))}*" OR process_name = "*${quote(path.split(/\\|\//).pop() ?? path)}*")`,
    );
  }
  if (title) {
    push(
      out,
      "def-title",
      "Stesso titolo alert Defender",
      "Quante altre volte lo stesso titolo è uscito nel tenant.",
      `${DEFENDER_BASE} AND (title = "${quote(title)}" OR incident_name = "${quote(title)}" OR msg = "*${quote(title)}*") | chart count() as cnt by hostname, user`,
    );
  }
  pushFortiPublic(out, result, "def-forti-public");
  pushTi(out, result, "def-ti");
  return out;
}

function agentxPack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const host = ctx(result, "host_name") ?? firstOf(result.artifacts, "hostname")?.normalizedValue;
  const user = ctx(result, "user_name") ?? firstOf(result.artifacts, "username")?.normalizedValue;
  const hash = hashOf(result);
  const image = ctx(result, "file_path") ?? firstOf(result.artifacts, "file_path")?.normalizedValue;

  if (host) {
    const h = quote(host);
    push(
      out,
      "ax-host",
      "Hunt AgentX sull'host",
      "Tutti gli eventi AgentX/Sysmon della macchina nel time-range dell'incidente.",
      `${AGENTX_BASE} AND (hostname = "${h}" OR computer = "${h}") | ${AGENTX_FIELDS}`,
    );
  }
  if (user) {
    const u = quote(user);
    push(
      out,
      "ax-user",
      "Utente su AgentX",
      "Processi e logon dello stesso account raccolti dall'agente.",
      `${AGENTX_BASE} AND (user = "${u}" OR targetUserName = "${u}" OR subjectUserName = "${u}" OR parentUser = "${u}") | ${AGENTX_FIELDS}`,
    );
  }
  if (hash) {
    push(
      out,
      "ax-hash",
      "Hash processo AgentX",
      "Stesso hash su altri endpoint AgentX.",
      `${AGENTX_BASE} AND (${queryForArtifact({
        type: "hash_sha256",
        value: hash,
        normalizedValue: hash,
        scope: "public",
        provenance: "context",
      })})`,
    );
  }
  if (image) {
    const name = image.split(/\\|\//).pop() ?? image;
    push(
      out,
      "ax-image",
      "Process image / parent",
      "Creazioni processo con la stessa image vista nel JSON Sysmon.",
      `${AGENTX_BASE} AND (process_name = "*${quote(name)}*" OR file_path = "*${quote(name)}*" OR msg = "*${quote(name)}*") | chart count() as cnt by hostname, user, process_name`,
    );
  }
  pushFortiPublic(out, result, "ax-forti-public");
  pushTi(out, result, "ax-ti");
  return out;
}

function m365Pack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const user = ctx(result, "user_name") ?? firstOf(result.artifacts, "email_address")?.normalizedValue
    ?? firstOf(result.artifacts, "username")?.normalizedValue;
  const operation = ctx(result, "operation");
  const workload = ctx(result, "workload");

  if (user) {
    const u = quote(user);
    push(
      out,
      "m365-user",
      "Audit M365 per UserId",
      "Tutte le Operation dello stesso account nel time-range, da mettere in segnalazione.",
      `${M365_BASE} AND (${equalsAny(EMAIL_FIELDS, u)}) | ${M365_FIELDS}`,
    );
  }
  if (operation) {
    const op = quote(operation);
    const userFilter = user
      ? ` AND (UserId = "${quote(user)}" OR user = "${quote(user)}" OR MailboxOwnerUPN = "${quote(user)}")`
      : "";
    push(
      out,
      "m365-operation",
      "Stessa Operation",
      "Volume della stessa Operation (altri utenti / stessi fallimenti).",
      `${M365_BASE} AND Operation = "${op}"${userFilter} | chart count() as cnt by UserId, ResultStatus | order by cnt desc`,
    );
  }
  if (workload) {
    push(
      out,
      "m365-workload",
      "Workload correlato",
      "Attività nello stesso Workload intorno all'evento.",
      `${M365_BASE} AND Workload = "${quote(workload)}" | timechart count() by Operation`,
    );
  }
  const ip = ctx(result, "host_ip") ?? firstOf(result.artifacts, "ip")?.normalizedValue;
  if (ip) {
    push(
      out,
      "m365-client-ip",
      "ClientIP audit M365",
      "Stesso ClientIP/ActorIpAddress su M365 e, se pubblico, sul firewall.",
      `(${M365_BASE} AND (ClientIP = "${quote(ip)}" OR ClientIPAddress = "${quote(ip)}" OR ActorIpAddress = "${quote(ip)}" OR source_address = "${quote(ip)}")) OR (norm_id=FortiOS AND (${fortigateIpClause(quote(ip))}))`,
    );
  }
  pushTi(out, result, "m365-ti");
  return out;
}

function gsuitePack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const email = ctx(result, "user_name") ?? firstOf(result.artifacts, "email_address")?.normalizedValue;
  const ip = ctx(result, "host_ip") ?? firstOf(result.artifacts, "ip")?.normalizedValue;
  const app = ctx(result, "application");
  const eventName = ctx(result, "incident_name");

  if (email) {
    const e = quote(email);
    push(
      out,
      "gs-user",
      "Attività GSuite dell'attore",
      "Report Google dello stesso utente (login, admin, drive).",
      `${GSUITE_BASE} AND (user = "${e}" OR email = "${e}" OR actor = "${e}") | fields log_ts, user, email, source_address, application, event_name, label, msg`,
    );
  }
  if (ip) {
    push(
      out,
      "gs-ip",
      "IP GSuite + FortiGate",
      "Stesso IP visto da Google e dal firewall.",
      `(${GSUITE_BASE} AND source_address = "${quote(ip)}") OR (norm_id=FortiOS AND (${fortigateIpClause(quote(ip))}))`,
    );
  }
  if (app || eventName) {
    const bits = [GSUITE_BASE];
    if (app) bits.push(`(application = "${quote(app)}" OR applicationName = "${quote(app)}")`);
    if (eventName) bits.push(`(event_name = "${quote(eventName)}" OR name = "${quote(eventName)}")`);
    push(
      out,
      "gs-event",
      "Stesso evento / applicazione Google",
      "Altre occorrenze dello stesso events.name o applicationName.",
      bits.join(" AND "),
    );
  }
  pushTi(out, result, "gs-ti");
  return out;
}

function bitdefenderPack(result: DecodeResult): InvestigationQuery[] {
  const out: InvestigationQuery[] = [];
  const host = ctx(result, "host_name") ?? firstOf(result.artifacts, "hostname")?.normalizedValue;
  const detection = ctx(result, "incident_name");
  const src = ctx(result, "host_ip") ?? firstOf(result.artifacts, "ip")?.normalizedValue;
  const url = ctx(result, "url") ?? firstOf(result.artifacts, "url")?.normalizedValue;

  if (host) {
    push(
      out,
      "bd-host",
      "Eventi Bitdefender sull'host",
      "Altre detection GravityZone sulla stessa FQDN, non traffico Forti IPS.",
      `${BD_BASE} AND (hostname = "${quote(host)}" OR computer = "${quote(host)}" OR fqdn = "${quote(host)}" OR BitdefenderGZComputerFQDN = "${quote(host)}") | ${BD_FIELDS}`,
    );
  }
  if (detection) {
    push(
      out,
      "bd-detection",
      "Stesso DetectionName",
      "Quante macchine hanno la stessa detection Bitdefender.",
      `${BD_BASE} AND (threat_name = "${quote(detection)}" OR DetectionName = "${quote(detection)}" OR BitdefenderGZDetectionName = "${quote(detection)}" OR msg = "*${quote(detection)}*") | chart count() as cnt by hostname, BitdefenderGZComputerFQDN, action`,
    );
  }
  if (src) {
    push(
      out,
      "bd-src",
      "Source IP Bitdefender",
      "IP src dell'alert su Bitdefender e, se pubblico, anche su FortiGate traffic.",
      `${BD_BASE} AND (source_address = "${quote(src)}" OR src = "${quote(src)}" OR dvc = "${quote(src)}") | ${BD_FIELDS}`,
    );
  }
  if (url) {
    push(
      out,
      "bd-url",
      "URL / request Bitdefender",
      "Stesso URL visto da GravityZone.",
      `${BD_BASE} AND (url = "${quote(url)}" OR request = "${quote(url)}")`,
    );
  }
  pushFortiPublic(out, result, "bd-forti-public");
  pushTi(out, result, "bd-ti");
  return out;
}

export function buildInvestigationPack(
  result: DecodeResult,
  allowlist?: Allowlist | null,
): InvestigationQuery[] {
  if (result.error || result.artifacts.length === 0) return [];
  let pack: InvestigationQuery[];
  if (result.vendor === "Cynet") pack = cynetPack(result);
  else if (result.vendor === "Defender") pack = defenderPack(result);
  else if (result.vendor === "AgentX") pack = agentxPack(result);
  else if (result.vendor === "Microsoft365") pack = m365Pack(result);
  else if (result.vendor === "GSuite") pack = gsuitePack(result);
  else if (result.vendor === "Bitdefender") pack = bitdefenderPack(result);
  else if (result.vendor === "FortiGate") pack = fortigatePack(result);
  else pack = genericPack(result);

  if (!allowlist) return pack;
  return pack.map((q) => ({
    ...q,
    query: applyAllowlistToQuery(q.query, allowlist),
  }));
}
