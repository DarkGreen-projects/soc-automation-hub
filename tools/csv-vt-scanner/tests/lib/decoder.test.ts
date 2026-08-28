import { describe, expect, it } from "vitest";
import { buildInvestigationPack } from "../../app/src/lib/decoder/investigationPack";
import { combineReliability, osintEligible, osintPermalinks } from "../../app/src/lib/decoder/osint";
import { decodeSiemText, queryForArtifact } from "../../app/src/lib/decoder/pipeline";
import {
  captureSchema,
  catalogToJson,
  mergeIntoCatalog,
} from "../../app/src/lib/decoder/schemaCapture";
import type { Artifact } from "../../app/src/lib/decoder/types";

describe("decodeSiemText", () => {
  it("extracts Cynet JSON fields", () => {
    const raw = JSON.stringify({
      HostName: "FTP-101",
      HostIp: "172.16.21.7",
      UserName: "DentalFeel",
      Sha256Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      IncidentName: "Logon Failure",
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("Cynet");
    expect(result.artifacts.some((a) => a.type === "ip" && a.value === "172.16.21.7")).toBe(
      true,
    );
    expect(result.artifacts.some((a) => a.type === "hostname" && a.value === "FTP-101")).toBe(
      true,
    );
    expect(result.artifacts.some((a) => a.type === "hash_sha256")).toBe(true);
    expect(result.artifacts.find((a) => a.type === "ip")?.scope).toBe("internal");
  });

  it("unwraps nested full_log JSON", () => {
    const inner = JSON.stringify({
      HostIp: "10.1.2.3",
      HostName: "WKS01",
    });
    const raw = JSON.stringify({
      AgentX_Alert_win: { full_log: inner },
    });
    const result = decodeSiemText(raw);
    expect(result.artifacts.some((a) => a.value === "10.1.2.3")).toBe(true);
  });

  it("parses FortiGate key=value syslog", () => {
    const raw =
      'date=2026-07-30 time=11:48:14 type="utm" subtype="ips" srcip=8.8.8.8 dstip=10.0.0.5 attack="Censys.io.Scanner" url="/" hostname="example.com"';
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("FortiGate");
    expect(result.artifacts.some((a) => a.type === "ip" && a.value === "8.8.8.8")).toBe(true);
    expect(result.artifacts.find((a) => a.value === "8.8.8.8")?.scope).toBe("public");
    expect(result.artifacts.some((a) => a.type === "ip" && a.value === "10.0.0.5")).toBe(true);
  });

  it("parses an IOC list", () => {
    const result = decodeSiemText(
      "8.8.8.8, 1.2.3.4; aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    expect(result.format).toBe("ioc");
    expect(result.artifacts.filter((a) => a.type === "ip")).toHaveLength(2);
    expect(result.artifacts.some((a) => a.type === "hash_sha256")).toBe(true);
  });

  it("builds a LogPoint query for a public IP", () => {
    const q = queryForArtifact({
      type: "ip",
      value: "8.8.8.8",
      normalizedValue: "8.8.8.8",
      scope: "public",
      provenance: "test",
    });
    expect(q).toContain('source_address = "8.8.8.8"');
    expect(q).toContain('ClientIP = "8.8.8.8"');
    expect(q).toContain('srcip = "8.8.8.8"');
    expect(q).toContain('ActorIpAddress = "8.8.8.8"');
  });

  it("builds hash queries covering Bitdefender and AgentX hashes blob", () => {
    const hash = "a".repeat(64);
    const q = queryForArtifact({
      type: "hash_sha256",
      value: hash,
      normalizedValue: hash,
      scope: "public",
      provenance: "test",
    });
    expect(q).toContain(`BitdefenderGZMalwareHash = "${hash}"`);
    expect(q).toContain(`hashes = "*${hash}*"`);
  });

  it("builds email queries with MailboxOwnerUPN / UserId", () => {
    const q = queryForArtifact({
      type: "email_address",
      value: "a@b.test",
      normalizedValue: "a@b.test",
      scope: "internal",
      provenance: "test",
    });
    expect(q).toContain('MailboxOwnerUPN = "a@b.test"');
    expect(q).toContain('UserId = "a@b.test"');
  });
});

const publicIp = (value: string): Artifact => ({
  type: "ip",
  value,
  normalizedValue: value,
  scope: "public",
  provenance: "test",
});

const internalIp = (value: string): Artifact => ({
  type: "ip",
  value,
  normalizedValue: value,
  scope: "internal",
  provenance: "test",
});

describe("osintEligible", () => {
  it("skips RFC1918 IPs", () => {
    expect(osintEligible(internalIp("172.16.21.7"))).toBe(false);
  });

  it("allows public IPs, hashes and domains", () => {
    expect(osintEligible(publicIp("8.8.8.8"))).toBe(true);
    expect(
      osintEligible({
        type: "hash_sha256",
        value: "aa".repeat(32),
        normalizedValue: "aa".repeat(32),
        scope: "public",
        provenance: "test",
      }),
    ).toBe(true);
  });

  it("skips hostname and username", () => {
    expect(
      osintEligible({
        type: "hostname",
        value: "WKS01",
        normalizedValue: "WKS01",
        scope: "public",
        provenance: "test",
      }),
    ).toBe(false);
  });

  it("builds VT and AbuseIPDB links for public IPs", () => {
    const links = osintPermalinks(publicIp("8.8.8.8"));
    expect(links.vt).toBe("https://www.virustotal.com/gui/ip-address/8.8.8.8");
    expect(links.abuse).toBe("https://www.abuseipdb.com/check/8.8.8.8");
  });

  it("does not build OSINT links for internal IPs", () => {
    expect(osintPermalinks(internalIp("172.16.21.7"))).toEqual({});
  });
});

describe("combineReliability", () => {
  it("marks internal without looking at scores", () => {
    expect(
      combineReliability("internal", { status: "success", summary: "", malicious: 90 }, undefined),
    ).toBe("interno");
  });

  it("returns alto for high VT or Abuse scores", () => {
    expect(
      combineReliability("public", { status: "success", summary: "", malicious: 12, total: 90 }),
    ).toBe("alto");
    expect(
      combineReliability("public", undefined, {
        status: "success",
        summary: "",
        abuseConfidenceScore: 80,
      }),
    ).toBe("alto");
  });

  it("returns medio for low-positive detections", () => {
    expect(
      combineReliability("public", { status: "success", summary: "", malicious: 2, total: 90 }),
    ).toBe("medio");
    expect(
      combineReliability("public", undefined, {
        status: "success",
        summary: "",
        abuseConfidenceScore: 30,
      }),
    ).toBe("medio");
  });

  it("returns basso when VT is clean", () => {
    expect(
      combineReliability("public", { status: "success", summary: "", malicious: 0, total: 90 }),
    ).toBe("basso");
  });

  it("returns sconosciuto when VT has no record", () => {
    expect(combineReliability("public", { status: "not_found", summary: "" })).toBe("sconosciuto");
  });
});

describe("buildInvestigationPack", () => {
  it("builds Cynet host, user, hash and FortiGate queries", () => {
    const result = decodeSiemText(
      JSON.stringify({
        HostName: "FTP-101",
        HostIp: "172.16.21.7",
        UserName: "DentalFeel",
        Sha256Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        Path: "C:\\temp\\evil.exe",
        IncidentName: "Logon Failure",
        AlertUrl: "http://evil.example/payload",
      }),
    );
    const pack = buildInvestigationPack(result);
    const ids = pack.map((q) => q.id);
    expect(ids).toContain("cynet-host-timeline");
    expect(ids).toContain("cynet-host-alerts");
    expect(ids).toContain("cynet-user");
    expect(ids).toContain("cynet-hash");
    expect(ids).toContain("cynet-path");
    expect(ids).toContain("cynet-forti-hostip");
    expect(ids).toContain("cynet-ti");
    expect(pack.find((q) => q.id === "cynet-host-timeline")?.query).toContain('hostname = "FTP-101"');
    expect(pack.find((q) => q.id === "cynet-forti-hostip")?.query).toContain("172.16.21.7");
  });

  it("builds FortiGate src/dst and attack queries", () => {
    const result = decodeSiemText(
      'date=2026-07-30 time=11:48:14 type="utm" subtype="ips" srcip=8.8.8.8 dstip=10.0.0.5 attack="Censys.io.Scanner" url="/" user="alice"',
    );
    const pack = buildInvestigationPack(result);
    const ids = pack.map((q) => q.id);
    expect(ids).toContain("fg-same-ips");
    expect(ids).toContain("fg-same-attack");
    expect(ids).toContain("fg-user");
    expect(ids).toContain("fg-ips-related");
    expect(pack.find((q) => q.id === "fg-same-ips")?.query).toContain("8.8.8.8");
    expect(pack.find((q) => q.id === "fg-same-attack")?.query).toContain("Censys.io.Scanner");
  });

  it("builds generic OR hunt for an IOC list", () => {
    const result = decodeSiemText("8.8.8.8, 1.2.3.4");
    const pack = buildInvestigationPack(result);
    expect(pack.some((q) => q.id.startsWith("generic-"))).toBe(true);
    expect(pack.some((q) => q.query.includes("8.8.8.8"))).toBe(true);
  });
});

describe("captureSchema", () => {
  const cynetRaw = JSON.stringify({
    HostName: "FTP-101",
    HostIp: "172.16.21.7",
    UserName: "DentalFeel",
    Sha256Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    IncidentName: "Logon Failure",
    Path: "C:\\temp\\evil.exe",
  });

  it("records field names and kinds without real values", () => {
    const decoded = decodeSiemText(cynetRaw);
    const sample = captureSchema(cynetRaw, decoded);
    expect(sample).not.toBeNull();
    const json = catalogToJson({ samples: [sample!] });
    expect(json).not.toContain("172.16.21.7");
    expect(json).not.toContain("DentalFeel");
    expect(json).not.toContain("FTP-101");
    expect(json).not.toContain("Logon Failure");
    expect(json).not.toContain("evil.exe");
    expect(json).not.toContain("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(sample!.fields.some((f) => f.path.includes("HostIp") && f.kind === "ip")).toBe(true);
    expect(sample!.fields.some((f) => f.path.includes("UserName") && f.kind === "username")).toBe(
      true,
    );
    expect(sample!.fields.some((f) => f.path.includes("Sha256Hex") && f.kind === "hash")).toBe(true);
    expect(sample!.contextKeys).toContain("host_name");
    expect(sample!.contextKeys).not.toContain("FTP-101");
    expect(sample!.artifactStats.some((s) => s.type === "ip" && s.scope === "internal")).toBe(true);
  });

  it("increments seenCount for the same schema", () => {
    const decoded = decodeSiemText(cynetRaw);
    const first = captureSchema(cynetRaw, decoded)!;
    const second = captureSchema(cynetRaw, decoded)!;
    const merged = mergeIntoCatalog(mergeIntoCatalog({ samples: [] }, first), second);
    expect(merged.samples).toHaveLength(1);
    expect(merged.samples[0]?.seenCount).toBe(2);
  });

  it("omits FortiGate IP values from the catalog", () => {
    const raw =
      'date=2026-07-30 time=11:48:14 type="utm" subtype="ips" srcip=8.8.8.8 dstip=10.0.0.5 attack="Censys.io.Scanner" url="/" hostname="example.com"';
    const decoded = decodeSiemText(raw);
    const sample = captureSchema(raw, decoded)!;
    const json = JSON.stringify(sample);
    expect(json).not.toContain("8.8.8.8");
    expect(json).not.toContain("10.0.0.5");
    expect(json).not.toContain("example.com");
    expect(sample.fields.some((f) => f.path.includes("srcip") && f.kind === "ip")).toBe(true);
  });
});

describe("vendor detection from real schemas", () => {
  const sha256 = "bb".repeat(32);
  const sha1 = "cc".repeat(20);

  it("detects Defender Graph and builds host/hash queries", () => {
    const raw = JSON.stringify({
      MicrosoftGraph: {
        title: "Suspicious process",
        evidence: [
          {
            hostName: "WKS-TEST01",
            lastIpAddress: "10.0.0.8",
            lastExternalIpAddress: "203.0.113.10",
            imageFile: {
              sha256,
              sha1,
              filePath: "C:\\temp\\a.exe",
              fileName: "a.exe",
            },
            userAccount: {
              accountName: "jdoe",
              userPrincipalName: "jdoe@contoso.test",
            },
            processCommandLine: "a.exe --x",
          },
        ],
      },
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("Defender");
    expect(result.artifacts.some((a) => a.type === "hostname" && a.value === "WKS-TEST01")).toBe(
      true,
    );
    expect(result.artifacts.some((a) => a.type === "hash_sha256")).toBe(true);
    const pack = buildInvestigationPack(result);
    const ids = pack.map((q) => q.id);
    expect(ids).toContain("def-host");
    expect(ids).toContain("def-hash");
    expect(pack.find((q) => q.id === "def-host")?.query).toContain("MicrosoftGraph");
    expect(pack.some((q) => q.query.includes("Cynet"))).toBe(false);
  });

  it("detects AgentX Sysmon JSON and does not use Cynet queries", () => {
    const raw = JSON.stringify({
      AgentX_Alert_win: {
        agent: { ip: "10.1.1.1", name: "WKS-AX" },
        full_log: {
          win: {
            system: { computer: "WKS-AX", eventID: "1" },
            eventdata: {
              user: "CONTOSO\\alice",
              hashes: `SHA256=${sha256},MD5=${"ee".repeat(16)}`,
              image: "C:\\Windows\\System32\\cmd.exe",
              commandLine: "cmd.exe /c whoami",
              parentImage: "C:\\Windows\\explorer.exe",
            },
          },
        },
      },
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("AgentX");
    expect(result.artifacts.some((a) => a.type === "hostname" && a.value === "WKS-AX")).toBe(true);
    expect(result.artifacts.some((a) => a.type === "hash_sha256")).toBe(true);
    const pack = buildInvestigationPack(result);
    expect(pack.some((q) => q.query.includes("col_type = AgentX"))).toBe(true);
    expect(pack.some((q) => q.query.includes("Cynet"))).toBe(false);
  });

  it("detects GSuite actor and IP", () => {
    const raw = JSON.stringify({
      GSuite: {
        actor: { email: "user@example.test" },
        ipAddress: "203.0.113.20",
        id: { applicationName: "login" },
        events: [{ name: "login_success" }],
      },
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("GSuite");
    expect(result.artifacts.some((a) => a.type === "email_address")).toBe(true);
    const pack = buildInvestigationPack(result);
    expect(pack.some((q) => q.id === "gs-user")).toBe(true);
    expect(pack.find((q) => q.id === "gs-user")?.query).toContain("GSuite");
  });

  it("detects Microsoft 365 audit JSON", () => {
    const raw = JSON.stringify({
      UserId: "admin@contoso.test",
      Operation: "UserLoggedIn",
      Workload: "AzureActiveDirectory",
      Actor: [{ ID: "admin@contoso.test" }],
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("Microsoft365");
    const pack = buildInvestigationPack(result);
    expect(pack.map((q) => q.id)).toContain("m365-user");
    expect(pack.find((q) => q.id === "m365-operation")?.query).toContain("UserLoggedIn");
  });

  it("detects Bitdefender CEF instead of FortiGate IPS", () => {
    const raw =
      "CEF:0|Bitdefender|GravityZone|1|1|Malware|7|BitdefenderGZComputerFQDN=host.contoso.test BitdefenderGZDetectionName=Trojan.Generic src=203.0.113.5 request=http://evil.test/payload sproc=scanner.exe";
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("Bitdefender");
    expect(result.artifacts.some((a) => a.type === "hostname")).toBe(true);
    const pack = buildInvestigationPack(result);
    expect(pack.some((q) => q.id.startsWith("bd-"))).toBe(true);
    expect(pack.some((q) => q.query.includes("sub_category=ips"))).toBe(false);
    expect(pack.find((q) => q.id === "bd-host")?.query).toContain("Bitdefender");
  });

  it("adds FortiGate app/service queries from syslog fields", () => {
    const raw =
      'date=2026-07-30 time=11:48:14 type="utm" subtype="app-ctrl" srcip=10.0.0.9 dstip=1.1.1.1 app="SSH" service="SSH" direction="outgoing" action="pass"';
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("FortiGate");
    expect(result.context.app).toBe("SSH");
    const pack = buildInvestigationPack(result);
    expect(pack.map((q) => q.id)).toContain("fg-app");
    expect(pack.map((q) => q.id)).toContain("fg-service-direction");
  });

  it("maps FortiGate CEF src/dst into pack queries", () => {
    const raw =
      "CEF:0|Fortinet|Fortigate|7.0|00000|traffic:start|5|src=203.0.113.8 dst=10.0.0.9 act=pass app=HTTPS FTNTFGTsubtype=app-ctrl FTNTFGTappcat=Web deviceDirection=1 spt=54321 dpt=443";
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("FortiGate");
    expect(result.context.srcip).toBe("203.0.113.8");
    expect(result.context.dstip).toBe("10.0.0.9");
    expect(result.context.action).toBe("pass");
    expect(result.context.subtype).toBe("app-ctrl");
    expect(result.context.direction).toBe("outgoing");
    const pack = buildInvestigationPack(result);
    expect(pack.find((q) => q.id === "fg-same-ips")?.query).toContain("203.0.113.8");
    expect(pack.map((q) => q.id)).toContain("fg-app");
  });

  it("extracts AgentX Security logon targetUserName", () => {
    const raw = JSON.stringify({
      AgentX_win: {
        agent: { ip: "10.2.2.2", name: "DC01" },
        full_log: {
          win: {
            system: { computer: "DC01", eventID: "4624" },
            eventdata: {
              targetUserName: "bob",
              subjectUserName: "SYSTEM",
              ipAddress: "203.0.113.40",
              logonType: "3",
              targetUserSid: "S-1-5-21-1-2-3-4",
            },
          },
        },
      },
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("AgentX");
    expect(result.context.user_name).toBe("bob");
    expect(result.artifacts.some((a) => a.type === "username" && a.value === "bob")).toBe(true);
    expect(result.artifacts.some((a) => a.value.startsWith("S-1-5-"))).toBe(false);
    expect(result.artifacts.some((a) => a.type === "ip" && a.value === "203.0.113.40")).toBe(true);
    const pack = buildInvestigationPack(result);
    expect(pack.find((q) => q.id === "ax-user")?.query).toContain("bob");
  });

  it("extracts AgentX process create newProcessName", () => {
    const raw = JSON.stringify({
      AgentX_Alert_win: {
        agent: { ip: "10.3.3.3", name: "WKS-4688" },
        full_log: {
          win: {
            system: { computer: "WKS-4688", eventID: "4688" },
            eventdata: {
              subjectUserName: "alice",
              newProcessName: "C:\\Windows\\System32\\cmd.exe",
              parentProcessName: "C:\\Windows\\explorer.exe",
              commandLine: "cmd.exe /c whoami",
            },
          },
        },
      },
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("AgentX");
    expect(result.context.file_path).toContain("cmd.exe");
    expect(result.context.user_name).toBe("alice");
    const pack = buildInvestigationPack(result);
    expect(pack.some((q) => q.id === "ax-image")).toBe(true);
  });

  it("extracts M365 ClientIP into the pack", () => {
    const raw = JSON.stringify({
      UserId: "admin@contoso.test",
      Operation: "FileDownloaded",
      Workload: "SharePoint",
      ClientIP: "203.0.113.77",
      ActorIpAddress: "203.0.113.77",
    });
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("Microsoft365");
    expect(result.context.host_ip).toBe("203.0.113.77");
    const pack = buildInvestigationPack(result);
    expect(pack.map((q) => q.id)).toContain("m365-client-ip");
    expect(pack.find((q) => q.id === "m365-client-ip")?.query).toContain("203.0.113.77");
    expect(pack.find((q) => q.id === "m365-user")?.query).toContain("MailboxOwnerUPN");
    expect(pack.find((q) => q.id === "m365-user")?.query).toContain("ClientIPAddress");
  });

  it("FortiGate pack queries raw srcip/dstip aliases from schemas", () => {
    const raw =
      'date=2024-01-01 time=12:00:00 devid=FG100 srcip=203.0.113.10 dstip=198.51.100.20 subtype=ips attack="Test.Signature" action=dropped';
    const result = decodeSiemText(raw);
    expect(result.vendor).toBe("FortiGate");
    const pack = buildInvestigationPack(result);
    const sameIps = pack.find((q) => q.id === "fg-same-ips")?.query ?? "";
    expect(sameIps).toContain("srcip");
    expect(sameIps).toContain("203.0.113.10");
  });

  it("labels Bitdefender CEF schemas with Bitdefender prefix", () => {
    const raw =
      "CEF:0|Bitdefender|GravityZone|1|1|Malware|7|BitdefenderGZComputerFQDN=host.contoso.test BitdefenderGZDetectionName=Trojan.Generic src=203.0.113.5";
    const decoded = decodeSiemText(raw);
    const sample = captureSchema(raw, decoded)!;
    expect(decoded.vendor).toBe("Bitdefender");
    expect(sample.fields.some((f) => f.path.startsWith("Bitdefender."))).toBe(true);
    expect(sample.fields.some((f) => f.path.startsWith("FortiGate.Bitdefender"))).toBe(false);
  });
});
