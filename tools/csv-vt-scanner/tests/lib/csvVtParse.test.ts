import { describe, expect, it } from "vitest";
import { buildAllResultsCsv, buildMaliciousCsv } from "../../app/src/lib/csvVt/exportCsv";
import { parseLogpointIpCsv, scannableRows } from "../../app/src/lib/csvVt/parseCsv";
import { estimateEtaSeconds, formatEta } from "../../app/src/lib/csvVt/scan";
import {
  classifyVtResult,
  computePercents,
  computeStats,
  initialResults,
} from "../../app/src/lib/csvVt/stats";
import type { ScanRowResult } from "../../app/src/lib/csvVt/types";

describe("parseLogpointIpCsv", () => {
  it("parses rows without header", () => {
    const text = [
      "8.8.8.8,United States,100,dns",
      "1.1.1.1,Australia,50,dns",
    ].join("\n");
    const parsed = parseLogpointIpCsv(text);
    expect(parsed.hadHeader).toBe(false);
    expect(parsed.uniqueCount).toBe(2);
    expect(parsed.rows[0].ip).toBe("8.8.8.8");
    expect(parsed.rows[0].country).toBe("United States");
    expect(parsed.rows[0].count).toBe("100");
    expect(parsed.rows[0].eventType).toBe("dns");
    expect(parsed.rows[0].skipped).toBe(false);
  });

  it("detects header and skips it", () => {
    const text = [
      "ip,country,count,event_type",
      "8.8.4.4,United States,10,server-rst",
    ].join("\n");
    const parsed = parseLogpointIpCsv(text);
    expect(parsed.hadHeader).toBe(true);
    expect(parsed.rows).toHaveLength(1);
    expect(parsed.rows[0].ip).toBe("8.8.4.4");
  });

  it("dedups by IP keeping first occurrence", () => {
    const text = [
      "8.8.8.8,US,100,a",
      "8.8.8.8,US,200,b",
    ].join("\n");
    const parsed = parseLogpointIpCsv(text);
    expect(parsed.uniqueCount).toBe(1);
    expect(parsed.rows[0].count).toBe("100");
    expect(parsed.rows[0].eventType).toBe("a");
  });

  it("marks private as skipped; lines without IPv4 are ignored", () => {
    const text = [
      "192.168.1.1,Finland,13500,server-rst",
      "10.0.0.5,Internal,1,x",
      "not-an-ip,Nowhere,1,y",
      "1.2.3.4,Public,9,z",
    ].join("\n");
    const parsed = parseLogpointIpCsv(text);
    expect(parsed.rows).toHaveLength(3);
    expect(parsed.rows.find((r) => r.ip === "192.168.1.1")?.skipped).toBe(true);
    expect(parsed.rows.find((r) => r.ip === "192.168.1.1")?.skipReason).toBe("private");
    expect(parsed.rows.find((r) => r.ip === "not-an-ip")).toBeUndefined();
    expect(scannableRows(parsed.rows)).toHaveLength(1);
    expect(scannableRows(parsed.rows)[0].ip).toBe("1.2.3.4");
  });

  it("handles quoted commas", () => {
    const text = `"8.8.8.8","United States, Inc",42,"server-rst"`;
    const parsed = parseLogpointIpCsv(text);
    expect(parsed.rows[0].country).toBe("United States, Inc");
  });

  it("extracts multiple IPs from a free-text line", () => {
    const text = "alert src=1.2.3.4 dst=5.6.7.8 proto=tcp";
    const parsed = parseLogpointIpCsv(text);
    expect(scannableRows(parsed.rows).map((r) => r.ip)).toEqual(["1.2.3.4", "5.6.7.8"]);
  });

  it("keeps structured metadata and also queues extra IPs on the same line", () => {
    const text = "8.8.8.8,US,10,dns,peer=9.9.9.9";
    const parsed = parseLogpointIpCsv(text);
    expect(parsed.uniqueCount).toBe(2);
    const main = parsed.rows.find((r) => r.ip === "8.8.8.8");
    expect(main?.country).toBe("US");
    expect(main?.count).toBe("10");
    expect(main?.eventType).toBe("dns");
    const extra = parsed.rows.find((r) => r.ip === "9.9.9.9");
    expect(extra?.skipped).toBe(false);
    expect(extra?.country).toBe("");
  });

  it("skips private IPs found inside free text", () => {
    const text = "conn 10.0.0.1 -> 8.8.4.4";
    const parsed = parseLogpointIpCsv(text);
    expect(parsed.rows.find((r) => r.ip === "10.0.0.1")?.skipReason).toBe("private");
    expect(scannableRows(parsed.rows).map((r) => r.ip)).toEqual(["8.8.4.4"]);
  });

  it("dedups IPs across free-text lines", () => {
    const text = ["hit 1.1.1.1 once", "again 1.1.1.1 and 2.2.2.2"].join("\n");
    const parsed = parseLogpointIpCsv(text);
    expect(scannableRows(parsed.rows).map((r) => r.ip)).toEqual(["1.1.1.1", "2.2.2.2"]);
  });
});

describe("classifyVtResult / stats", () => {
  it("classifies malicious when malicious >= 1", () => {
    expect(
      classifyVtResult({
        status: "success",
        summary: "ok",
        malicious: 1,
        total: 90,
      }),
    ).toBe("malicious");
    expect(
      classifyVtResult({
        status: "success",
        summary: "ok",
        malicious: 0,
        total: 90,
      }),
    ).toBe("clean");
    expect(classifyVtResult({ status: "not_found", summary: "404" })).toBe("not_found");
    expect(classifyVtResult({ status: "error", summary: "429" })).toBe("error");
  });

  it("computes counts and percentages", () => {
    const results: ScanRowResult[] = [
      {
        ip: "1.1.1.1",
        country: "AU",
        count: "1",
        eventType: "a",
        skipped: false,
        category: "malicious",
      },
      {
        ip: "8.8.8.8",
        country: "US",
        count: "1",
        eventType: "a",
        skipped: false,
        category: "clean",
      },
      {
        ip: "9.9.9.9",
        country: "US",
        count: "1",
        eventType: "a",
        skipped: false,
        category: "not_found",
      },
      {
        ip: "192.168.0.1",
        country: "LAN",
        count: "1",
        eventType: "a",
        skipped: true,
        skipReason: "private",
        category: "skipped",
      },
      {
        ip: "2.2.2.2",
        country: "X",
        count: "1",
        eventType: "a",
        skipped: false,
        category: "error",
      },
    ];
    const stats = computeStats(results);
    expect(stats).toMatchObject({
      total: 5,
      malicious: 1,
      clean: 1,
      notFound: 1,
      error: 1,
      skipped: 1,
      pending: 0,
      done: 5,
    });
    expect(computePercents(stats)).toEqual({
      malicious: 20,
      clean: 20,
      notFound: 20,
      error: 20,
      skipped: 20,
    });
  });

  it("initialResults marks private as skipped and public as pending", () => {
    const parsed = parseLogpointIpCsv("10.0.0.1,x,1,a\n1.1.1.1,y,2,b");
    const init = initialResults(parsed.rows);
    expect(init.find((r) => r.ip === "10.0.0.1")?.category).toBe("skipped");
    expect(init.find((r) => r.ip === "1.1.1.1")?.category).toBe("pending");
  });
});

describe("exportCsv builders", () => {
  it("exports only malicious rows", () => {
    const results: ScanRowResult[] = [
      {
        ip: "1.1.1.1",
        country: "AU",
        count: "1",
        eventType: "dns",
        skipped: false,
        category: "malicious",
        vt: {
          status: "success",
          summary: "ok",
          malicious: 3,
          total: 90,
          detectionRatio: "3/90",
          permalink: "https://www.virustotal.com/gui/ip-address/1.1.1.1",
        },
      },
      {
        ip: "8.8.8.8",
        country: "US",
        count: "2",
        eventType: "dns",
        skipped: false,
        category: "clean",
        vt: { status: "success", summary: "ok", malicious: 0, total: 90 },
      },
    ];
    const csv = buildMaliciousCsv(results);
    expect(csv).toContain("1.1.1.1");
    expect(csv).not.toContain("8.8.8.8");
    expect(csv.split(/\r?\n/).filter(Boolean)).toHaveLength(2);

    const all = buildAllResultsCsv(results);
    expect(all).toContain("8.8.8.8");
  });
});

describe("ETA helpers", () => {
  it("estimates and formats ETA with multiple keys", () => {
    expect(estimateEtaSeconds(4)).toBe(60);
    expect(estimateEtaSeconds(4, 15, 4)).toBe(15);
    expect(estimateEtaSeconds(2000, 15, 4)).toBe(7500);
    expect(formatEta(60)).toBe("1m 0s");
    expect(formatEta(0)).toBe("—");
  });
});

describe("resume helpers", () => {
  it("counts resumable and classified rows (skipped excluded)", async () => {
    const { countClassified, countResumable } = await import(
      "../../app/src/lib/csvVt/scan"
    );
    const rows = [
      {
        ip: "1.1.1.1",
        country: "a",
        count: "1",
        eventType: "x",
        skipped: false,
        category: "malicious" as const,
      },
      {
        ip: "2.2.2.2",
        country: "a",
        count: "1",
        eventType: "x",
        skipped: false,
        category: "pending" as const,
      },
      {
        ip: "3.3.3.3",
        country: "a",
        count: "1",
        eventType: "x",
        skipped: false,
        category: "error" as const,
      },
      {
        ip: "192.168.0.1",
        country: "lan",
        count: "1",
        eventType: "x",
        skipped: true,
        skipReason: "private" as const,
        category: "skipped" as const,
      },
    ];
    expect(countResumable(rows)).toBe(2);
    expect(countClassified(rows)).toBe(2);
  });
});
