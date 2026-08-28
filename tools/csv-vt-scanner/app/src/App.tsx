import { useState } from "react";
import { AlertCoveragePanel } from "@/components/AlertCoveragePanel";
import { BulkIocPanel, HUB_PREFILL_IOC } from "@/components/BulkIocPanel";
import { CsvPivotPanel } from "@/components/CsvPivotPanel";
import { CsvVtScanner } from "@/components/CsvVtScanner";
import { SiemDecoderPanel } from "@/components/SiemDecoderPanel";

type HubTab = "csv-vt" | "alert-rules" | "siem-decoder" | "csv-pivot" | "bulk-ioc";

const TABS: { id: HubTab; label: string }[] = [
  { id: "csv-vt", label: "CSV VT Scanner" },
  { id: "alert-rules", label: "Alert Rule Planner" },
  { id: "siem-decoder", label: "SIEM Decoder" },
  { id: "csv-pivot", label: "CSV Pivot" },
  { id: "bulk-ioc", label: "Bulk IOC" },
];

export default function App() {
  const [tab, setTab] = useState<HubTab>("csv-vt");

  const sendToBulk = (iocText: string) => {
    sessionStorage.setItem(HUB_PREFILL_IOC, iocText);
    setTab("bulk-ioc");
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <h1>SOC Automation Hub</h1>
          <p className="app-subtitle">Demo tool per automazione SOC</p>
        </div>
        <a
          className="header-link"
          href="https://github.com/DarkGreen-projects/soc-automation-hub"
          target="_blank"
          rel="noreferrer"
        >
          GitHub
        </a>
      </header>

      <nav className="hub-tabs">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            className={`hub-tab ${tab === id ? "hub-tab-active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      <main className="app-main hub-main">
        {tab === "csv-vt" && <CsvVtScanner />}
        {tab === "alert-rules" && <AlertCoveragePanel />}
        {tab === "siem-decoder" && <SiemDecoderPanel onSendToBulk={sendToBulk} />}
        {tab === "csv-pivot" && <CsvPivotPanel />}
        {tab === "bulk-ioc" && <BulkIocPanel />}
      </main>
    </div>
  );
}
