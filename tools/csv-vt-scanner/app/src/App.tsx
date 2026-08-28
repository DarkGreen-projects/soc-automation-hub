import { useState } from "react";
import { AlertCoveragePanel } from "@/components/AlertCoveragePanel";
import { CsvVtScanner } from "@/components/CsvVtScanner";

type HubTab = "csv-vt" | "alert-rules";

export default function App() {
  const [tab, setTab] = useState<HubTab>("csv-vt");

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
        <button
          type="button"
          className={`hub-tab ${tab === "csv-vt" ? "hub-tab-active" : ""}`}
          onClick={() => setTab("csv-vt")}
        >
          CSV VT Scanner
        </button>
        <button
          type="button"
          className={`hub-tab ${tab === "alert-rules" ? "hub-tab-active" : ""}`}
          onClick={() => setTab("alert-rules")}
        >
          Alert Rule Planner
        </button>
      </nav>

      <main className="app-main hub-main">
        {tab === "csv-vt" ? <CsvVtScanner /> : <AlertCoveragePanel />}
      </main>
    </div>
  );
}
