import { CsvVtScanner } from "@/components/CsvVtScanner";

export default function App() {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <h1>CSV VT Scanner</h1>
          <p className="app-subtitle">SOC Automation Hub — verifica IP da export LogPoint</p>
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
      <main className="app-main csvvt-main">
        <CsvVtScanner />
      </main>
    </div>
  );
}
