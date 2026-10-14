import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { ChevronDown, Download, FileText, Link2, Printer, RotateCw, Sparkles } from "lucide-react";
import RiskSummary from "./RiskSummary";
import FindingsExplorer from "./FindingsExplorer";
import PosturePanel, { SourcesList } from "./PosturePanel";
import Markdown from "../Markdown";
import { GitHubMark } from "../Logo";
import { SEVERITIES } from "../../lib/severity";
import { formatDate } from "../../lib/format";
import { download, reportToMarkdown } from "../../lib/exportMarkdown";
import { makeShareLink } from "../../lib/share";
import { startScan } from "../../lib/scans";
import { toast } from "../../lib/toast";
import "../../styles/report.css";

function ExportMenu({ report }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const close = (e) => {
      if (e.type === "keydown" ? e.key === "Escape" : !ref.current?.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  const slug = (report.target?.slug || "report").replace("/", "-");
  const date = (report.scanTimestamp || "").slice(0, 10);

  return (
    <div className="menu" ref={ref}>
      <button type="button" className="btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <Download aria-hidden="true" /> Export <ChevronDown aria-hidden="true" />
      </button>
      {open && (
        <div className="menu-list" role="menu">
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              download(`cipherguard-${slug}-${date}.md`, reportToMarkdown(report));
              setOpen(false);
              toast("Markdown report downloaded");
            }}
          >
            <FileText aria-hidden="true" /> Markdown
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              // The print stylesheet lays the report out for PDF.
              requestAnimationFrame(() => window.print());
            }}
          >
            <Printer aria-hidden="true" /> PDF (print)
          </button>
        </div>
      )}
    </div>
  );
}

export default function ReportView({ report, shared = null }) {
  const navigate = useNavigate();
  const [severityFilter, setSeverityFilter] = useState(() => new Set(SEVERITIES));
  const [sharing, setSharing] = useState(false);
  const findingsRef = useRef(null);

  // Detected secrets: raw values in a live report, masked values in a stored one.
  const secrets = useMemo(
    () =>
      (report.findings || [])
        .filter((f) => f.secret)
        .map((f) => ({ value: f.secret.value || f.secret.masked, masked: f.secret.masked }))
        .sort((a, b) => b.value.length - a.value.length),
    [report]
  );

  const pickSeverity = (s) => {
    setSeverityFilter((prev) => (prev.size === 1 && prev.has(s) ? new Set(SEVERITIES) : new Set([s])));
    findingsRef.current?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  };

  const share = async () => {
    setSharing(true);
    try {
      const link = await makeShareLink(report);
      await navigator.clipboard.writeText(link.url).catch(() => {});
      toast(link.kind === "stored" ? "Share link copied. Secrets are redacted; the link expires in 30 days." : "Share link copied. Secrets are redacted.");
    } catch (err) {
      toast(err.message || "Could not create a share link.", { tone: "warn", ms: 5000 });
    } finally {
      setSharing(false);
    }
  };

  const rescan = async () => {
    const id = await startScan(report.repository);
    navigate(`/report/${id}`);
  };

  const ai = report.ai;

  return (
    <article className="shell report">
      <header className="report-head">
        <div className="report-title">
          <nav className="crumbs" aria-label="Breadcrumb">
            <Link to="/history">Scans</Link>
            <span aria-hidden="true">/</span>
            <span aria-current="page">{report.target?.slug}</span>
          </nav>
          <h1 className="mono">
            <a href={report.repository} target="_blank" rel="noreferrer" className="repo-link">
              <GitHubMark size={18} />
              {report.target?.slug || report.repository}
            </a>
          </h1>
          <p className="report-meta">
            {shared ? `Shared report${shared.createdAt ? `, created ${formatDate(shared.createdAt)}` : ""} · secrets redacted` : `Scanned ${formatDate(report.scanTimestamp)}`}
          </p>
        </div>
        <div className="report-actions">
          <ExportMenu report={report} />
          {!shared && (
            <button type="button" className="btn" onClick={share} disabled={sharing}>
              <Link2 aria-hidden="true" /> {sharing ? "Creating link" : "Share"}
            </button>
          )}
          <button type="button" className="btn" onClick={rescan}>
            <RotateCw aria-hidden="true" /> Rescan
          </button>
        </div>
      </header>

      <RiskSummary report={report} severityFilter={severityFilter} onPickSeverity={pickSeverity} />

      {report.overallAssessment ? (
        <section className="ai-summary panel" aria-labelledby="ai-title">
          <h2 id="ai-title" className="ai-summary-head">
            <Sparkles aria-hidden="true" /> AI summary <span className="muted">{ai?.model}</span>
          </h2>
          {/* Gemini only ever receives masked secrets, so its text needs no redaction. */}
          <div className="ai-summary-body">
            <Markdown text={report.overallAssessment} />
          </div>
          <p className="ai-disclaimer">Generated from the scan data above. Verify before acting on it.</p>
        </section>
      ) : (
        ai &&
        ai.status !== "ok" && (
          <p className="ai-off muted">
            <Sparkles aria-hidden="true" /> AI analysis {ai.status === "skipped" ? "skipped" : "unavailable"}: {ai.detail}. Findings and scores do not depend on it.
          </p>
        )
      )}

      <div ref={findingsRef} className="findings-anchor">
        <FindingsExplorer report={report} secrets={secrets} severityFilter={severityFilter} setSeverityFilter={setSeverityFilter} />
      </div>

      <PosturePanel posture={report.posture} sources={report.sources} />
      <SourcesList sources={report.sources} />

      <p className="report-foot muted">
        Risk score method: <a href="https://github.com/NicholasDarwin/CipherGuard#how-the-risk-score-works">how the risk score works</a>.
      </p>
    </article>
  );
}
