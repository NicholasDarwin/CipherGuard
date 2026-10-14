import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { Check, Circle, CircleMinus, LoaderCircle, RotateCw, X } from "lucide-react";
import { cancelScan, startScan } from "../lib/scans";
import { duration } from "../lib/format";
import "../styles/progress.css";

const ICON = { pending: Circle, running: LoaderCircle, done: Check, skipped: CircleMinus, failed: X };
const STATUS_TEXT = { pending: "Waiting", running: "Running", done: "Done", skipped: "Skipped", failed: "Failed" };

function useElapsed(startedAt, running) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(t);
  }, [running]);
  return now - Date.parse(startedAt);
}

export default function ScanProgress({ scan }) {
  const navigate = useNavigate();
  const running = scan.status === "running";
  const elapsed = useElapsed(scan.startedAt, running);
  const done = scan.steps.filter((s) => ["done", "skipped"].includes(s.status)).length;
  const current = scan.steps.find((s) => s.status === "running");
  const failed = scan.status === "failed" || scan.status === "cancelled";

  const retry = async () => {
    const id = await startScan(scan.repoUrl);
    navigate(`/report/${id}`, { replace: true });
  };

  return (
    <div className="shell progress-page">
      <div className="progress-head">
        <div>
          <p className="eyebrow">{failed ? (scan.status === "cancelled" ? "Scan cancelled" : "Scan failed") : "Scanning"}</p>
          <h1 className="progress-repo mono">{scan.slug}</h1>
        </div>
        <div className="progress-head-actions">
          {running && (
            <>
              <span className="progress-elapsed mono" aria-hidden="true">
                {duration(Math.max(0, elapsed))}
              </span>
              <button type="button" className="btn" onClick={() => cancelScan(scan.id)}>
                Cancel
              </button>
            </>
          )}
          {failed && (
            <button type="button" className="btn btn-primary" onClick={retry}>
              <RotateCw aria-hidden="true" /> Run again
            </button>
          )}
        </div>
      </div>

      <div
        className="progress-meter"
        role="progressbar"
        aria-label="Scan progress"
        aria-valuemin={0}
        aria-valuemax={scan.steps.length}
        aria-valuenow={done}
        aria-valuetext={`${done} of ${scan.steps.length} steps complete`}
      >
        <span style={{ transform: `scaleX(${done / scan.steps.length})` }} />
      </div>

      <ol className="steps">
        {scan.steps.map((s) => {
          const Icon = ICON[s.status] || Circle;
          return (
            <li key={s.id} className={`step step-${s.status}`} aria-current={s.status === "running" ? "step" : undefined}>
              <span className="step-icon" aria-hidden="true">
                <Icon />
              </span>
              <div className="step-body">
                <div className="step-line">
                  <span className="step-label">{s.label}</span>
                  <span className="visually-hidden">: {STATUS_TEXT[s.status]}</span>
                  {s.durationMs != null && <span className="step-time mono">{duration(s.durationMs)}</span>}
                </div>
                <p className="step-detail">{s.detail || s.hint}</p>
              </div>
            </li>
          );
        })}
      </ol>

      <p className="visually-hidden" aria-live="polite">
        {current ? `${current.label}: ${current.detail || ""}` : failed ? scan.error : ""}
      </p>

      {failed && scan.error && (
        <div className="progress-error" role="alert">
          <p className="progress-error-title">{scan.status === "cancelled" ? "You cancelled this scan." : "The scan stopped."}</p>
          {scan.status !== "cancelled" && <p>{scan.error}</p>}
        </div>
      )}
    </div>
  );
}
