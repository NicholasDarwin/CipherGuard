import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { History as HistoryIcon, Trash2 } from "lucide-react";
import Grade from "../components/Grade";
import { clearHistory, listHistory, removeFromHistory } from "../lib/history";
import { getHealth, listClusterScans } from "../lib/api";
import { useScans } from "../lib/scans";
import { slugOf } from "../lib/repoUrl";
import { SEVERITIES } from "../lib/severity";
import { num, timeAgo } from "../lib/format";
import "../styles/history.css";

function MiniBar({ counts }) {
  const total = SEVERITIES.reduce((n, s) => n + (counts?.[s] || 0), 0);
  if (!total) return <span className="minibar minibar-empty" aria-hidden="true" />;
  return (
    <span className="minibar" aria-hidden="true">
      {SEVERITIES.filter((s) => counts[s]).map((s) => (
        <span key={s} className={`sev-${s}`} style={{ flexGrow: counts[s] / total }} />
      ))}
    </span>
  );
}

const countsLabel = (counts) =>
  SEVERITIES.filter((s) => counts?.[s])
    .map((s) => `${counts[s]} ${s}`)
    .join(", ");

export default function History() {
  const live = useScans();
  const [version, setVersion] = useState(0);
  const [cluster, setCluster] = useState(null);
  const refresh = () => setVersion((v) => v + 1);

  // Re-read storage whenever a scan in this tab changes state or a row is removed.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const entries = useMemo(() => listHistory(), [live, version]);

  // In cluster mode the API also knows scans started from other browsers.
  useEffect(() => {
    let alive = true;
    getHealth()
      .then((h) => (h.mode === "cluster" ? listClusterScans() : null))
      .then((list) => alive && list && setCluster(list))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const running = live.filter((s) => s.status === "running");
  const known = new Set([...entries.map((e) => e.id), ...running.map((s) => s.id)]);
  const remote = (cluster || [])
    .filter((s) => !known.has(s.scanId))
    .map((s) => ({
      id: s.scanId,
      slug: slugOf(s.repoUrl),
      status: s.status,
      startedAt: s.timestamp,
      completedAt: s.completedAt,
      risk: s.results?.risk,
      severityCounts: s.results?.severityCounts,
      totalFindings: s.results?.totalFindings,
    }));
  const rows = [...running.map((s) => ({ id: s.id, slug: s.slug, status: "running", startedAt: s.startedAt })), ...entries.filter((e) => !running.some((s) => s.id === e.id)), ...remote];

  return (
    <div className="shell history">
      <div className="history-head">
        <div>
          <h1>Scans</h1>
          <p className="muted">Scans run from this browser. Saved reports have secret values redacted.</p>
        </div>
        {entries.length > 0 && (
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              if (window.confirm("Remove all saved scans from this browser?")) {
                clearHistory();
                refresh();
              }
            }}
          >
            <Trash2 aria-hidden="true" /> Clear history
          </button>
        )}
      </div>

      {rows.length === 0 ? (
        <div className="history-empty">
          <HistoryIcon aria-hidden="true" />
          <h2>No scans yet</h2>
          <p className="muted">Scan a repository and its report will be listed here.</p>
          <Link to="/" className="btn btn-primary">
            Start a scan
          </Link>
        </div>
      ) : (
        <table className="history-table">
          <thead>
            <tr>
              <th scope="col">
                <span className="visually-hidden">Grade</span>
              </th>
              <th scope="col">Repository</th>
              <th scope="col">Findings</th>
              <th scope="col" className="col-time">
                When
              </th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <Grade grade={r.risk?.grade} />
                </td>
                <td className="col-repo">
                  <Link to={`/report/${r.id}`} className="mono">
                    {r.slug}
                  </Link>
                </td>
                <td className="col-findings">
                  {r.status === "running" ? (
                    <span className="muted">Scanning</span>
                  ) : r.status === "failed" ? (
                    <span className="muted">Failed</span>
                  ) : (
                    <span className="findings-cell" title={countsLabel(r.severityCounts)}>
                      <span className="mono">{num(r.totalFindings ?? 0)}</span>
                      <MiniBar counts={r.severityCounts} />
                      <span className="visually-hidden">{countsLabel(r.severityCounts)}</span>
                    </span>
                  )}
                </td>
                <td className="col-time muted">{timeAgo(r.completedAt || r.startedAt)}</td>
                <td className="col-actions">
                  {entries.some((e) => e.id === r.id) && (
                    <button
                      type="button"
                      className="btn btn-ghost btn-icon"
                      aria-label={`Remove ${r.slug} from history`}
                      onClick={() => {
                        removeFromHistory(r.id);
                        refresh();
                      }}
                    >
                      <Trash2 aria-hidden="true" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
