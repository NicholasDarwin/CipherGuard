import Grade from "../Grade";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { duration, num, pct } from "../../lib/format";

const BANDS = [
  ["A", 0, 15],
  ["B", 15, 35],
  ["C", 35, 55],
  ["D", 55, 75],
  ["F", 75, 100],
];

/** Risk score on a 0-100 track divided into grade bands. */
function RiskTrack({ score, grade }) {
  return (
    <div className="risk-track" aria-hidden="true">
      {BANDS.map(([g, from, to]) => (
        <span key={g} className={`risk-band${g === grade ? " is-current" : ""}`} style={{ flexGrow: to - from }}>
          <span className="risk-band-label">{g}</span>
        </span>
      ))}
      <span className="risk-marker" style={{ left: `${score}%` }} />
    </div>
  );
}

/** One stacked bar of findings by severity. Segments filter the list below. */
function SeverityBar({ counts, total, active, onPick }) {
  return (
    <div className="sevbar" role="group" aria-label="Findings by severity">
      {SEVERITIES.filter((s) => counts[s]).map((s) => {
        const share = counts[s] / total;
        const label = `${SEVERITY_LABEL[s]}: ${num(counts[s])} (${pct(share, 0)})`;
        return (
          <button
            key={s}
            type="button"
            className={`sevbar-seg sev-${s}${active && !active.has(s) ? " is-dim" : ""}`}
            style={{ flexGrow: Math.max(share, 0.015) }}
            onClick={() => onPick(s)}
            aria-label={`${label}. Show only ${SEVERITY_LABEL[s].toLowerCase()} findings`}
            data-tip={label}
          />
        );
      })}
    </div>
  );
}

export default function RiskSummary({ report, severityFilter, onPickSeverity }) {
  const { risk, severityCounts: counts = {} } = report;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const deps = report.findings.filter((f) => f.type === "dependency" && f.advisory);
  const kev = deps.filter((f) => f.advisory.kev).length;
  const maxEpss = deps.reduce((m, f) => Math.max(m, f.advisory.epss?.score ?? 0), 0);

  const facts = [
    ["Files scanned", num(report.totalFilesScanned)],
    ["Dependencies", num(report.dependenciesScanned)],
    ["Known exploited", num(kev), kev ? "is-alert" : ""],
    ["Highest EPSS", deps.some((f) => f.advisory.epss) ? pct(maxEpss) : "–"],
    ["Scan time", duration(report.durationMs)],
  ];

  return (
    <section className="report-summary panel" aria-label="Risk summary">
      <div className="summary-grade">
        <Grade grade={risk?.grade} size="lg" label={`Grade ${risk?.grade}, risk ${risk?.score} out of 100`} />
        <div className="summary-score">
          <p className="eyebrow">Risk score</p>
          <p className="score-value">
            <span className="mono">{risk?.score ?? "–"}</span>
            <span className="muted">/100</span>
          </p>
          {risk?.inputs?.floors?.length > 0 && <p className="score-floor">{risk.inputs.floors.join(". ")}.</p>}
        </div>
      </div>

      <div className="summary-body">
        <RiskTrack score={risk?.score ?? 0} grade={risk?.grade} />

        <div className="summary-sev">
          {total > 0 ? (
            <>
              <SeverityBar counts={counts} total={total} active={severityFilter.size === SEVERITIES.length ? null : severityFilter} onPick={onPickSeverity} />
              <ul className="sev-legend">
                {SEVERITIES.map((s) => (
                  <li key={s} className={counts[s] ? "" : "is-zero"}>
                    <span className={`sev-dot sev-${s}`} aria-hidden="true" />
                    <span className="sev-legend-n mono">{num(counts[s] || 0)}</span> {SEVERITY_LABEL[s]}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="muted">No findings.</p>
          )}
        </div>

        <dl className="summary-facts">
          {facts.map(([k, v, cls]) => (
            <div key={k} className={cls}>
              <dt>{k}</dt>
              <dd className="mono">{v}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
