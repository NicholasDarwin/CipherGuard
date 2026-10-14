import { useId, useState } from "react";
import { ChevronRight, ExternalLink, Eye, EyeOff, Flame, Sparkles } from "lucide-react";
import CodeSnippet from "./CodeSnippet";
import Markdown from "../Markdown";
import { RedactedText, RedactedValue } from "../Redacted";
import { SEVERITY_LABEL, TYPE_LABEL } from "../../lib/severity";
import { pct } from "../../lib/format";

export function SeverityBadge({ severity }) {
  return (
    <span className={`sev-badge sev-${severity}`}>
      <span className="sev-dot" aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function KevBadge() {
  return (
    <span className="kev-badge" title="Listed in the CISA Known Exploited Vulnerabilities catalog">
      <Flame aria-hidden="true" />
      Known exploited
    </span>
  );
}

function Location({ f, secrets, revealed }) {
  if (f.type === "dependency") {
    const p = f.package || {};
    return (
      <span className="mono">
        {p.name}@{p.version}
        {p.fixedVersion && <span className="loc-fix"> → {p.fixedVersion}</span>}
        {f.file && <span className="loc-file"> · {f.file}</span>}
      </span>
    );
  }
  return (
    <span className="mono">
      {f.file}
      {f.line ? `:${f.line}` : ""}
      {f.type === "secret" && f.secret && (
        <>
          {" · "}
          <RedactedValue masked={f.secret.masked} raw={f.secret.value} revealed={revealed} />
        </>
      )}
      {f.type === "code" && f.match && !f.snippet && (
        <>
          {" · "}
          <RedactedText text={f.match} secrets={secrets} revealed={revealed} />
        </>
      )}
    </span>
  );
}

function AdvisoryDetails({ f }) {
  const a = f.advisory;
  if (!a) return null;
  const rows = [];
  if (a.cvss) {
    rows.push([
      "CVSS",
      <>
        <strong>{a.cvss.score ?? "–"}</strong> <span className="mono muted">{a.cvss.vector}</span> <SourceTag name={a.cvss.source} />
      </>,
    ]);
  }
  if (a.epss) {
    rows.push([
      "EPSS",
      <>
        <strong>{pct(a.epss.score)}</strong> chance of exploitation in the next 30 days (higher than {pct(a.epss.percentile, 0)} of CVEs) <SourceTag name="EPSS" href={a.urls?.epss} />
      </>,
    ]);
  }
  if (a.kev) {
    rows.push([
      "CISA KEV",
      <>
        Exploited in the wild, added {a.kev.dateAdded}
        {a.kev.ransomware ? "; used in ransomware campaigns" : ""}. <SourceTag name="KEV" href={a.urls?.kev} />
      </>,
    ]);
  }
  if (a.cwes?.length) {
    rows.push([
      "Weakness",
      a.cwes.map((c, i) => (
        <span key={c}>
          {i > 0 && ", "}
          <a href={`https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html`} target="_blank" rel="noreferrer">
            {c}
          </a>
          {a.cweNames?.[c] ? ` ${a.cweNames[c]}` : ""}
        </span>
      )),
    ]);
  }
  rows.push([
    "Advisory",
    [a.cve, a.ghsa, a.id]
      .filter((x, i, arr) => x && arr.indexOf(x) === i)
      .map((id, i) => (
        <span key={id}>
          {i > 0 && " · "}
          <span className="mono">{id}</span>
        </span>
      )),
  ]);
  if (f.package) {
    rows.push(["Package", `${f.package.ecosystem} · ${f.package.direct ? "direct" : "transitive"} dependency${f.package.dev ? " (dev)" : ""}`]);
  }

  return (
    <dl className="facts">
      {rows.map(([k, v]) => (
        <div key={k} className="fact">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function SourceTag({ name, href }) {
  if (!name) return null;
  return href ? (
    <a className="source-chip" href={href} target="_blank" rel="noreferrer">
      {name}
      <ExternalLink aria-hidden="true" />
    </a>
  ) : (
    <span className="source-chip">{name}</span>
  );
}

export default function FindingRow({ f, open, onToggle, secrets }) {
  const panelId = useId();
  const [revealed, setRevealed] = useState(false);
  const a = f.advisory;
  const canReveal = f.type === "secret" && f.secret?.value;

  return (
    <li className={`finding sev-edge-${f.severity}${open ? " is-open" : ""}`}>
      <button type="button" className="finding-summary" aria-expanded={open} aria-controls={panelId} onClick={onToggle}>
        <ChevronRight className="finding-chevron" aria-hidden="true" />
        <span className="finding-main">
          <span className="finding-title">{f.title}</span>
          <span className="finding-loc">
            <span className="finding-type">{TYPE_LABEL[f.type] || f.type}</span>
            <Location f={f} secrets={secrets} revealed={revealed} />
          </span>
        </span>
        <span className="finding-tags">
          {a?.kev && <KevBadge />}
          {a?.epss && a.epss.score >= 0.01 && (
            <span className="metric" title="EPSS: probability of exploitation in the next 30 days">
              EPSS <strong>{pct(a.epss.score, a.epss.score < 0.1 ? 1 : 0)}</strong>
            </span>
          )}
          {a?.cvss?.score != null && (
            <span className="metric" title={`CVSS ${a.cvss.vector || ""}`}>
              CVSS <strong>{a.cvss.score}</strong>
            </span>
          )}
          <SeverityBadge severity={f.severity} />
        </span>
      </button>

      {open && (
        <div className="finding-panel" id={panelId}>
          {f.description && f.description !== f.title && (
            <div className="finding-desc">
              <Markdown text={f.description} />
            </div>
          )}

          {f.snippet && <CodeSnippet snippet={f.snippet} line={f.line} file={f.file} secrets={secrets} revealed={revealed} keyBlock={f.rule === "private_key"} />}

          {canReveal && (
            <button type="button" className="btn btn-ghost reveal-btn" onClick={() => setRevealed((v) => !v)} aria-pressed={revealed}>
              {revealed ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
              {revealed ? "Hide secret value" : "Reveal secret value"}
            </button>
          )}

          <AdvisoryDetails f={f} />

          {f.ai?.explanation && (
            <section className="ai-note" aria-label="AI explanation">
              <p className="ai-note-head">
                <Sparkles aria-hidden="true" /> AI explanation
                {f.ai.falsePositive && <span className="muted"> · false positive {f.ai.falsePositive}</span>}
              </p>
              {/* Gemini only ever sees masked secrets, so its text is safe to render as Markdown. */}
              <Markdown text={f.ai.explanation} />
            </section>
          )}

          <section className="remediation" aria-label="Remediation">
            <p className="remediation-head">How to fix</p>
            <Markdown text={f.ai?.fix || f.remediation || "Review this finding manually."} />
          </section>

          {f.sources?.length > 0 && (
            <p className="finding-sources">
              <span className="muted">Sources</span>
              {f.sources.map((s) => (
                <SourceTag key={s.name} name={s.name} href={s.url} />
              ))}
            </p>
          )}
        </div>
      )}
    </li>
  );
}
