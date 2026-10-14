import { useState } from "react";
import { Link } from "react-router";
import { ArrowRight } from "lucide-react";
import CommandBar from "../components/CommandBar";
import HeroSample from "../components/HeroSample";
import Grade from "../components/Grade";
import { STEPS } from "../lib/scans";
import { listHistory } from "../lib/history";
import { timeAgo } from "../lib/format";
import "../styles/landing.css";

const SOURCES = ["OSV.dev", "GitHub Advisories", "NVD", "CISA KEV", "FIRST EPSS", "OpenSSF Scorecard", "deps.dev"];

export default function Landing() {
  const [recent] = useState(() => listHistory().slice(0, 4));

  return (
    <>
      <section className="hero">
        <div className="shell hero-inner">
          <div className="hero-copy">
          <p className="eyebrow">Security scanner for public GitHub repositories</p>
          <h1 className="hero-title">
            Find what your repo is{" "}
            <span className="hero-redact">
              <span>leaking</span>
            </span>
            .
          </h1>
          <p className="hero-sub">
            Exposed secrets, risky code and vulnerable dependencies. Every CVE is checked against live exploit data, so you fix
            what attackers actually use first.
          </p>
          <CommandBar autoFocus examples />
          </div>
          <HeroSample />
        </div>
      </section>

      <section className="shell pipeline" aria-labelledby="pipeline-title">
        <h2 id="pipeline-title" className="eyebrow">
          What a scan does
        </h2>
        <ol className="pipeline-list">
          {STEPS.map((s) => (
            <li key={s.id}>
              <span className="pipeline-name">{s.label}</span>
              <span className="pipeline-hint">{s.hint}</span>
            </li>
          ))}
        </ol>
        <p className="pipeline-sources">
          <span className="muted">Data from</span>{" "}
          {SOURCES.map((s) => (
            <span key={s} className="source-tag mono">
              {s}
            </span>
          ))}
        </p>
      </section>

      {recent.length > 0 && (
        <section className="shell recent" aria-labelledby="recent-title">
          <div className="recent-head">
            <h2 id="recent-title" className="eyebrow">
              Recent scans
            </h2>
            <Link to="/history" className="recent-all">
              All scans <ArrowRight aria-hidden="true" />
            </Link>
          </div>
          <ul className="recent-list">
            {recent.map((r) => (
              <li key={r.id}>
                <Link to={`/report/${r.id}`} className="recent-item">
                  <Grade grade={r.risk?.grade} />
                  <span className="recent-slug mono">{r.slug}</span>
                  <span className="recent-meta">{r.status === "failed" ? "Failed" : `${r.totalFindings ?? 0} findings`}</span>
                  <span className="recent-time">{timeAgo(r.completedAt || r.startedAt)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}
