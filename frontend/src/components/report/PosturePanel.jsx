import { Check, CircleMinus, ExternalLink, Star } from "lucide-react";
import { num, timeAgo } from "../../lib/format";
import { SourceTag } from "./FindingRow";

function Practice({ ok, label, detail }) {
  return (
    <li className={ok ? "is-ok" : "is-missing"}>
      {ok ? <Check aria-hidden="true" /> : <CircleMinus aria-hidden="true" />}
      <span>
        {label}
        <span className="visually-hidden">: {ok ? "present" : "missing"}</span>
      </span>
      {detail && <span className="muted mono practice-detail">{detail}</span>}
    </li>
  );
}

/** Repository posture: OpenSSF Scorecard, GitHub metadata, security practices. */
export default function PosturePanel({ posture, sources }) {
  if (!posture) return null;
  const { scorecard, repo, practices } = posture;
  const scorecardSource = sources?.find((s) => s.key === "scorecard");

  return (
    <section className="posture" aria-labelledby="posture-title">
      <h2 id="posture-title" className="section-title">
        Repository posture
      </h2>
      <div className="posture-grid">
        <div className="panel posture-card">
          <div className="posture-card-head">
            <p className="eyebrow">OpenSSF Scorecard</p>
            {scorecard && <SourceTag name="Scorecard" href={scorecard.url} />}
          </div>
          {scorecard ? (
            <>
              <p className="posture-score">
                <span className="mono">{scorecard.score}</span>
                <span className="muted">/10</span>
              </p>
              <p className="muted posture-note">Lowest-scoring checks</p>
              <ul className="checks">
                {scorecard.checks
                  .filter((c) => c.score >= 0)
                  .slice(0, 5)
                  .map((c) => (
                    <li key={c.name}>
                      <a href={c.url} target="_blank" rel="noreferrer" title={c.reason}>
                        {c.name}
                      </a>
                      <span className="check-meter" aria-hidden="true">
                        <span style={{ width: `${c.score * 10}%` }} />
                      </span>
                      <span className="mono check-score">{c.score}</span>
                    </li>
                  ))}
              </ul>
            </>
          ) : (
            <p className="muted posture-unavailable">{scorecardSource?.detail || "Scorecard data unavailable."}</p>
          )}
        </div>

        <div className="panel posture-card">
          <div className="posture-card-head">
            <p className="eyebrow">Repository</p>
            {repo && <SourceTag name="GitHub" href={repo.url} />}
          </div>
          {repo ? (
            <dl className="repo-facts">
              <div>
                <dt>Stars</dt>
                <dd className="mono">
                  <Star aria-hidden="true" /> {num(repo.stars)}
                </dd>
              </div>
              <div>
                <dt>Last push</dt>
                <dd>{timeAgo(repo.pushedAt)}</dd>
              </div>
              <div>
                <dt>License</dt>
                <dd className="mono">{repo.license || "None"}</dd>
              </div>
              <div>
                <dt>Open security issues</dt>
                <dd className="mono">{repo.openSecurityIssues ?? "–"}</dd>
              </div>
              {repo.archived && (
                <div>
                  <dt>Status</dt>
                  <dd>Archived</dd>
                </div>
              )}
            </dl>
          ) : (
            <p className="muted posture-unavailable">Repository metadata unavailable.</p>
          )}
        </div>

        <div className="panel posture-card">
          <div className="posture-card-head">
            <p className="eyebrow">Security practices</p>
          </div>
          {practices && (
            <ul className="practices">
              <Practice ok={!!practices.securityPolicy} label="Security policy" detail={practices.securityPolicy} />
              <Practice ok={practices.dependabot || practices.renovate} label="Automated dependency updates" detail={practices.dependabot ? "Dependabot" : practices.renovate ? "Renovate" : null} />
              <Practice ok={practices.codeql} label="CodeQL code scanning" />
              <Practice ok={practices.ciWorkflows > 0} label="CI workflows" detail={practices.ciWorkflows ? `${practices.ciWorkflows}` : null} />
            </ul>
          )}
          <p className="muted posture-note">From files in the repository.</p>
        </div>
      </div>
    </section>
  );
}

export function SourcesList({ sources }) {
  if (!sources?.length) return null;
  const LABEL = { ok: "Responded", partial: "Partial", unavailable: "Source unavailable", skipped: "Not needed" };
  return (
    <section className="sources" aria-labelledby="sources-title">
      <h2 id="sources-title" className="section-title">
        Data sources
      </h2>
      <ul className="sources-list panel">
        {sources.map((s) => (
          <li key={s.key || s.name}>
            <span className={`src-status src-${s.status}`}>{LABEL[s.status] || s.status}</span>
            <a href={s.url} target="_blank" rel="noreferrer" className="src-name">
              {s.name}
              <ExternalLink aria-hidden="true" />
            </a>
            <span className="muted src-detail">{s.detail}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
