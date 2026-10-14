import { Flame } from "lucide-react";
import { RedactedValue } from "./Redacted";

// A static excerpt of a report, shown beside the hero on wide screens so
// people see what a scan returns before they run one.
const ROWS = [
  { sev: "critical", title: "AWS access key ID", loc: "src/config/aws.js:14", secret: "AKIA************ZAM2" },
  { sev: "critical", title: "Remote code execution in log4j-core", loc: "log4j-core@2.14.1 → 2.17.1", kev: true, epss: "94.4%" },
  { sev: "high", title: "Prototype pollution in lodash", loc: "lodash@4.17.15 → 4.17.21", epss: "21.3%" },
  { sev: "medium", title: "CORS allows any origin", loc: "server/app.js:22" },
];

export default function HeroSample() {
  return (
    <div className="hero-sample" aria-hidden="true">
      <div className="hero-sample-head">
        <span className="grade grade-sm tone-high">D</span>
        <span className="mono">acme/payments-api</span>
        <span className="hero-sample-score mono">
          71<span className="muted">/100</span>
        </span>
      </div>
      <ul>
        {ROWS.map((r) => (
          <li key={r.title} className={`sev-edge-${r.sev}`}>
            <span className="hero-sample-title">{r.title}</span>
            <span className="hero-sample-loc mono">
              {r.loc}
              {r.secret && (
                <>
                  {" · "}
                  <RedactedValue masked={r.secret} />
                </>
              )}
            </span>
            <span className="hero-sample-tags">
              {r.kev && (
                <span className="kev-badge">
                  <Flame /> Known exploited
                </span>
              )}
              {r.epss && (
                <span className="metric">
                  EPSS <strong>{r.epss}</strong>
                </span>
              )}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
