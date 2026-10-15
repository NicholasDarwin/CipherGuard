import { useDeferredValue, useMemo, useState } from "react";
import { ChevronDown, ChevronsDownUp, ChevronsUpDown, Flame, Search, SearchX, ShieldCheck } from "lucide-react";
import FindingRow from "./FindingRow";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/severity";
import { num } from "../../lib/format";

const PAGE = 40;
const TYPES = [
  ["all", "All"],
  ["secret", "Secrets"],
  ["code", "Code"],
  ["dependency", "Dependencies"],
];

function haystack(f) {
  return [f.title, f.rule, f.file, f.match, f.package?.name, f.advisory?.cve, f.advisory?.ghsa, f.advisory?.id, ...(f.advisory?.cwes || [])]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export default function FindingsExplorer({ report, secrets, severityFilter, setSeverityFilter }) {
  const findings = useMemo(() => report.findings || [], [report.findings]);
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [type, setType] = useState("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [open, setOpen] = useState(() => new Set());
  const [collapsed, setCollapsed] = useState(() => new Set(["info"]));
  const [limits, setLimits] = useState({});

  const index = useMemo(() => new Map(findings.map((f) => [f.id, haystack(f)])), [findings]);
  const hasKev = findings.some((f) => f.advisory?.kev);
  const typeCounts = useMemo(() => {
    const c = { all: findings.length, secret: 0, code: 0, dependency: 0 };
    for (const f of findings) c[f.type] = (c[f.type] || 0) + 1;
    return c;
  }, [findings]);

  const visible = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase();
    return findings.filter(
      (f) =>
        severityFilter.has(f.severity) &&
        (type === "all" || f.type === type) &&
        (!kevOnly || f.advisory?.kev) &&
        (!q || index.get(f.id).includes(q))
    );
  }, [findings, severityFilter, type, kevOnly, deferredQuery, index]);

  const groups = SEVERITIES.map((s) => [s, visible.filter((f) => f.severity === s)]).filter(([, items]) => items.length);

  const toggle = (id) =>
    setOpen((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const expandAll = () => {
    setCollapsed(new Set());
    setOpen(new Set(groups.flatMap(([s, items]) => items.slice(0, limits[s] || PAGE).map((f) => f.id))));
  };
  const collapseAll = () => setOpen(new Set());

  const toggleSeverity = (s) =>
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next.size ? next : new Set(SEVERITIES);
    });

  const filtersActive = query || type !== "all" || kevOnly || severityFilter.size !== SEVERITIES.length;
  const reset = () => {
    setQuery("");
    setType("all");
    setKevOnly(false);
    setSeverityFilter(new Set(SEVERITIES));
  };

  if (!findings.length) {
    return (
      <section className="findings-empty panel">
        <ShieldCheck aria-hidden="true" />
        <div>
          <h2>No findings</h2>
          <p className="muted">
            {num(report.totalFilesScanned)} files and {num(report.dependenciesScanned)} dependencies checked. Nothing matched a secret pattern, risky code rule or known vulnerability.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="findings" aria-labelledby="findings-title">
      <div className="findings-head">
        <h2 id="findings-title">
          Findings <span className="muted">{visible.length === findings.length ? num(findings.length) : `${num(visible.length)} of ${num(findings.length)}`}</span>
        </h2>
        <div className="findings-bulk">
          <button type="button" className="btn btn-ghost" onClick={expandAll}>
            <ChevronsUpDown aria-hidden="true" /> Expand all
          </button>
          <button type="button" className="btn btn-ghost" onClick={collapseAll}>
            <ChevronsDownUp aria-hidden="true" /> Collapse all
          </button>
        </div>
      </div>

      <div className="toolbar" role="group" aria-label="Filter findings">
        <label className="search">
          <Search aria-hidden="true" />
          <span className="visually-hidden">Search findings</span>
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by file, rule, CVE or package" spellCheck="false" />
        </label>

        <div className="seg" role="radiogroup" aria-label="Finding type">
          {TYPES.filter(([k]) => k === "all" || typeCounts[k]).map(([k, label]) => (
            <button key={k} type="button" role="radio" aria-checked={type === k} className="seg-item" onClick={() => setType(k)}>
              {label} <span className="seg-count">{num(typeCounts[k])}</span>
            </button>
          ))}
        </div>

        <div className="sev-filters" role="group" aria-label="Severity">
          {SEVERITIES.filter((s) => report.severityCounts?.[s]).map((s) => (
            <button key={s} type="button" className={`sev-toggle sev-${s}`} aria-pressed={severityFilter.has(s)} onClick={() => toggleSeverity(s)}>
              <span className="sev-dot" aria-hidden="true" />
              {SEVERITY_LABEL[s]} <span className="seg-count">{num(report.severityCounts[s])}</span>
            </button>
          ))}
          {hasKev && (
            <button type="button" className="sev-toggle kev-toggle" aria-pressed={kevOnly} onClick={() => setKevOnly((v) => !v)}>
              <Flame aria-hidden="true" /> Known exploited
            </button>
          )}
        </div>
      </div>

      {groups.length === 0 ? (
        <div className="findings-none">
          <SearchX aria-hidden="true" />
          <p>No findings match these filters.</p>
          <button type="button" className="btn" onClick={reset}>
            Clear filters
          </button>
        </div>
      ) : (
        groups.map(([sev, items]) => {
          const isCollapsed = collapsed.has(sev) && !filtersActive;
          const limit = limits[sev] || PAGE;
          return (
            <div key={sev} className="sev-group">
              <h3 className="sev-group-head">
                <button
                  type="button"
                  aria-expanded={!isCollapsed}
                  onClick={() =>
                    setCollapsed((prev) => {
                      const next = new Set(prev);
                      next.has(sev) ? next.delete(sev) : next.add(sev);
                      return next;
                    })
                  }
                >
                  <ChevronDown className="sev-group-chevron" aria-hidden="true" />
                  <span className={`sev-dot sev-${sev}`} aria-hidden="true" />
                  {SEVERITY_LABEL[sev]}
                  <span className="muted">{num(items.length)}</span>
                </button>
              </h3>
              {!isCollapsed && (
                <>
                  <ul className="finding-list">
                    {items.slice(0, limit).map((f) => (
                      <FindingRow key={f.id} f={f} open={open.has(f.id)} onToggle={() => toggle(f.id)} secrets={secrets} report={report} />
                    ))}
                  </ul>
                  {items.length > limit && (
                    <button type="button" className="btn show-more" onClick={() => setLimits((l) => ({ ...l, [sev]: limit + PAGE * 2 }))}>
                      Show {num(Math.min(PAGE * 2, items.length - limit))} more of {num(items.length - limit)}
                    </button>
                  )}
                </>
              )}
            </div>
          );
        })
      )}
    </section>
  );
}
