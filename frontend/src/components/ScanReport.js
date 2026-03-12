import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";

export default function ScanReport({ api }) {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${api}/scan/${id}`);
        if (res.ok) setScan(await res.json());
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    })();
  }, [api, id]);

  if (loading) {
    return (
      <div className="loading-center">
        <i className="fas fa-spinner fa-spin"></i>
        <p>Loading report&hellip;</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="loading-center">
        <i className="fas fa-exclamation-triangle"></i>
        <p>Scan not found.</p>
      </div>
    );
  }

  const r = scan.results || {};
  const findings = r.findings || [];
  const sev = r.severityCounts || { critical: 0, high: 0, medium: 0, low: 0 };
  const aiAnalyses = r.aiAnalyses || [];
  const assessment = r.overallAssessment;

  const grouped = {
    critical: findings.filter((f) => f.severity === "critical"),
    high: findings.filter((f) => f.severity === "high"),
    medium: findings.filter((f) => f.severity === "medium"),
    low: findings.filter((f) => f.severity === "low"),
  };

  const sevIcon = {
    critical: "skull-crossbones",
    high: "exclamation-triangle",
    medium: "info-circle",
    low: "check-circle",
  };

  return (
    <>
      <Link to="/" className="report-back">
        <i className="fas fa-arrow-left"></i> Back to dashboard
      </Link>

      <div className="report-header">
        <h2>
          <i className="fab fa-github"></i>&nbsp;{scan.repoUrl}
        </h2>
        <div className="report-meta">
          <span>
            <strong>Status:</strong>{" "}
            <span className={`status-badge ${scan.status}`}>{scan.status}</span>
          </span>
          <span>
            <strong>Started:</strong> {new Date(scan.timestamp).toLocaleString()}
          </span>
          {scan.completedAt && (
            <span>
              <strong>Completed:</strong>{" "}
              {new Date(scan.completedAt).toLocaleString()}
            </span>
          )}
        </div>
      </div>

      {scan.status === "failed" && (
        <div className="ai-section">
          <h3>
            <i className="fas fa-times-circle" style={{ color: "#ef4444" }}></i>{" "}
            Scan Failed
          </h3>
          <p className="ai-text">{r.error || "Unknown error"}</p>
        </div>
      )}

      {scan.status === "completed" && (
        <>
          {/* Stats */}
          <div className="stats-row">
            <StatCard icon="folder-open" color="blue" value={r.totalFilesScanned || 0} label="Files Scanned" />
            <StatCard icon="skull-crossbones" color="red" value={sev.critical} label="Critical" />
            <StatCard icon="exclamation-triangle" color="yellow" value={sev.high} label="High" />
            <StatCard icon="info-circle" color="cyan" value={sev.medium} label="Medium" />
            <StatCard icon="check-circle" color="green" value={sev.low} label="Low" />
            <StatCard icon="robot" color="purple" value={aiAnalyses.length} label="AI Analyzed" />
          </div>

          {/* Findings */}
          <div className="findings-section">
            <h3>
              <i className="fas fa-list-check"></i> Detailed Findings
            </h3>

            {findings.length === 0 ? (
              <div className="no-findings">
                <i className="fas fa-check-circle"></i>
                <p>No vulnerabilities detected.</p>
              </div>
            ) : (
              Object.entries(grouped).map(
                ([severity, items]) =>
                  items.length > 0 && (
                    <div className="severity-group" key={severity}>
                      <div className={`severity-header ${severity}`}>
                        <i className={`fas fa-${sevIcon[severity]}`}></i>
                        {severity.toUpperCase()} ({items.length})
                      </div>
                      {items.map((f, i) => {
                        const ai = aiAnalyses.find(
                          (a) =>
                            a.finding.file === f.file &&
                            a.finding.keyword === f.keyword &&
                            a.finding.line === f.line
                        );
                        return <FindingCard key={i} finding={f} ai={ai} />;
                      })}
                    </div>
                  )
              )
            )}
          </div>

          {/* AI Assessment */}
          {assessment && (
            <div className="ai-section">
              <h3>
                <i className="fas fa-robot"></i> AI Security Assessment
              </h3>
              <div className="ai-text">{assessment}</div>
            </div>
          )}
        </>
      )}
    </>
  );
}

function StatCard({ icon, color, value, label }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${color}`}>
        <i className={`fas fa-${icon}`}></i>
      </div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function FindingCard({ finding, ai }) {
  return (
    <div className="finding-card">
      <div className="finding-header">
        <span className="finding-file">
          <i className="fas fa-file-code"></i>
          {finding.file}
        </span>
        <span className={`finding-badge ${finding.severity}`}>
          {finding.severity}
        </span>
      </div>
      <div className="finding-details">
        <span className="finding-detail">
          <i className="fas fa-tag"></i> {finding.keyword}
        </span>
        <span className="finding-detail">
          <i className="fas fa-hashtag"></i> Line {finding.line}
        </span>
        <span className="finding-detail">
          <i className="fas fa-info-circle"></i> {finding.description}
        </span>
      </div>
      {finding.match && <div className="finding-match">{finding.match}</div>}
      {ai && (
        <div style={{ marginTop: ".6rem", padding: ".6rem", background: "rgba(139,92,246,.06)", borderRadius: "8px", border: "1px solid rgba(139,92,246,.2)" }}>
          <div style={{ fontSize: ".8rem", fontWeight: 700, color: "#8b5cf6", marginBottom: ".3rem" }}>
            <i className="fas fa-robot"></i> AI Analysis
          </div>
          <div style={{ fontSize: ".78rem", color: "#4b5563", whiteSpace: "pre-wrap" }}>
            {ai.analysis}
          </div>
        </div>
      )}
    </div>
  );
}
