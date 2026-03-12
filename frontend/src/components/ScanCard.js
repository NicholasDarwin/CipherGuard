import React from "react";
import { Link } from "react-router-dom";

export default function ScanCard({ scan }) {
  const { scanId, repoUrl, status, timestamp } = scan;
  const shortRepo = repoUrl.replace(/^https?:\/\/(www\.)?github\.com\//, "");
  const time = new Date(timestamp).toLocaleString();

  return (
    <div className="scan-card">
      <div className="scan-card-header">
        <span className="scan-repo" title={repoUrl}>
          <i className="fab fa-github"></i>
          {shortRepo}
        </span>
        <span className={`status-badge ${status}`}>{status}</span>
      </div>

      <div className="scan-progress-bar">
        <div className={`scan-progress-fill ${status}`} />
      </div>

      <div className="scan-card-meta">
        <i className="fas fa-clock"></i> {time}
      </div>

      <div className="scan-card-actions">
        {status === "completed" || status === "failed" ? (
          <Link to={`/scan/${scanId}`} className="btn-view">
            <i className="fas fa-file-lines"></i> View Report
          </Link>
        ) : (
          <span className="btn-view" style={{ opacity: 0.5, cursor: "default" }}>
            <i className="fas fa-hourglass-half"></i> Awaiting results…
          </span>
        )}
      </div>
    </div>
  );
}
