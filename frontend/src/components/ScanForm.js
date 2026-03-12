import React, { useState } from "react";

const GH_RE = /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+\/?$/;

export default function ScanForm({ api, onScanCreated }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    const url = repoUrl.trim();
    if (!url) {
      setError("Please enter a repository URL.");
      return;
    }
    if (!GH_RE.test(url)) {
      setError("Enter a valid GitHub repository URL (https://github.com/owner/repo).");
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch(`${api}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: url }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Failed to start scan");
        return;
      }
      onScanCreated(data);
      setRepoUrl("");
    } catch (err) {
      setError("Network error — is the API running?");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="scan-form-card">
      <h2>
        <i className="fas fa-crosshairs"></i> New Security Scan
      </h2>
      <form onSubmit={handleSubmit}>
        <div className="scan-form-row">
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            disabled={submitting}
          />
          <button type="submit" disabled={submitting}>
            {submitting ? (
              <><i className="fas fa-spinner fa-spin"></i> Starting…</>
            ) : (
              <><i className="fas fa-rocket"></i> Scan</>
            )}
          </button>
        </div>
        {error && <p className="form-error"><i className="fas fa-exclamation-circle"></i> {error}</p>}
      </form>
    </div>
  );
}
