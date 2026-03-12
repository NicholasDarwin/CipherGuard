import React, { useState } from "react";

const GH_RE = /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+\/?$/;

export default function ScanForm({ api, onScanCreated }) {
  const [repoUrls, setRepoUrls] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const parseUrls = () =>
    repoUrls.split("\n").map((u) => u.trim()).filter(Boolean);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    const urls = parseUrls();
    if (urls.length === 0) {
      setError("Enter at least one repository URL.");
      return;
    }

    const invalid = urls.filter((u) => !GH_RE.test(u));
    if (invalid.length > 0) {
      setError(`Invalid URL${invalid.length > 1 ? "s" : ""}: ${invalid.join(", ")}`);
      return;
    }

    setSubmitting(true);
    try {
      const results = await Promise.allSettled(
        urls.map((url) =>
          fetch(`${api}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ repoUrl: url }),
          }).then(async (res) => {
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || `Failed: ${url}`);
            return data;
          })
        )
      );

      const errors = [];
      for (const r of results) {
        if (r.status === "fulfilled") {
          onScanCreated(r.value);
        } else {
          errors.push(r.reason.message);
        }
      }
      if (errors.length > 0) setError(errors.join("; "));
      setRepoUrls("");
    } catch (err) {
      setError("Network error \u2014 is the API running?");
    } finally {
      setSubmitting(false);
    }
  };

  const urlCount = parseUrls().length;

  return (
    <div className="scan-form-card">
      <h2>
        <i className="fas fa-crosshairs"></i> New Security Scan
      </h2>
      <form onSubmit={handleSubmit}>
        <div className="scan-form-col">
          <textarea
            value={repoUrls}
            onChange={(e) => setRepoUrls(e.target.value)}
            placeholder={"https://github.com/owner/repo-a\nhttps://github.com/owner/repo-b\nhttps://github.com/owner/repo-c"}
            disabled={submitting}
            rows={3}
          />
          <button type="submit" disabled={submitting || urlCount === 0}>
            {submitting ? (
              <><i className="fas fa-spinner fa-spin"></i> Starting {urlCount} scan{urlCount !== 1 ? "s" : ""}\u2026</>
            ) : (
              <><i className="fas fa-rocket"></i> Scan{urlCount > 1 ? ` ${urlCount} repos` : ""}</>
            )}
          </button>
        </div>
        <p className="form-hint">One GitHub URL per line. All repos scan simultaneously.</p>
        {error && <p className="form-error"><i className="fas fa-exclamation-circle"></i> {error}</p>}
      </form>
    </div>
  );
}
