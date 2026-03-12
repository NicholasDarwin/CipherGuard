import React, { useState, useEffect, useCallback } from "react";
import ScanForm from "./ScanForm";
import ScanCard from "./ScanCard";

const POLL_INTERVAL = 4000;

export default function ScanDashboard({ api }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = useCallback(async () => {
    try {
      const res = await fetch(`${api}/scans`);
      if (res.ok) setScans(await res.json());
    } catch (err) {
      console.error("Failed to fetch scans:", err);
    } finally {
      setLoading(false);
    }
  }, [api]);

  // Initial fetch + polling
  useEffect(() => {
    fetchScans();
    const id = setInterval(fetchScans, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [fetchScans]);

  const handleNewScan = (scan) => {
    setScans((prev) => [scan, ...prev]);
  };

  const hasActive = scans.some(
    (s) => s.status === "queued" || s.status === "running"
  );

  return (
    <>
      <ScanForm api={api} onScanCreated={handleNewScan} />

      <div className="dashboard-heading">
        <h2>
          <i className="fas fa-list-check"></i> Scan Dashboard
        </h2>
        <span className="scan-count">
          {scans.length} scan{scans.length !== 1 ? "s" : ""}
          {hasActive && " · polling…"}
        </span>
      </div>

      {loading ? (
        <div className="loading-center">
          <i className="fas fa-spinner fa-spin"></i>
          <p>Loading scans…</p>
        </div>
      ) : (
        <div className="scan-grid">
          {scans.length === 0 ? (
            <div className="empty-state">
              <i className="fas fa-radar"></i>
              <p>No scans yet. Submit a repository URL above to begin.</p>
            </div>
          ) : (
            scans.map((scan) => <ScanCard key={scan.scanId} scan={scan} />)
          )}
        </div>
      )}
    </>
  );
}
