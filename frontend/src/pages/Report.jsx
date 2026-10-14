import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import ScanProgress from "../components/ScanProgress";
import ReportView from "../components/report/ReportView";
import ReportSkeleton from "../components/report/ReportSkeleton";
import { useScan, watchClusterScan } from "../lib/scans";
import { getStoredReport } from "../lib/history";
import { getClusterScan } from "../lib/api";

export default function Report() {
  const { id } = useParams();
  const live = useScan(id);
  const [stored] = useState(() => getStoredReport(id));
  const [lookup, setLookup] = useState(live || stored ? "found" : "loading");

  // Not started in this tab and not in local history: ask the API (cluster mode keeps scans).
  useEffect(() => {
    if (live || stored) return;
    let alive = true;
    getClusterScan(id)
      .then((rec) => {
        if (!alive) return;
        watchClusterScan(id, rec);
        setLookup("found");
      })
      .catch(() => alive && setLookup("missing"));
    return () => {
      alive = false;
    };
  }, [id, live, stored]);

  if (live && live.status !== "completed") return <ScanProgress scan={live} />;
  if (live?.report) return <ReportView report={live.report} scanId={id} />;
  if (stored) return <ReportView report={stored} scanId={id} />;
  if (lookup === "loading") return <ReportSkeleton />;

  return (
    <div className="shell page-empty">
      <p className="eyebrow">Report not found</p>
      <h1>This report is not available here</h1>
      <p className="muted">Reports are kept in the browser that ran the scan. Run the scan again, or ask for a share link.</p>
      <Link to="/" className="btn btn-primary">
        Start a scan
      </Link>
    </div>
  );
}
