import { useEffect, useState } from "react";
import { Link, useLocation, useParams } from "react-router";
import ReportView from "../components/report/ReportView";
import ReportSkeleton from "../components/report/ReportSkeleton";
import { getShare } from "../lib/api";
import { readFragmentReport } from "../lib/share";

async function loadShared(shareId, hash) {
  if (shareId) return getShare(shareId);
  const report = await readFragmentReport(hash);
  if (!report) throw new Error("This link has no report in it.");
  return { report };
}

/** Read-only report from /r/:shareId (stored on the server) or /shared#<data> (in the URL). */
export default function Shared() {
  const { shareId } = useParams();
  const { hash } = useLocation();
  const [state, setState] = useState({ status: "loading" });

  useEffect(() => {
    let alive = true;
    loadShared(shareId, hash)
      .then((entry) => alive && setState({ status: "ok", entry }))
      .catch((err) => {
        if (!alive) return;
        const message = err.status === 404 ? "This shared report does not exist or has expired." : err.message || "This link could not be read.";
        setState({ status: "error", message });
      });
    return () => {
      alive = false;
    };
  }, [shareId, hash]);

  if (state.status === "loading") return <ReportSkeleton />;
  if (state.status === "error") {
    return (
      <div className="shell page-empty">
        <p className="eyebrow">Shared report</p>
        <h1>This report could not be opened</h1>
        <p className="muted">{state.message}</p>
        <Link to="/" className="btn btn-primary">
          Scan a repository
        </Link>
      </div>
    );
  }
  return <ReportView report={state.entry.report} shared={{ createdAt: state.entry.createdAt }} />;
}
