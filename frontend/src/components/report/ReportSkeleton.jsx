export default function ReportSkeleton() {
  return (
    <div className="shell report" aria-busy="true" aria-label="Loading report">
      <div className="report-summary panel skeleton-panel">
        <span className="skeleton" style={{ width: 88, height: 88 }} />
        <div style={{ flex: 1, display: "grid", gap: 10 }}>
          <span className="skeleton" style={{ width: "40%", height: 20 }} />
          <span className="skeleton" style={{ width: "70%", height: 12 }} />
          <span className="skeleton" style={{ width: "100%", height: 10 }} />
        </div>
      </div>
      <div style={{ display: "grid", gap: 8, marginTop: 24 }}>
        {[0, 1, 2, 3, 4].map((i) => (
          <span key={i} className="skeleton" style={{ height: 52 }} />
        ))}
      </div>
    </div>
  );
}
