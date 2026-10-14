import { useEffect, useState } from "react";
import { getHealth } from "../lib/api";

export default function StatusFooter() {
  const [health, setHealth] = useState(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    let alive = true;
    getHealth()
      .then((h) => alive && setHealth(h))
      .catch(() => alive && setDown(true));
    return () => {
      alive = false;
    };
  }, []);

  const state = down ? "down" : health ? "up" : "checking";
  const label = { up: "Scanner online", down: "Scanner unreachable", checking: "Checking scanner" }[state];

  return (
    <footer className="statusbar">
      <div className="shell statusbar-inner">
        <span className={`status-dot status-${state}`} role="status">
          {label}
        </span>
        {health && (
          <>
            <span className="statusbar-item">AI analysis {health.ai ? "on" : "off"}</span>
            <span className="statusbar-item">{health.mode === "cluster" ? "Kubernetes workers" : "Streaming scans"}</span>
            <span className="statusbar-item mono">v{health.version}</span>
          </>
        )}
        <span className="statusbar-spacer" />
        <a className="statusbar-item" href="https://github.com/NicholasDarwin/CipherGuard#how-the-risk-score-works" target="_blank" rel="noreferrer">
          Scoring
        </a>
        <a className="statusbar-item" href="https://github.com/NicholasDarwin/CipherGuard" target="_blank" rel="noreferrer">
          Source
        </a>
      </div>
    </footer>
  );
}
