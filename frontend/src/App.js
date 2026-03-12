import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import ScanDashboard from "./components/ScanDashboard";
import ScanReport from "./components/ScanReport";

const API = process.env.REACT_APP_API_URL || "";

export default function App() {
  return (
    <Router>
      <div className="app-container">
        <header className="app-header">
          <div className="header-inner">
            <div className="logo">
              <i className="fas fa-shield-halved"></i>
              <span>CipherGuard</span>
            </div>
            <p className="subtitle">AI-Powered Kubernetes Security Scanner</p>
          </div>
        </header>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<ScanDashboard api={API} />} />
            <Route path="/scan/:id" element={<ScanReport api={API} />} />
          </Routes>
        </main>

        <footer className="app-footer">
          <p>CipherGuard v2.0 &mdash; Concurrent scanning powered by Kubernetes</p>
        </footer>
      </div>
    </Router>
  );
}
