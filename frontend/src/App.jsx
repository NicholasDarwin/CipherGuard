import { useEffect } from "react";
import { Route, Routes, useNavigate } from "react-router";
import { Analytics } from "@vercel/analytics/react";
import TopBar from "./components/TopBar";
import StatusFooter from "./components/StatusFooter";
import Landing from "./pages/Landing";
import History from "./pages/History";
import Report from "./pages/Report";
import Shared from "./pages/Shared";
import NotFound from "./pages/NotFound";
import { FOCUS_COMMAND_EVENT } from "./lib/commands";
import "./styles/shell.css";
import "./styles/components.css";

export default function App() {
  const navigate = useNavigate();

  // Cmd/Ctrl+K opens a new scan from anywhere.
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        navigate("/");
        requestAnimationFrame(() => window.dispatchEvent(new Event(FOCUS_COMMAND_EVENT)));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  return (
    <div className="app">
      <a href="#content" className="skip-link">
        Skip to content
      </a>
      <TopBar />
      <main id="content" className="app-main" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/history" element={<History />} />
          <Route path="/report/:id" element={<Report />} />
          <Route path="/r/:shareId" element={<Shared />} />
          <Route path="/shared" element={<Shared />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
      <StatusFooter />
      <Analytics />
    </div>
  );
}
