import { Link, NavLink, useLocation, useNavigate } from "react-router";
import { Moon, Monitor, Plus, Sun } from "lucide-react";
import { GitHubMark, Mark } from "./Logo";
import { useTheme } from "../lib/theme";
import { FOCUS_COMMAND_EVENT, isMac } from "../lib/commands";

const THEME_NEXT = { dark: "light", light: "system", system: "dark" };
const THEME_ICON = { dark: Moon, light: Sun, system: Monitor };
const THEME_LABEL = { dark: "Dark", light: "Light", system: "System" };

export default function TopBar() {
  const [theme, setTheme] = useTheme();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const ThemeIcon = THEME_ICON[theme];

  const newScan = () => {
    navigate("/");
    requestAnimationFrame(() => window.dispatchEvent(new Event(FOCUS_COMMAND_EVENT)));
  };

  return (
    <header className="topbar">
      <div className="shell topbar-inner">
        <Link to="/" className="brand" aria-label="CipherGuard home">
          <Mark />
          <span>CipherGuard</span>
        </Link>

        <nav className="topnav" aria-label="Primary">
          <NavLink to="/" end>
            Scan
          </NavLink>
          <NavLink to="/history">History</NavLink>
        </nav>

        <div className="topbar-actions">
          {pathname !== "/" && (
            <button type="button" className="btn btn-ghost new-scan" onClick={newScan}>
              <Plus aria-hidden="true" />
              <span className="new-scan-label">New scan</span>
              <span className="kbd" aria-hidden="true">
                {isMac ? "⌘" : "Ctrl"} K
              </span>
            </button>
          )}
          <button
            type="button"
            className="btn btn-ghost btn-icon"
            onClick={() => setTheme(THEME_NEXT[theme])}
            aria-label={`Theme: ${THEME_LABEL[theme]}. Switch to ${THEME_LABEL[THEME_NEXT[theme]]}`}
            title={`Theme: ${THEME_LABEL[theme]}`}
          >
            <ThemeIcon aria-hidden="true" />
          </button>
          <a
            className="btn btn-ghost btn-icon"
            href="https://github.com/NicholasDarwin/CipherGuard"
            target="_blank"
            rel="noreferrer"
            aria-label="CipherGuard source on GitHub"
          >
            <GitHubMark />
          </a>
        </div>
      </div>
    </header>
  );
}
