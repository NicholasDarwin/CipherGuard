import { useEffect, useId, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { CornerDownLeft, LoaderCircle, Search } from "lucide-react";
import { normalizeRepoInput } from "../lib/repoUrl";
import { startScan } from "../lib/scans";
import { FOCUS_COMMAND_EVENT, isMac } from "../lib/commands";
import ExampleChips from "./ExampleChips";

/** The scan input, command-bar style, with optional example chips below it. */
export default function CommandBar({ autoFocus = false, examples = false }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inputRef = useRef(null);
  const navigate = useNavigate();
  const errorId = useId();
  const hintId = useId();

  useEffect(() => {
    const focus = () => inputRef.current?.focus();
    window.addEventListener(FOCUS_COMMAND_EVENT, focus);
    return () => window.removeEventListener(FOCUS_COMMAND_EVENT, focus);
  }, []);

  const run = async (raw) => {
    const parsed = normalizeRepoInput(raw);
    if (parsed.error) {
      setError(parsed.error);
      inputRef.current?.focus();
      return;
    }
    setError("");
    setValue(parsed.slug);
    setBusy(true);
    try {
      const id = await startScan(parsed.url);
      navigate(`/report/${id}`);
    } catch (err) {
      setError(err.message || "The scan could not be started.");
      setBusy(false);
    }
  };

  return (
    <div className="cmdbar-wrap">
      <form
        className={`cmdbar${error ? " has-error" : ""}`}
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          run(value);
        }}
      >
        <label htmlFor="repo-input" className="visually-hidden">
          GitHub repository to scan
        </label>
        <Search className="cmdbar-icon" aria-hidden="true" />
        <input
          id="repo-input"
          ref={inputRef}
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            if (error) setError("");
          }}
          placeholder="github.com/owner/repo"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck="false"
          inputMode="url"
          enterKeyHint="go"
          autoFocus={autoFocus}
          aria-invalid={!!error}
          aria-describedby={`${hintId}${error ? ` ${errorId}` : ""}`}
          disabled={busy}
        />
        {!value && (
          <span className="kbd cmdbar-kbd" aria-hidden="true">
            {isMac ? "⌘" : "Ctrl"} K
          </span>
        )}
        <button type="submit" className="btn btn-primary cmdbar-submit" disabled={busy}>
          {busy ? <LoaderCircle className="spin" aria-hidden="true" /> : null}
          <span>{busy ? "Starting" : "Scan"}</span>
          {!busy && <CornerDownLeft aria-hidden="true" className="cmdbar-enter" />}
        </button>
      </form>
      <p id={hintId} className="visually-hidden">
        Paste a public GitHub URL or type owner slash repo, then press Enter.
      </p>
      {error && (
        <p id={errorId} className="cmdbar-error" role="alert">
          {error}
        </p>
      )}
      {examples && <ExampleChips onPick={run} disabled={busy} />}
    </div>
  );
}
