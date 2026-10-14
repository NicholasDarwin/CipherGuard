/** The CipherGuard mark: a frame with a line of text and a redaction bar. */
export function Mark({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" className="mark">
      <rect x="2.75" y="2.75" width="18.5" height="18.5" rx="5" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <rect x="6.75" y="8" width="5.5" height="1.6" rx="0.8" fill="currentColor" />
      <rect x="6.75" y="12" width="10.5" height="3.6" rx="1.1" fill="var(--accent)" />
    </svg>
  );
}

/** GitHub's mark (Primer Octicons, MIT). Lucide no longer ships brand icons. */
export function GitHubMark({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true" fill="currentColor">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}
