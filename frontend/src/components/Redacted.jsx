/**
 * Renders a masked secret ("AKIA************ZAM2"): runs of * become solid
 * redaction bars. When `raw` is provided and `revealed` is true, the real
 * value is shown instead.
 */
export function RedactedValue({ masked, raw, revealed }) {
  if (revealed && raw) return <span className="redacted-raw">{raw}</span>;
  const parts = String(masked || "").split(/(\*+)/);
  return (
    <span className="redacted" aria-label="Secret value hidden">
      {parts.map((p, i) =>
        p.startsWith("*") ? <span key={i} className="redact-bar" style={{ "--n": Math.min(p.length, 28) }} aria-hidden="true" /> : <span key={i} aria-hidden="true">{p}</span>
      )}
    </span>
  );
}

/** Replace every occurrence of `raw` inside `text` with a redacted value. */
export function RedactedText({ text, secrets, revealed }) {
  if (!secrets?.length || revealed) return text;
  const escaped = secrets.map((s) => s.value.replace(/[.*+?^$()|[\]\\{}]/g, "\\$&"));
  const pattern = new RegExp("(" + escaped.join("|") + ")", "g");
  return String(text)
    .split(pattern)
    .map((part, i) => {
      const s = secrets.find((x) => x.value === part);
      return s ? <RedactedValue key={i} masked={s.masked} /> : part;
    });
}
