import { Bug, KeyRound, ShieldCheck } from "lucide-react";

export const EXAMPLES = [
  { label: "Leaked secrets", slug: "trufflesecurity/test_keys", icon: KeyRound, note: "Deliberately leaked test credentials published by Truffle Security" },
  { label: "Vulnerable web app", slug: "OWASP/NodeGoat", icon: Bug, note: "OWASP's intentionally insecure Node.js app" },
  { label: "Clean repo", slug: "octocat/Hello-World", icon: ShieldCheck, note: "GitHub's sample repository, nothing to flag" },
];

export default function ExampleChips({ onPick, disabled }) {
  return (
    <div className="examples">
      <span className="examples-label" id="examples-label">
        Try an example
      </span>
      <ul className="examples-list" aria-labelledby="examples-label">
        {EXAMPLES.map(({ label, slug, icon: Icon, note }) => (
          <li key={slug}>
            <button type="button" className="chip" onClick={() => onPick(slug)} disabled={disabled} title={note}>
              <Icon aria-hidden="true" />
              <span className="chip-label">{label}</span>
              <span className="chip-slug mono">{slug}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
