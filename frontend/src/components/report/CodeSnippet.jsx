import { Highlight } from "prism-react-renderer";
import { RedactedText } from "../Redacted";
import { maskKeyBlock } from "../../lib/sanitize";

const LANG_BY_EXT = {
  js: "jsx", jsx: "jsx", mjs: "jsx", cjs: "jsx", ts: "tsx", tsx: "tsx",
  py: "python", go: "go", rs: "rust", json: "json", yml: "yaml", yaml: "yaml",
  md: "markdown", html: "markup", htm: "markup", xml: "markup", vue: "markup",
  c: "cpp", h: "cpp", cpp: "cpp", cc: "cpp", hpp: "cpp", kt: "kotlin", swift: "swift",
  graphql: "graphql", gql: "graphql",
};

// Colors come from CSS variables so both themes share one Prism theme.
const theme = {
  plain: { color: "var(--text)", backgroundColor: "transparent" },
  styles: [
    { types: ["comment", "prolog", "doctype", "cdata"], style: { color: "var(--syn-comment)", fontStyle: "italic" } },
    { types: ["keyword", "boolean", "important", "atrule", "selector"], style: { color: "var(--syn-keyword)" } },
    { types: ["string", "char", "attr-value", "regex", "template-string"], style: { color: "var(--syn-string)" } },
    { types: ["number", "constant", "symbol"], style: { color: "var(--syn-number)" } },
    { types: ["function", "class-name", "builtin"], style: { color: "var(--syn-function)" } },
    { types: ["punctuation", "operator"], style: { color: "var(--syn-punct)" } },
    { types: ["tag"], style: { color: "var(--syn-tag)" } },
    { types: ["attr-name", "property"], style: { color: "var(--syn-attr)" } },
  ],
};

function languageFor(file) {
  const ext = (file || "").split(".").pop().toLowerCase();
  return LANG_BY_EXT[ext] || null;
}

/**
 * Source lines around a finding with the offending line marked. Lines that
 * contain a secret are rendered unhighlighted with the value redacted,
 * unless `revealed` is set.
 */
export default function CodeSnippet({ snippet: rawSnippet, line, file, secrets: rawSecrets, revealed, keyBlock = false }) {
  if (!rawSnippet?.lines?.length) return null;
  let snippet = rawSnippet;
  let secrets = rawSecrets;
  // A private key spans many lines: mask every body line, not one value.
  if (keyBlock && !revealed) {
    snippet = { ...snippet, lines: maskKeyBlock(snippet.lines) };
    secrets = [...(secrets || []), ...snippet.lines.filter((l) => /\*{4,}/.test(l)).map((l) => ({ value: l.trim(), masked: l.trim() }))];
  }
  const lang = languageFor(file);
  const code = snippet.lines.join("\n");
  const hasSecret = (text) => secrets?.some((s) => text.includes(s.value));
  const lastLine = snippet.startLine + snippet.lines.length - 1;
  const gutter = String(lastLine).length;

  const renderLine = (n, content, key) => {
    const hit = n === line;
    return (
      <div key={key} className={`code-line${hit ? " code-line-hit" : ""}`} aria-current={hit ? "true" : undefined}>
        <span className="code-ln" style={{ minWidth: `${gutter}ch` }} aria-hidden="true">
          {n}
        </span>
        <span className="code-text">{content}</span>
        {hit && <span className="visually-hidden"> (flagged line)</span>}
      </div>
    );
  };

  return (
    <figure className="code" aria-label={`${file}, lines ${snippet.startLine} to ${lastLine}`}>
      <figcaption className="code-head mono">
        <span>{file}</span>
        <span className="muted">
          {snippet.startLine}–{lastLine}
        </span>
      </figcaption>
      <pre className="code-body">
        {lang ? (
          <Highlight code={code} language={lang} theme={theme}>
            {({ tokens, getTokenProps }) =>
              tokens.map((toks, i) => {
                const n = snippet.startLine + i;
                const text = snippet.lines[i] ?? "";
                if (!revealed && hasSecret(text)) return renderLine(n, <RedactedText text={text} secrets={secrets} />, i);
                return renderLine(
                  n,
                  toks.map((t, k) => {
                    const { key: _key, ...props } = getTokenProps({ token: t });
                    return <span key={k} {...props} />;
                  }),
                  i
                );
              })
            }
          </Highlight>
        ) : (
          snippet.lines.map((text, i) => renderLine(snippet.startLine + i, <RedactedText text={text} secrets={secrets} revealed={revealed} />, i))
        )}
      </pre>
    </figure>
  );
}
