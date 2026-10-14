// Minimal Markdown renderer for AI text: headings, paragraphs, lists, bold,
// italics and inline code. Builds React elements, so model output can never
// inject HTML.

function inline(text, keyBase) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*)/g;
  let last = 0;
  let m;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    const key = `${keyBase}-${i++}`;
    if (t.startsWith("**")) out.push(<strong key={key}>{t.slice(2, -2)}</strong>);
    else if (t.startsWith("`")) out.push(<code key={key}>{t.slice(1, -1)}</code>);
    else out.push(<em key={key}>{t.slice(1, -1)}</em>);
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export default function Markdown({ text }) {
  if (!text) return null;
  const blocks = [];
  let list = null;
  const flush = () => {
    if (list) blocks.push(list);
    list = null;
  };

  text.split(/\r?\n/).forEach((raw, idx) => {
    const line = raw.trimEnd();
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    const ordered = line.match(/^\s*\d+[.)]\s+(.*)$/);

    if (heading) {
      flush();
      blocks.push({ type: "h", text: heading[2], key: idx });
    } else if (bullet || ordered) {
      const kind = bullet ? "ul" : "ol";
      if (!list || list.type !== kind) {
        flush();
        list = { type: kind, items: [], key: idx };
      }
      list.items.push((bullet || ordered)[1]);
    } else if (!line.trim()) {
      flush();
    } else {
      flush();
      const prev = blocks[blocks.length - 1];
      if (prev?.type === "p" && !prev.closed) prev.text += " " + line.trim();
      else blocks.push({ type: "p", text: line.trim(), key: idx });
    }
    if (!line.trim() && blocks.length) blocks[blocks.length - 1].closed = true;
  });
  flush();

  return (
    <div className="md">
      {blocks.map((b) => {
        if (b.type === "h") return <h4 key={b.key}>{inline(b.text, b.key)}</h4>;
        if (b.type === "p") return <p key={b.key}>{inline(b.text, b.key)}</p>;
        const List = b.type;
        return (
          <List key={b.key}>
            {b.items.map((it, i) => (
              <li key={i}>{inline(it, `${b.key}-${i}`)}</li>
            ))}
          </List>
        );
      })}
    </div>
  );
}
