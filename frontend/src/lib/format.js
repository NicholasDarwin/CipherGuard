const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const UNITS = [
  ["year", 31536e6],
  ["month", 2592e6],
  ["week", 6048e5],
  ["day", 864e5],
  ["hour", 36e5],
  ["minute", 6e4],
];

export function timeAgo(iso) {
  if (!iso) return "";
  const diff = Date.parse(iso) - Date.now();
  for (const [unit, ms] of UNITS) if (Math.abs(diff) >= ms) return rtf.format(Math.round(diff / ms), unit);
  return "just now";
}

export function formatDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function duration(ms) {
  if (ms == null) return "";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  return s < 60 ? `${s.toFixed(s < 10 ? 1 : 0)} s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

export const num = (n) => (n == null ? "–" : new Intl.NumberFormat().format(n));

export const pct = (x, digits = 1) => (x == null ? "–" : `${(x * 100).toFixed(digits)}%`);

export const plural = (n, word, many = `${word}s`) => `${num(n)} ${n === 1 ? word : many}`;
