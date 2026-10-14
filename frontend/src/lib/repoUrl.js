// Accepts what people paste: full URLs, URLs without a scheme, owner/repo
// shorthand, .git clone URLs, and links to a file or folder inside a repo.
const NAME = /^[A-Za-z0-9_.-]+$/;

export function normalizeRepoInput(raw) {
  let s = String(raw || "").trim();
  if (!s) return { error: "Enter a repository." };
  s = s.replace(/^git@github\.com:/i, "https://github.com/");
  if (!/^https?:\/\//i.test(s)) {
    // "host.tld/..." is a URL without a scheme; plain "owner/repo" is shorthand.
    const looksLikeHost = /^[^/]+\.[a-z]{2,}(\/|$)/i.test(s);
    s = looksLikeHost ? `https://${s}` : `https://github.com/${s.replace(/^\/+/, "")}`;
  }
  let url;
  try {
    url = new URL(s);
  } catch {
    return { error: "That is not a valid URL." };
  }
  if (!/^(www\.)?github\.com$/i.test(url.hostname)) {
    return { error: "Only public GitHub repositories are supported." };
  }
  const [owner, repoRaw] = url.pathname.split("/").filter(Boolean);
  const repo = (repoRaw || "").replace(/\.git$/i, "");
  if (!owner || !repo || !NAME.test(owner) || !NAME.test(repo)) {
    return { error: "Use the form owner/repo or https://github.com/owner/repo." };
  }
  return { url: `https://github.com/${owner}/${repo}`, slug: `${owner}/${repo}` };
}

export const slugOf = (url) => String(url || "").replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/\/$/, "");
