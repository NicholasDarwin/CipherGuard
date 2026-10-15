/**
 * Link to a file (and line) on GitHub. Uses the scanned commit when the
 * report has it, so line numbers still match after the repo changes;
 * older reports fall back to the default branch.
 */
export function githubFileUrl(report, file, line) {
  if (!file || !report?.repository) return null;
  const ref = report.commit || "HEAD";
  const path = file.split("/").map(encodeURIComponent).join("/");
  return `${report.repository}/blob/${ref}/${path}${line ? `#L${line}` : ""}`;
}
