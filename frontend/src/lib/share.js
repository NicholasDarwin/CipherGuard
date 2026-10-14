// Share links. Preferred: server-stored, unguessable ID with an expiry
// (/r/<id>). If the server has no storage configured, the redacted report is
// compressed into the URL fragment (/shared#<data>), which browsers never
// send to a server.
import { createShare } from "./api";
import { sanitizeReport } from "./sanitize";

const FRAGMENT_LIMIT = 60_000; // characters; longer URLs break in chat apps and some browsers

function toBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function deflate(text) {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function inflate(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Response(stream).text();
}

// Trim what a reader of a shared link does not need, to keep fragments short.
function compact(report) {
  return { ...report, aiAnalyses: undefined, steps: undefined };
}

export async function makeShareLink(report) {
  const clean = sanitizeReport(report);
  try {
    const { id, expiresAt } = await createShare(clean);
    return { url: `${location.origin}/r/${id}`, kind: "stored", expiresAt };
  } catch (err) {
    if (err.status !== 501) throw err;
  }
  const encoded = toBase64Url(await deflate(JSON.stringify(compact(clean))));
  if (encoded.length > FRAGMENT_LIMIT) {
    throw new Error("This report is too large for a link. Export it as Markdown or PDF instead.");
  }
  return { url: `${location.origin}/shared#${encoded}`, kind: "fragment" };
}

export async function readFragmentReport(hash) {
  const data = hash.replace(/^#/, "");
  if (!data) return null;
  return JSON.parse(await inflate(fromBase64Url(data)));
}
