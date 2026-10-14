// POST /api/share  { report } -> { id, expiresAt }
const { createShare, sendJson } = require("../../backend/src/http/handlers");

module.exports = (req, res) => {
  if (req.method !== "POST") return sendJson(res, 405, { error: "Use POST" });
  return createShare(req, res);
};
