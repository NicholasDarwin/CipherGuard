// GET /api/scan-stream?repo=<github url>  (rewritten from /scan_stream)
const { scanStream } = require("../backend/src/http/handlers");

module.exports = (req, res) => scanStream(req, res);
