// GET /api/share/:id
const { getShare } = require("../../backend/src/http/handlers");

module.exports = (req, res) => getShare(req, res, req.query.id);
