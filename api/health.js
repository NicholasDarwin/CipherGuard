// GET /api/health
const { health } = require("../backend/src/http/handlers");

module.exports = (req, res) => health(req, res);
