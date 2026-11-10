// Módulo auxiliar fictício: a checagem real mora aqui.
const { requireAuth } = require('./auth');

function garantirDono(req, res, next) {
  requireAuth(req, res, next);
}

module.exports = { garantirDono };
