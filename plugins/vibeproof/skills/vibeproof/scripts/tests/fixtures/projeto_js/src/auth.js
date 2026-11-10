// Autorização fictícia, só para os testes.
function requireAuth(req, res, next) {
  if (!req.headers['x-sessao-ficticia']) return res.status(401).end();
  next();
}
function authorizeAdmin(req, res, next) {
  requireAuth(req, res, next);
}
module.exports = { requireAuth, authorizeAdmin };
