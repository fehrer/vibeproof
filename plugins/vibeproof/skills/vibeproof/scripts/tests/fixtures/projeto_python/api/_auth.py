"""Autorização fictícia, só para os testes do inventário de rotas."""


class Unauthorized(Exception):
    pass


def authorize(headers):
    token = headers.get("X-Sessao-Ficticia") or ""
    if not token:
        raise Unauthorized("sem sessão")
    return {"user": "fulano.teste", "admin": False}


def authorize_admin(headers):
    quem = authorize(headers)
    if not quem["admin"]:
        raise Unauthorized("não é admin")
    return quem
