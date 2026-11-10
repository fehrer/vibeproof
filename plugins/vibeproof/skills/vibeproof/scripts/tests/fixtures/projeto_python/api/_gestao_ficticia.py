"""Módulo auxiliar: a checagem de admin mora aqui, não na rota (caso b)."""
import _auth


def checar_permissao(headers):
    return _auth.authorize_admin(headers)


class GestaoMixin(object):

    def _gerir(self, executar):
        quem = _auth.authorize_admin(self.headers)
        return executar(quem)
