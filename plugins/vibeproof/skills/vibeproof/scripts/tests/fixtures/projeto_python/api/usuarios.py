"""/api/usuarios: rota fictícia de gestão; a autorização mora em _gestao_ficticia."""
from http.server import BaseHTTPRequestHandler

import _gestao_ficticia as gestao


class handler(gestao.GestaoMixin, BaseHTTPRequestHandler):

    def do_GET(self):
        gestao.checar_permissao(self.headers)
        self.wfile.write(b"[]")

    def do_DELETE(self):
        self._gerir(lambda quem: None)
