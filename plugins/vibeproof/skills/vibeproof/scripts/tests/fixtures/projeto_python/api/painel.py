"""/api/painel: rota fictícia com variantes require_* e *_admin."""
from http.server import BaseHTTPRequestHandler

from _permissoes_ficticias import require_owner, somente_admin


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        require_owner(self.headers)
        self.wfile.write(b"ok")

    def do_DELETE(self):
        somente_admin(self.headers)
        self.wfile.write(b"ok")
