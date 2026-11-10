"""/api/relatorios-admin: o handler chama um método próprio que chama authorize."""
from http.server import BaseHTTPRequestHandler

import _auth


class handler(BaseHTTPRequestHandler):

    def _checar(self):
        return _auth.authorize(self.headers)

    def do_GET(self):
        self._checar()
        self.wfile.write(b"ok")
