"""/api/admin: rota fictícia que chama a variante authorize_admin."""
from http.server import BaseHTTPRequestHandler

import _auth


class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        _auth.authorize_admin(self.headers)
        self.wfile.write(b"ok")
