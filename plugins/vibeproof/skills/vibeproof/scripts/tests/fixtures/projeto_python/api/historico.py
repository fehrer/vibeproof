"""/api/historico: rota fictícia com a chamada direta."""
from http.server import BaseHTTPRequestHandler

import _auth


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        _auth.authorize(self.headers)
        self.wfile.write(b"[]")
