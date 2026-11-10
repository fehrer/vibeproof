"""/api/webhook: rota fictícia que compara o header com ==."""
import os
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.headers.get("X-Chave-Ficticia") != os.environ.get("CHAVE_FICTICIA"):
            self.send_response(401)
            return
        self.wfile.write(b"ok")
