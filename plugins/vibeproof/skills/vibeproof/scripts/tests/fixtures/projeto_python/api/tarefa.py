"""/api/tarefa: chamada por um agendador fictício, sem sessão.

Não chama `_auth.authorize()`: usa um token compartilhado em header.
"""
import hmac
import os
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        esperado = os.environ.get("TOKEN_FICTICIO", "")
        recebido = self.headers.get("X-Token-Ficticio") or ""
        if not hmac.compare_digest(recebido.encode(), esperado.encode()):
            self.send_response(401)
            return
        self.wfile.write(b"ok")
