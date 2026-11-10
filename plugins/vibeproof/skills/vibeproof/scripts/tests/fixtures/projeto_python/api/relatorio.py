"""/api/relatorio: rota fictícia.

Esta rota não chama `_auth.authorize()`, de propósito, e por isso precisa de revisão.
"""
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        # TODO: chamar _auth.authorize(self.headers) aqui
        mensagem = "lembre de usar authorize(headers) antes"
        self.wfile.write(mensagem.encode())
