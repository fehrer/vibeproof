"""Testes do inventario_rotas.py com projetos fictícios em fixtures/.

Rode com: <python> -m unittest discover -s scripts/tests -v
(a partir da pasta da skill). Só biblioteca padrão.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

AQUI = Path(__file__).resolve().parent
SCRIPT = AQUI.parent / "inventario_rotas.py"
FIXTURES = AQUI / "fixtures"


def inventario(projeto, *extra):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(FIXTURES / projeto), "--json", *extra],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"script falhou ({proc.returncode}): {proc.stderr}")
    dados = json.loads(proc.stdout)
    return {(r["metodo"], r["rota"]): r for r in dados["rotas"]}


class TestePython(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rotas = inventario("projeto_python")

    def rota(self, metodo, caminho):
        chave = (metodo, caminho)
        self.assertIn(chave, self.rotas, f"rota {chave} não foi inventariada")
        return self.rotas[chave]

    # Caso a: texto em docstring, comentário e string não é chamada.
    def test_a_mencao_em_texto_nao_conta(self):
        r = self.rota("GET", "/api/relatorio")
        self.assertEqual(r["auth"], "não encontrada", r)
        self.assertEqual(r["funcoes_auth"], [], r)

    # Caso b: a checagem mora num módulo auxiliar importado.
    def test_b_funcao_de_modulo_auxiliar(self):
        r = self.rota("GET", "/api/usuarios")
        self.assertEqual(r["auth"], "indireta", r)
        self.assertIn("authorize_admin", r["funcoes_auth"], r)
        self.assertTrue(r["via"].startswith("api/_gestao_ficticia.py:"), r)

    def test_b_metodo_herdado_de_mixin_em_outro_modulo(self):
        r = self.rota("DELETE", "/api/usuarios")
        self.assertEqual(r["auth"], "indireta", r)
        self.assertTrue(r["via"].startswith("api/_gestao_ficticia.py:"), r)

    def test_b_metodo_auxiliar_no_proprio_arquivo(self):
        r = self.rota("GET", "/api/relatorios-admin")
        self.assertEqual(r["auth"], "indireta", r)
        self.assertEqual(r["via"], "api/relatorios-admin.py:10", r)

    # Caso c: variantes de nome sem precisar de --auth-nomes.
    def test_c_variante_authorize_sufixo(self):
        r = self.rota("POST", "/api/admin")
        self.assertEqual(r["auth"], "direta", r)
        self.assertEqual(r["funcoes_auth"], ["authorize_admin"], r)

    def test_c_variantes_require_e_admin(self):
        self.assertEqual(self.rota("GET", "/api/painel")["auth"], "direta")
        self.assertEqual(self.rota("DELETE", "/api/painel")["auth"], "direta")

    # Positivo simples.
    def test_positivo_chamada_direta(self):
        r = self.rota("GET", "/api/historico")
        self.assertEqual(r["auth"], "direta", r)
        self.assertEqual(r["via"], "api/historico.py:10", r)

    # Alternativa: segredo em header.
    def test_alternativa_compare_digest(self):
        r = self.rota("POST", "/api/tarefa")
        self.assertEqual(r["auth"], "alternativa", r)
        self.assertIn("compare_digest", r["detalhe"], r)

    def test_alternativa_header_comparado(self):
        r = self.rota("POST", "/api/webhook")
        self.assertEqual(r["auth"], "alternativa", r)
        self.assertIn("header", r["detalhe"], r)

    def test_modulo_com_underscore_nao_e_rota(self):
        self.assertFalse([k for k in self.rotas if "_auth" in k[1] or "_gestao" in k[1]])


class TesteJavaScript(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rotas = inventario("projeto_js")

    def rota(self, metodo, caminho):
        chave = (metodo, caminho)
        self.assertIn(chave, self.rotas, f"rota {chave} não foi inventariada")
        return self.rotas[chave]

    def test_a_comentario_e_string_nao_contam(self):
        self.assertEqual(self.rota("GET", "/api/exportar")["auth"], "não encontrada")

    def test_b_middleware_de_modulo_auxiliar(self):
        r = self.rota("POST", "/api/pedidos")
        self.assertEqual(r["auth"], "indireta", r)
        self.assertTrue(r["via"].startswith("src/permissoes.js:"), r)

    def test_c_variante_camel_case(self):
        self.assertEqual(self.rota("DELETE", "/api/clientes/:id")["auth"], "direta")

    def test_positivo_middleware_direto(self):
        self.assertEqual(self.rota("GET", "/api/perfil")["auth"], "direta")

    def test_alternativa_timing_safe_equal(self):
        r = self.rota("POST", "/api/cron")
        self.assertEqual(r["auth"], "alternativa", r)
        self.assertIn("timingSafeEqual", r["detalhe"], r)


class TesteSaidaTexto(unittest.TestCase):

    def test_rota_sensivel_sem_auth_recebe_alerta(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), str(FIXTURES / "projeto_python")],
            capture_output=True, text=True, encoding="utf-8", check=False,
        )
        linhas = {l.split("|")[2].strip(): l for l in proc.stdout.splitlines()
                  if l.startswith("| ") and "`" in l}
        self.assertNotIn("(!)", linhas["`/api/usuarios`"])
        self.assertIn("indireta (via api/_gestao_ficticia.py:", linhas["`/api/usuarios`"])


if __name__ == "__main__":
    unittest.main()
