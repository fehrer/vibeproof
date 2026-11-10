#!/usr/bin/env python3
"""Inventário de pontos de entrada HTTP, base para a matriz de acesso.

Uso: <python> inventario_rotas.py [raiz] [--json] [--diff BASE..HEAD | --arquivos LISTA]
                                   [--auth-nomes nome1,nome2,...]

Reconhece:
  - frameworks: Express/Fastify/Hono/Koa, NestJS, FastAPI, Flask, Django, SvelteKit, Nuxt,
    Supabase Edge Functions e Firebase Functions;
  - roteamento por nome de arquivo: Next.js (app/**/route.* e pages/api/**) e a pasta api/
    no estilo Vercel (api/*.py, api/*.js, api/*.ts; arquivo ou pasta começando com _ não é rota);
  - servidores sem framework: classes BaseHTTPRequestHandler (do_GET, do_POST...) e
    http.createServer do Node.

Para cada rota, classifica a autorização em:
  direta          a rota chama (ou usa como decorator/middleware) uma função de autorização;
  indireta        a rota chama uma função do próprio projeto que chama a autorização
                  (mostra arquivo:linha da chamada real e o caminho até ela);
  alternativa     sem função de autorização, mas com segredo comparado: hmac.compare_digest,
                  secrets.compare_digest, crypto.timingSafeEqual ou header lido e comparado;
  não encontrada  nada disso foi achado.

Só contam CHAMADAS e usos reais. Texto em comentário, docstring ou string nunca conta: em
Python a análise é feita na árvore sintática (ast); nas outras linguagens, comentários e
strings são removidos antes da busca. Importar ou definir a função também não conta.

Os nomes vêm de NOMES_AUTH_PADRAO mais --auth-nomes e casam com variantes: authorize_*,
authenticate_*, require_*, autorizar_*, autenticar_*, as formas camelCase (authorizeAdmin,
requireOwner) e *_admin / *Admin. É heurística: confirme lendo o código e testando sem
sessão. Somente leitura. Não faz requisições de rede.
"""

import ast
import io
import json
import re
import sys
import tokenize
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _comum import (arquivos_no_escopo, eh_codigo, ler_texto, linha_de_escopo,  # noqa: E402
                    parser_base, rel, resolver_escopo)

NOMES_AUTH_PADRAO = [
    "authenticate", "authorize", "requireAuth", "requireUser", "requireAdmin", "requireRole",
    "requireLogin", "isAuthenticated", "ensureAuthenticated", "ensureAuth", "verifyToken", "verifyJwt",
    "checkAuth", "withAuth", "protect", "getServerSession", "getSession", "getUser", "currentUser",
    "auth", "UseGuards", "login_required", "permission_required", "get_current_user",
    "require_auth", "autenticar", "autorizar", "exigir_login", "exigir_admin",
]

# Prefixos que casam com variantes: authorize_admin, authorizeAdmin, require_owner...
PREFIXOS_VARIANTE = ["authorize", "authenticate", "require", "autorizar", "autenticar"]
# Sufixos que casam com variantes: somente_admin, onlyAdmin, is_admin...
SUFIXOS_VARIANTE = ["_admin", "Admin"]

# Comparação de segredo em tempo constante: autorização alternativa (token, assinatura).
COMPARACAO_CONSTANTE = {"compare_digest", "timingSafeEqual", "constant_time_compare"}

PROFUNDIDADE_MAX = 3  # quantos níveis de chamada seguir dentro do projeto
NAO_ENCONTRADA = "não encontrada"

METODOS_HTTP = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
EXT_JS = r"\.(m?[jt]sx?|c[jt]s)$"

EXPRESS = re.compile(r"\b(app|router|server|api|r|routes|fastify|hono|\w+Router)\.(get|post|put|patch|delete|all|options|head|use)\(\s*['\"`]([^'\"`]+)['\"`]")
NEST_CTRL = re.compile(r"@Controller\(\s*['\"]?([^'\")]*)")
NEST_ROTA = re.compile(r"@(Get|Post|Put|Patch|Delete|All|Head|Options)\(\s*['\"]?([^'\")]*)")
FASTAPI = re.compile(r"@(\w+)\.(get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]+)")
FLASK = re.compile(r"@(\w+)\.route\(\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?")
DJANGO = re.compile(r"\b(re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)")
FIREBASE_FN = re.compile(r"export(s)?\.?\s*(const\s+)?(\w+)\s*=\s*(functions\.https\.(onRequest|onCall)|onRequest|onCall)\(")
EXPORT_METODO = re.compile(rf"export\s+(?:async\s+)?(?:function\s+|const\s+)({METODOS_HTTP})\b")
DO_METODO = re.compile(rf"^(\s*)def\s+do_({METODOS_HTTP})\s*\(\s*self")
CAMINHO_PY = re.compile(r"""(?:self\.path|\.path|caminho|path)\s*(?:==|\.startswith\()\s*['"]([^'"]+)['"]""")
CAMINHO_JS = re.compile(r"""(?:req\.url|request\.url|url\.pathname|pathname)\s*(?:===?|\.startsWith\()\s*['"`]([^'"`]+)['"`]""")
METODO_JS = re.compile(rf"""(?:req|request)\.method\s*===?\s*['"`]({METODOS_HTTP})['"`]""")
METODO_PAGES = re.compile(rf"""req\.method\s*(?:===?|!==?)\s*['"`]({METODOS_HTTP})['"`]""")
SEM_STRINGS = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")
IMPORTACAO = re.compile(r"^\s*(import\b|from\s+\S+\s+import\b|export\s+\{|.*\brequire\s*\()")
IDENTIFICADOR = re.compile(r"(?<![\w$])@?([A-Za-z_$][\w$]*)\b(?!\s*[:=](?!=))")
DEFINICAO_JS = re.compile(r"\b(?:def|function|class|const|let|var)\s+([A-Za-z_$][\w$]*)|^\s*([A-Za-z_$][\w$]*)\s*=\s*")
HEADER_JS = re.compile(r"""\b(?:req|request|event|ctx|c)\.(?:headers|header)\s*(?:\[|\.get\s*\(|\()""")
COMPARACAO_JS = re.compile(r"(?<![=!<>])(?:===?|!==?)(?!=)")
COMPARA_VAZIO_JS = re.compile(r"(?:===?|!==?)\s*(?:''|null|undefined)(?![\w$])|(?<![\w$])(?:''|null|undefined)\s*(?:===?|!==?)")

COMENTARIO_LINHA = {".rb": "#", ".sh": "#", ".yml": "#", ".yaml": "#", ".toml": "#"}


# ---------------------------------------------------------------------------
# Nomes de autorização
# ---------------------------------------------------------------------------

class NomesDeAuth:
    """Decide se um nome de função é de autorização (nome exato ou variante)."""

    def __init__(self, nomes, extras=()):
        self.nomes = list(dict.fromkeys(n for n in nomes if n))
        self.exatos = set(self.nomes)
        # Nomes passados pela pessoa também valem como prefixo (meu_auth -> meu_auth_admin).
        self.prefixos = list(dict.fromkeys(PREFIXOS_VARIANTE + [n for n in extras if n]))

    def casa(self, nome) -> bool:
        if not nome:
            return False
        nome = nome.lstrip("@")
        if nome in self.exatos:
            return True
        for p in self.prefixos:
            if len(nome) > len(p) and nome.startswith(p) and (nome[len(p)] == "_" or nome[len(p)].isupper()):
                return True
        for s in SUFIXOS_VARIANTE:
            if len(nome) > len(s) and nome.endswith(s) and nome[:-len(s)].strip("_"):
                return True
        return False


# ---------------------------------------------------------------------------
# Limpeza de comentário e string (análise por texto)
# ---------------------------------------------------------------------------

def remover_comentarios_c(texto: str) -> str:
    """Troca comentários // e /* */ por espaços, mantendo strings e quebras de linha."""
    saida, i, n = [], 0, len(texto)
    while i < n:
        c = texto[i]
        if c in "'\"`":
            j = i + 1
            while j < n and texto[j] != c:
                if texto[j] == "\\":
                    j += 1
                elif texto[j] == "\n" and c != "`":
                    break
                j += 1
            saida.append(texto[i:j + 1])
            i = j + 1
        elif texto.startswith("//", i):
            j = texto.find("\n", i)
            j = n if j < 0 else j
            saida.append(" " * (j - i))
            i = j
        elif texto.startswith("/*", i):
            j = texto.find("*/", i + 2)
            j = n if j < 0 else j + 2
            saida.append("".join("\n" if ch == "\n" else " " for ch in texto[i:j]))
            i = j
        else:
            saida.append(c)
            i += 1
    return "".join(saida)


def remover_comentarios_e_strings_py(texto: str) -> str:
    """Python que não compila: apaga COMMENT e STRING via tokenize, mantendo as linhas."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(texto).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return "\n".join(l.split("#", 1)[0] for l in texto.splitlines())
    linhas = [list(l) for l in texto.splitlines(True)]
    for tok in tokens:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (l1, c1), (l2, c2) = tok.start, tok.end
        for ln in range(l1, min(l2, len(linhas)) + 1):
            linha = linhas[ln - 1]
            for k in range(c1 if ln == l1 else 0, min(c2 if ln == l2 else len(linha), len(linha))):
                if linha[k] != "\n":
                    linha[k] = " "
    return "".join("".join(l) for l in linhas)


def texto_limpo(r: str, texto: str) -> str:
    if r.endswith(".py"):
        return remover_comentarios_e_strings_py(texto)
    sufixo = Path(r).suffix.lower()
    if sufixo in COMENTARIO_LINHA:
        return "\n".join(l.split(COMENTARIO_LINHA[sufixo], 1)[0] for l in texto.splitlines())
    return remover_comentarios_c(texto)


def resultado(tipo, funcoes=(), via=None, detalhe="", cadeia=()):
    return {"auth": tipo, "funcoes_auth": sorted(set(funcoes)), "via": via,
            "detalhe": detalhe, "cadeia": list(cadeia)}


# ---------------------------------------------------------------------------
# Python: análise pela árvore sintática
# ---------------------------------------------------------------------------

def nome_chamado(no):
    """Nome terminal de quem é chamado: _auth.authorize -> authorize."""
    if isinstance(no, ast.Name):
        return no.id
    if isinstance(no, ast.Attribute):
        return no.attr
    return None


def nome_pontilhado(no):
    if isinstance(no, ast.Name):
        return no.id
    if isinstance(no, ast.Attribute):
        base = nome_pontilhado(no.value)
        return f"{base}.{no.attr}" if base != "?" else no.attr
    return "?"


def le_header(no) -> bool:
    """self.headers.get(...), request.headers[...], headers.get(...) e afins."""
    for sub in ast.walk(no):
        alvo = None
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr in ("get", "getheader"):
            alvo = sub.func.value
        elif isinstance(sub, ast.Subscript):
            alvo = sub.value
        if alvo is not None and nome_chamado(alvo) in ("headers", "META"):
            return True
    return False


def eh_constante_vazia(no) -> bool:
    return isinstance(no, ast.Constant) and (no.value is None or no.value in ("", b""))


class ModuloPy:
    """Índice de um arquivo Python: funções, classes e importações."""

    def __init__(self, caminho: Path, arvore):
        self.caminho = caminho
        self.arvore = arvore
        self.funcoes, self.classes, self.aliases, self.importados = {}, {}, {}, {}
        for no in arvore.body:
            if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcoes[no.name] = no
            elif isinstance(no, ast.ClassDef):
                self.classes[no.name] = no
        for no in ast.walk(arvore):
            if isinstance(no, ast.Import):
                for a in no.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = (a.name, 0)
            elif isinstance(no, ast.ImportFrom):
                for a in no.names:
                    self.importados[a.asname or a.name] = (no.module or "", a.name, no.level)


class ProjetoPy:
    """Carrega módulos do próprio projeto sob demanda, para seguir chamadas."""

    def __init__(self, raiz: Path, nomes: NomesDeAuth):
        self.raiz = raiz.resolve()
        self.nomes = nomes
        self.cache = {}

    def modulo(self, caminho: Path):
        caminho = caminho.resolve()
        if caminho not in self.cache:
            self.cache[caminho] = None
            texto = ler_texto(caminho)
            if texto is not None:
                try:
                    self.cache[caminho] = ModuloPy(caminho, ast.parse(texto))
                except (SyntaxError, ValueError):
                    pass
        return self.cache[caminho]

    def rel(self, caminho: Path) -> str:
        return rel(caminho, self.raiz).replace("\\", "/")

    def achar_modulo(self, de: ModuloPy, nome: str, nivel: int = 0):
        """Arquivo do projeto para `import nome` feito em `de`. None se for externo."""
        partes = [p for p in nome.split(".") if p]
        if nivel:
            base = de.caminho.parent
            for _ in range(nivel - 1):
                base = base.parent
            bases = [base]
        else:
            bases = [de.caminho.parent, self.raiz]
        for base in bases:
            alvo = base.joinpath(*partes) if partes else base
            candidatos = ([alvo.with_suffix(".py")] if partes else []) + [alvo / "__init__.py"]
            for candidato in candidatos:
                if not candidato.is_file():
                    continue
                try:
                    candidato.resolve().relative_to(self.raiz)
                except ValueError:
                    continue
                return self.modulo(candidato)
        return None

    def modulo_do_alias(self, de: ModuloPy, alias: str):
        if alias in de.aliases:
            nome, nivel = de.aliases[alias]
            return self.achar_modulo(de, nome, nivel)
        if alias in de.importados:  # from . import modulo
            mod, attr, nivel = de.importados[alias]
            return self.achar_modulo(de, f"{mod}.{attr}" if mod else attr, nivel)
        return None

    def classe(self, de: ModuloPy, expr):
        """Resolve a expressão de uma classe base para (ModuloPy, ClassDef)."""
        if isinstance(expr, ast.Name):
            if expr.id in de.classes:
                return de, de.classes[expr.id]
            if expr.id in de.importados:
                mod, attr, nivel = de.importados[expr.id]
                outro = self.achar_modulo(de, mod, nivel)
                if outro and attr in outro.classes:
                    return outro, outro.classes[attr]
        elif isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            outro = self.modulo_do_alias(de, expr.value.id)
            if outro and expr.attr in outro.classes:
                return outro, outro.classes[expr.attr]
        return None

    def metodo(self, mod: ModuloPy, cls, nome: str, vistos=None, pular_propria=False):
        """Procura o método na classe e nas bases (ordem aproximada da MRO)."""
        vistos = vistos if vistos is not None else set()
        chave = (mod.caminho, cls.name)
        if chave in vistos:
            return None
        vistos.add(chave)
        if not pular_propria:
            for no in cls.body:
                if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)) and no.name == nome:
                    return no, mod, cls
        for base in cls.bases:
            achado = self.classe(mod, base)
            if achado:
                r = self.metodo(achado[0], achado[1], nome, vistos)
                if r:
                    return r
        return None

    def resolver(self, chamada: ast.Call, mod: ModuloPy, cls):
        """Função do projeto chamada aqui: (FunctionDef, ModuloPy, ClassDef|None) ou None."""
        f = chamada.func
        if isinstance(f, ast.Attribute):
            v = f.value
            if isinstance(v, ast.Name) and v.id in ("self", "cls") and cls is not None:
                return self.metodo(mod, cls, f.attr)
            if isinstance(v, ast.Call) and nome_chamado(v.func) == "super" and cls is not None:
                return self.metodo(mod, cls, f.attr, pular_propria=True)
            if isinstance(v, ast.Name):
                outro = self.modulo_do_alias(mod, v.id)
                if outro and f.attr in outro.funcoes:
                    return outro.funcoes[f.attr], outro, None
        elif isinstance(f, ast.Name):
            if f.id in mod.funcoes:
                return mod.funcoes[f.id], mod, None
            if f.id in mod.importados:
                m, attr, nivel = mod.importados[f.id]
                outro = self.achar_modulo(mod, m, nivel)
                if outro and attr in outro.funcoes:
                    return outro.funcoes[attr], outro, None
        return None

    # -- classificação ------------------------------------------------------

    def _chamadas_auth(self, nos):
        """Chamadas a funções de autorização (nós Call; texto nunca conta)."""
        return [(sub.lineno, nome_chamado(sub.func)) for no in nos for sub in ast.walk(no)
                if isinstance(sub, ast.Call) and self.nomes.casa(nome_chamado(sub.func))]

    def _referencias_auth(self, nos):
        """Decorators e defaults (Depends(get_current_user)): referência já é uso."""
        return [(sub.lineno, nome_chamado(sub)) for no in nos for sub in ast.walk(no)
                if isinstance(sub, (ast.Name, ast.Attribute)) and self.nomes.casa(nome_chamado(sub))]

    def _alternativa(self, nos):
        """Segredo comparado: compare_digest, ou header lido e comparado com ==/!=."""
        for no in nos:
            for sub in ast.walk(no):
                if isinstance(sub, ast.Call) and nome_chamado(sub.func) in COMPARACAO_CONSTANTE:
                    return sub.lineno, f"segredo comparado em tempo constante ({nome_pontilhado(sub.func)})"
        de_header = set()
        for no in nos:
            for sub in ast.walk(no):
                if isinstance(sub, (ast.Assign, ast.AnnAssign)) and sub.value is not None and le_header(sub.value):
                    for alvo in (sub.targets if isinstance(sub, ast.Assign) else [sub.target]):
                        if isinstance(alvo, ast.Name):
                            de_header.add(alvo.id)

        def vem_do_header(x):
            return le_header(x) or any(isinstance(n, ast.Name) and n.id in de_header for n in ast.walk(x))

        for no in nos:
            for sub in ast.walk(no):
                if not isinstance(sub, ast.Compare) or not all(isinstance(op, (ast.Eq, ast.NotEq)) for op in sub.ops):
                    continue
                lados = [sub.left] + list(sub.comparators)
                if any(vem_do_header(x) for x in lados) and not any(eh_constante_vazia(x) for x in lados):
                    return sub.lineno, "header lido e comparado com ==/!=, sem tempo constante"
        return None

    def classificar(self, nos, refs, mod, cls):
        """Classifica um trecho: corpo da rota (nos) e decorators/defaults (refs)."""
        rmod = self.rel(mod.caminho)
        diretos = self._referencias_auth(refs) + self._chamadas_auth(nos)
        if diretos:
            return resultado("direta", [n for _, n in diretos], f"{rmod}:{min(l for l, _ in diretos)}")
        achado = self._seguir(nos, mod, cls, 1, set())
        if achado:
            via, nomes, cadeia = achado
            return resultado("indireta", nomes, via, cadeia=cadeia)
        alt = self._alternativa(nos)
        if alt:
            return resultado("alternativa", via=f"{rmod}:{alt[0]}", detalhe=alt[1])
        return resultado(NAO_ENCONTRADA)

    def _seguir(self, nos, mod, cls, nivel, vistos):
        """Segue as chamadas para funções do projeto até achar a autorização."""
        if nivel > PROFUNDIDADE_MAX:
            return None
        chamadas = sorted((sub for no in nos for sub in ast.walk(no) if isinstance(sub, ast.Call)),
                          key=lambda c: (c.lineno, c.col_offset))
        for chamada in chamadas:
            alvo = self.resolver(chamada, mod, cls)
            if not alvo:
                continue
            func, mod2, cls2 = alvo
            chave = (mod2.caminho, func.lineno)
            if chave in vistos:
                continue
            vistos.add(chave)
            passo = f"{self.rel(mod2.caminho)}:{func.lineno} {func.name}()"
            diretos = self._chamadas_auth(func.body) + self._referencias_auth(func.decorator_list)
            if diretos:
                via = f"{self.rel(mod2.caminho)}:{min(l for l, _ in diretos)}"
                return via, [n for _, n in diretos], [passo]
            mais = self._seguir(func.body, mod2, cls2, nivel + 1, vistos)
            if mais:
                return mais[0], mais[1], [passo] + mais[2]
        return None

    def linhas_com_auth(self, mod):
        return sorted({l for l, _ in self._chamadas_auth([mod.arvore])})


def funcoes_com_classe(arvore):
    """(FunctionDef, ClassDef|None) para toda função do arquivo."""
    pares = []

    def visitar(no, cls):
        for filho in ast.iter_child_nodes(no):
            if isinstance(filho, ast.ClassDef):
                visitar(filho, filho)
            elif isinstance(filho, (ast.FunctionDef, ast.AsyncFunctionDef)):
                pares.append((filho, cls))
                visitar(filho, None)
            else:
                visitar(filho, cls)
    visitar(arvore, None)
    return pares


def trecho_py_da_rota(arvore, linha):
    """(nos, refs, ClassDef|None) da rota declarada na `linha` (1-based), ou None."""
    pares = funcoes_com_classe(arvore)

    def refs_de(func):
        return func.decorator_list + [d for d in func.args.defaults + func.args.kw_defaults if d is not None]

    for func, cls in pares:  # FastAPI/Flask: a linha é a do decorator
        if any(getattr(d, "lineno", -1) == linha for d in func.decorator_list):
            return func.body, refs_de(func), cls
    dentro = [(f, c) for f, c in pares if f.lineno <= linha <= getattr(f, "end_lineno", f.lineno)]
    if not dentro:
        return None
    func, cls = max(dentro, key=lambda p: p[0].lineno)
    if func.lineno != linha:
        # Rota declarada dentro do corpo (if self.path == '/x'): o if e o que vem antes dele.
        for sub in ast.walk(func):
            if isinstance(sub, ast.If) and sub.lineno == linha:
                antes = [s for s in func.body if getattr(s, "end_lineno", s.lineno) < sub.lineno]
                return antes + sub.body, refs_de(func), cls
    return func.body, refs_de(func), cls


# ---------------------------------------------------------------------------
# JS/TS e Python que não compila: análise por texto, sem comentário e sem string
# ---------------------------------------------------------------------------

def bloco_python(linhas, inicio):
    """Intervalo [inicio, fim) do corpo de uma função Python (0-based)."""
    recuo = len(linhas[inicio]) - len(linhas[inicio].lstrip())
    fim = inicio + 1
    while fim < len(linhas):
        atual = linhas[fim]
        if atual.strip() and (len(atual) - len(atual.lstrip())) <= recuo:
            break
        fim += 1
    return inicio, fim


def bloco_js(linhas, inicio, limite=400):
    """Intervalo [inicio, fim) de um bloco JS/TS, contando chaves (aproximado)."""
    profundidade, abriu = 0, False
    for i in range(inicio, min(len(linhas), inicio + limite)):
        profundidade += linhas[i].count("{") - linhas[i].count("}")
        abriu = abriu or "{" in linhas[i]
        if abriu and profundidade <= 0:
            return inicio, i + 1
    return inicio, min(len(linhas), inicio + limite)


def decoradores_acima(linhas, i):
    """Índice da primeira linha de decorators logo acima da linha `i`."""
    inicio = i
    while inicio > 0 and linhas[inicio - 1].strip().startswith("@"):
        inicio -= 1
    return inicio


def assinatura_abaixo(linhas, i, limite=8):
    """Fim (exclusivo) dos decorators abaixo da rota e da assinatura da função."""
    fim = i + 1
    for k, linha in enumerate(linhas[i + 1:i + 1 + limite]):
        fim = i + 2 + k
        s = linha.rstrip()
        if not s.strip().startswith("@") and (s.endswith(":") or s.endswith("{") or ")" in s):
            if re.search(r"\b(def|async def|function)\b|\w+\s*\(", s):
                break
    return fim


class AnalisadorTexto:
    """Classificação por texto: JS/TS, outras linguagens e Python que não compila."""

    EXTENSOES = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")

    def __init__(self, raiz: Path, nomes: NomesDeAuth):
        self.raiz = raiz.resolve()
        self.nomes = nomes
        self.cache = {}

    def linhas(self, caminho: Path):
        """Linhas do arquivo sem comentários (strings ficam; são apagadas linha a linha)."""
        caminho = caminho.resolve()
        if caminho not in self.cache:
            texto = ler_texto(caminho)
            self.cache[caminho] = None if texto is None else texto_limpo(
                rel(caminho, self.raiz).replace("\\", "/"), texto).splitlines()
        return self.cache[caminho]

    def usos(self, linhas, inicio, fim):
        """[(índice da linha, nome)] de usos de funções de autorização em linhas[inicio:fim]."""
        achados = []
        for i in range(max(0, inicio), min(fim, len(linhas))):
            if IMPORTACAO.search(linhas[i]):
                continue
            linha = SEM_STRINGS.sub("''", linhas[i])
            definidos = {m.group(1) or m.group(2) for m in DEFINICAO_JS.finditer(linha)}
            for m in IDENTIFICADOR.finditer(linha):
                if m.group(1) not in definidos and self.nomes.casa(m.group(1)):
                    achados.append((i, m.group(1)))
        return achados

    def identificadores(self, linhas, inicio, fim):
        vistos = []
        for i in range(max(0, inicio), min(fim, len(linhas))):
            if IMPORTACAO.search(linhas[i]):
                continue
            for m in IDENTIFICADOR.finditer(SEM_STRINGS.sub("''", linhas[i])):
                if m.group(1) not in vistos:
                    vistos.append(m.group(1))
        return vistos

    @staticmethod
    def definicao(linhas, nome):
        """Índice da linha onde `nome` é definido como função neste arquivo."""
        n = re.escape(nome)
        padrao = re.compile(rf"\bfunction\s*\*?\s*{n}\s*\(|\b(?:const|let|var)\s+{n}\s*=\s*"
                            rf"(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)")
        for i, linha in enumerate(linhas):
            if padrao.search(linha):
                return i
        return None

    def importacao(self, caminho: Path, linhas, nome):
        """Arquivo do projeto de onde `nome` é importado (import/require relativo)."""
        n = re.escape(nome)
        padroes = [
            rf"import\s+[^;]*?\b{n}\b[^;]*?from\s*['\"](\.[^'\"]+)['\"]",
            rf"(?:const|let|var)\s*\{{[^}}]*\b{n}\b[^}}]*\}}\s*=\s*require\(\s*['\"](\.[^'\"]+)['\"]",
            rf"(?:const|let|var)\s+{n}\s*=\s*require\(\s*['\"](\.[^'\"]+)['\"]",
        ]
        texto = "\n".join(linhas)
        for p in padroes:
            m = re.search(p, texto)
            if not m:
                continue
            base = caminho.parent / m.group(1)
            candidatos = [base] + [base.with_name(base.name + e) for e in self.EXTENSOES] + \
                         [base / f"index{e}" for e in self.EXTENSOES]
            for cand in candidatos:
                if cand.is_file():
                    try:
                        cand.resolve().relative_to(self.raiz)
                    except ValueError:
                        return None
                    return cand
        return None

    def alternativa(self, linhas, inicio, fim):
        """Segredo comparado: timingSafeEqual/compare_digest, ou header lido e comparado."""
        faixa = range(max(0, inicio), min(fim, len(linhas)))
        for i in faixa:
            for nome in sorted(COMPARACAO_CONSTANTE):
                if re.search(rf"\b{nome}\s*\(", linhas[i]):
                    return i, f"segredo comparado em tempo constante ({nome})"
        de_header = set()
        for i in faixa:
            m = re.search(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", linhas[i])
            if m and HEADER_JS.search(linhas[i]):
                de_header.add(m.group(1))
        for i in faixa:
            linha = SEM_STRINGS.sub("''", linhas[i])
            if not COMPARACAO_JS.search(linha) or COMPARA_VAZIO_JS.search(linha):
                continue
            if HEADER_JS.search(linhas[i]) or any(re.search(rf"(?<![\w$.]){re.escape(v)}\b", linha) for v in de_header):
                return i, "header lido e comparado com ===/!==, sem tempo constante"
        return None

    def classificar(self, caminho: Path, inicio, fim, extra_direto=None):
        linhas = self.linhas(caminho)
        if linhas is None:
            return resultado(NAO_ENCONTRADA)
        r = rel(caminho, self.raiz).replace("\\", "/")
        diretos = self.usos(linhas, inicio, fim)
        if extra_direto:
            diretos.append((inicio, extra_direto))
        if diretos:
            return resultado("direta", [n for _, n in diretos], f"{r}:{min(i for i, _ in diretos) + 1}")
        achado = self._seguir(caminho, linhas, inicio, fim, 1, set())
        if achado:
            via, nomes, cadeia = achado
            return resultado("indireta", nomes, via, cadeia=cadeia)
        alt = self.alternativa(linhas, inicio, fim)
        if alt:
            return resultado("alternativa", via=f"{r}:{alt[0] + 1}", detalhe=alt[1])
        return resultado(NAO_ENCONTRADA)

    def _seguir(self, caminho, linhas, inicio, fim, nivel, vistos):
        """Segue nomes usados no trecho até a definição (no arquivo ou em import relativo)."""
        if nivel > PROFUNDIDADE_MAX:
            return None
        for nome in self.identificadores(linhas, inicio, fim):
            alvo, alvo_linhas, def_i = caminho, linhas, self.definicao(linhas, nome)
            if def_i is None or inicio <= def_i < fim:
                outro = self.importacao(caminho, linhas, nome)
                outro_linhas = self.linhas(outro) if outro else None
                def_i = self.definicao(outro_linhas, nome) if outro_linhas else None
                if def_i is None:
                    continue
                alvo, alvo_linhas = outro, outro_linhas
            chave = (str(alvo), def_i)
            if chave in vistos:
                continue
            vistos.add(chave)
            r_alvo = rel(alvo, self.raiz).replace("\\", "/")
            a, b = bloco_js(alvo_linhas, def_i)
            diretos = [(i, n) for i, n in self.usos(alvo_linhas, a, b) if not (i == def_i and n == nome)]
            passo = f"{r_alvo}:{def_i + 1} {nome}()"
            if diretos:
                return f"{r_alvo}:{min(i for i, _ in diretos) + 1}", [n for _, n in diretos], [passo]
            mais = self._seguir(alvo, alvo_linhas, a + 1, b, nivel + 1, vistos)
            if mais:
                return mais[0], mais[1], [passo] + mais[2]
        return None


# ---------------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------------

def rota_por_arquivo(r: str):
    """Frameworks com roteamento por pastas. Devolve (framework, rota) ou (None, None)."""
    m = re.search(r"(?:^|/)(?:src/)?app/(?:(.*)/)?route\.(?:m?[jt]sx?)$", r)
    if m:
        return "Next.js (app)", "/" + re.sub(r"\([^)]*\)/?", "", m.group(1) or "").strip("/")
    m = re.search(r"(?:^|/)(?:src/)?pages/(api/.*)\.(?:m?[jt]sx?)$", r)
    if m:
        return "Next.js (pages)", "/" + re.sub(r"/index$", "", m.group(1))
    m = re.match(r"api/(.+)\.(py|m?[jt]s|c[jt]s)$", r)
    if m and not any(parte.startswith("_") for parte in m.group(1).split("/")):
        return "Vercel (api/)", "/api/" + re.sub(r"(^|/)index$", "", m.group(1)).strip("/")
    m = re.search(r"(?:^|/)src/routes/(.*)/\+server\.(?:[jt]s)$", r)
    if m:
        return "SvelteKit", "/" + m.group(1)
    m = re.search(r"(?:^|/)src/routes/(.*)/\+page\.server\.(?:[jt]s)$", r)
    if m:
        return "SvelteKit (actions)", "/" + m.group(1)
    m = re.search(r"(?:^|/)server/(api|routes)/(.*)\.(?:[jt]s)$", r)
    if m:
        return "Nuxt/Nitro", "/" + ("api/" if m.group(1) == "api" else "") + re.sub(r"/index$", "", m.group(2))
    m = re.search(r"(?:^|/)supabase/functions/([^/]+)/index\.(?:[jt]s)$", r)
    if m:
        return "Supabase Edge Function", "/functions/v1/" + m.group(1)
    return None, None


def eh_teste(r: str) -> bool:
    return bool(re.search(r"(^|/)(test|tests|__tests__|spec|e2e)/|\.(test|spec)\.|(^|/)test_[^/]+\.py$", r))


def analisar_arquivo(caminho: Path, r, texto, projeto: ProjetoPy, analisador: AnalisadorTexto):
    linhas = texto.splitlines()
    eh_py = r.endswith(".py")
    eh_js = bool(re.search(EXT_JS, r))
    mod = projeto.modulo(caminho) if eh_py else None
    rotas = []

    def add(fw, metodo, caminho_rota, linha, ini, fim, extra_direto=None, so_texto=False):
        """`linha` é 1-based (0 = arquivo inteiro); [ini, fim) é o trecho da análise por texto."""
        if mod and not so_texto:
            trecho = trecho_py_da_rota(mod.arvore, linha) if linha else None
            nos, refs, cls = trecho if trecho else ([mod.arvore], [], None)
            info = projeto.classificar(nos, refs, mod, cls)
        else:
            info = analisador.classificar(caminho, ini, fim, extra_direto)
        obs = ""
        if info["auth"] == NAO_ENCONTRADA:
            if mod:
                outras = projeto.linhas_com_auth(mod)
            else:
                outras = sorted({i + 1 for i, _ in analisador.usos(analisador.linhas(caminho) or [], 0, len(linhas))})
            if outras:
                obs = (f"há chamada de autorização em outro ponto do arquivo (linha {outras[0]}); "
                       "confira se ela alcança esta rota")
        rotas.append({"framework": fw, "metodo": metodo.upper(), "rota": caminho_rota or "/",
                      "arquivo": r, "linha": linha, **info, "obs": obs})

    # 1. Roteamento por arquivo (Next.js, Vercel api/, SvelteKit, Nuxt, Supabase)
    fw, rota = rota_por_arquivo(r)
    if fw:
        metodos = []
        for i, linha in enumerate(linhas):
            m = EXPORT_METODO.search(linha) if eh_js else None
            if m:
                metodos.append((m.group(1), i))
            m = DO_METODO.search(linha) if eh_py else None
            if m:
                metodos.append((m.group(2), i))
        if metodos:
            for metodo, i in metodos:
                add(fw, metodo, rota, i + 1, *(bloco_python(linhas, i) if eh_py else bloco_js(linhas, i)))
        else:
            # Um handler único para o arquivo inteiro (pages/api, Vercel com export default...).
            for metodo in sorted(set(METODO_PAGES.findall(texto))) or ["*"]:
                add(fw, metodo, rota, 0, 0, len(linhas))
        return rotas

    # 2. Server Actions do Next.js
    if eh_js and ("'use server'" in texto or '"use server"' in texto):
        for i, linha in enumerate(linhas):
            m = re.search(r"export\s+(?:async\s+)?function\s+(\w+)", linha)
            if m:
                add("Server Action", "ACTION", m.group(1), i + 1, *bloco_js(linhas, i))

    # 3. Frameworks declarados no código
    prefixo_nest, guard_no_controller = "", False
    for i, linha in enumerate(linhas):
        n = i + 1
        ini_dec = decoradores_acima(linhas, i)
        if eh_js:
            for m in EXPRESS.finditer(linha):
                add("Express-like", m.group(2), m.group(3), n, *bloco_js(linhas, i, limite=60))
            m = NEST_CTRL.search(linha)
            if m:
                prefixo_nest = "/" + m.group(1).strip("/") if m.group(1) else ""
                guard_no_controller = bool(analisador.usos(analisador.linhas(caminho) or [], ini_dec, i + 1))
            m = NEST_ROTA.search(linha)
            if m:
                sub = ("/" + m.group(2).strip("/")) if m.group(2) else ""
                add("NestJS", m.group(1), (prefixo_nest + sub) or "/", n, ini_dec,
                    assinatura_abaixo(linhas, i, limite=3), "UseGuards" if guard_no_controller else None)
            m = FIREBASE_FN.search(linha)
            if m:
                add("Firebase Function", m.group(5) or m.group(4), m.group(3), n, *bloco_js(linhas, i))
        if eh_py:
            m = FASTAPI.search(linha)
            if m:
                add("FastAPI", m.group(2), m.group(3), n, ini_dec, assinatura_abaixo(linhas, i))
            m = FLASK.search(linha)
            if m:
                for metodo in re.findall(r"['\"](\w+)['\"]", m.group(3) or "") or ["GET"]:
                    add("Flask", metodo, m.group(2), n, ini_dec, assinatura_abaixo(linhas, i))
            if r.endswith("urls.py"):
                m = DJANGO.search(linha)
                if m:
                    add("Django", "*", "/" + m.group(2), n, i, i + 1, so_texto=True)

    # 4. Python sem framework: BaseHTTPRequestHandler
    if eh_py and "BaseHTTPRequestHandler" in texto:
        for i, linha in enumerate(linhas):
            m = DO_METODO.search(linha)
            if not m:
                continue
            ini, fim = bloco_python(linhas, i)
            caminhos = [(c, j) for j in range(ini, fim) for c in CAMINHO_PY.findall(linhas[j])]
            if not caminhos:
                add("http.server", m.group(2), "(qualquer caminho)", i + 1, ini, fim)
            for caminho_rota, j in caminhos:
                add("http.server", m.group(2), caminho_rota, j + 1, *bloco_python(linhas, j))

    # 5. Node sem framework: http.createServer
    if eh_js and re.search(r"\bcreateServer\s*\(", texto):
        achou = False
        for i, linha in enumerate(linhas):
            for caminho_rota in CAMINHO_JS.findall(linha):
                achou = True
                janela = linhas[max(0, i - 2):i + 1]
                for metodo in sorted({mt for l in janela for mt in METODO_JS.findall(l)}) or ["*"]:
                    add("http.createServer", metodo, caminho_rota, i + 1, *bloco_js(linhas, i, limite=60))
        if not achou:
            i = next(k for k, l in enumerate(linhas) if re.search(r"\bcreateServer\s*\(", l))
            add("http.createServer", "*", "(qualquer caminho)", i + 1, *bloco_js(linhas, i))

    return rotas


def rotulo(it):
    if it["auth"] == "indireta":
        return f"indireta (via {it['via']})"
    if it["auth"] == "alternativa":
        return f"alternativa: {it['detalhe']} ({it['via']})"
    return it["auth"]


def main():
    parser = parser_base("Inventário de pontos de entrada HTTP (base da matriz de acesso).")
    parser.add_argument("--auth-nomes", metavar="LISTA",
                        help="funções de autorização a procurar além do padrão, separadas por vírgula; "
                             "cada nome também casa como prefixo (nome_admin, nomeAdmin)")
    args = parser.parse_args()
    raiz = Path(args.raiz).resolve()
    escopo = resolver_escopo(raiz, args)
    extras = [n.strip() for n in args.auth_nomes.split(",")] if args.auth_nomes else []
    nomes = NomesDeAuth(NOMES_AUTH_PADRAO + extras, extras)
    projeto = ProjetoPy(raiz, nomes)
    analisador = AnalisadorTexto(raiz, nomes)

    rotas = []
    for arq in arquivos_no_escopo(raiz, escopo):
        if not eh_codigo(arq):
            continue
        r = rel(arq, raiz).replace("\\", "/")
        if eh_teste(r):
            continue
        texto = ler_texto(arq)
        if texto is not None:
            rotas.extend(analisar_arquivo(arq, r, texto, projeto, analisador))

    aviso = None if rotas else "0 rotas reconhecidas: inventário manual necessário"

    if args.json:
        print(json.dumps({"escopo": escopo.como_dict(), "auth_nomes": nomes.nomes,
                          "auth_prefixos": nomes.prefixos, "auth_sufixos": SUFIXOS_VARIANTE,
                          "aviso": aviso, "rotas": rotas}, ensure_ascii=False, indent=2))
        return

    print(f"# Inventário de rotas: {raiz.name} ({len(rotas)} pontos de entrada)")
    print(linha_de_escopo(escopo))
    if aviso:
        print(f"\n{aviso}.")
        print("Nenhum formato conhecido foi encontrado. Procure os pontos de entrada lendo o código")
        print("(servidor, handlers, funções serverless, filas, webhooks) e monte a matriz à mão.")
        return
    print("Coluna autorização: 'direta' = a rota chama a função; 'indireta' = chama por meio de uma função")
    print("do projeto (arquivo:linha da chamada real); 'alternativa' = segredo comparado, sem sessão;")
    print("'não encontrada' = nenhuma chamada. Texto em comentário, docstring ou string não conta.")
    print("É heurística: confirme lendo o código e testando sem sessão.\n")
    print("| Método | Rota | Framework | Onde | Autorização | Funções |")
    print("|---|---|---|---|---|---|")
    sensivel = re.compile(r"(?i)admin|debug|internal|seed|reset|backup|metrics|export|delete|users?\b|usuarios?|clientes?")
    ordem = {NAO_ENCONTRADA: 0, "alternativa": 1, "indireta": 2, "direta": 3}
    for it in sorted(rotas, key=lambda x: (ordem[x["auth"]], x["rota"], x["metodo"])):
        alerta = " (!)" if it["auth"] == NAO_ENCONTRADA and sensivel.search(it["rota"]) else ""
        onde = f"{it['arquivo']}:{it['linha']}" if it["linha"] else it["arquivo"]
        funcoes = ", ".join(it["funcoes_auth"]) or "-"
        print(f"| {it['metodo']} | `{it['rota']}`{alerta} | {it['framework']} | {onde} | {rotulo(it)} | {funcoes} |")
    com_obs = [it for it in rotas if it["obs"]]
    if com_obs:
        print("\nObservações:")
        for it in com_obs:
            print(f"- {it['metodo']} `{it['rota']}`: {it['obs']}.")
    print("\n(!) = rota com nome sensível e nenhuma autorização encontrada. Priorize na matriz de acesso.")
    print("'alternativa' não é sessão: confira de onde vem o segredo, se a comparação é em tempo constante")
    print("e o que a rota faz com quem passa. Lembre: `app.use(auth)` antes das rotas protege as seguintes.")
    print(f"Nomes procurados: {', '.join(nomes.nomes)}.")
    print(f"Variantes: prefixo {', '.join(nomes.prefixos)} e sufixo {', '.join(SUFIXOS_VARIANTE)} "
          "(acrescente nomes com --auth-nomes).")


if __name__ == "__main__":
    main()
