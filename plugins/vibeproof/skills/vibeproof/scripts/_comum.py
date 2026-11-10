"""Funções compartilhadas pelos scripts da skill vibeproof.

Só biblioteca padrão. Nenhum script faz requisição de rede nem altera arquivos.
"""

import argparse
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

# Console do Windows costuma usar cp1252: força UTF-8 para acentos e emojis.
for _fluxo in (sys.stdout, sys.stderr):
    try:
        _fluxo.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# Sair em silêncio quando a saída é cortada (ex.: `| head`).
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

# Pastas que nunca têm código do projeto.
IGNORAR_SEMPRE = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".turbo", ".cache",
    "vendor", "target", ".gradle", ".idea", ".vscode", ".auditoria-seguranca",
    "bower_components", "Pods", ".dart_tool",
}

# Pastas de artefatos de build: ignoradas na análise de código,
# mas incluídas na busca de segredos (é ali que chaves vazam para o navegador).
PASTAS_BUILD = {
    "dist", "build", ".next", "out", ".nuxt", ".output", ".svelte-kit",
    ".vercel", ".netlify", "coverage", "public/build",
}

EXTENSOES_CODIGO = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue",
    ".svelte", ".astro", ".py", ".rb", ".php", ".go", ".java", ".kt", ".cs",
    ".rs", ".html", ".htm", ".ejs", ".hbs", ".njk", ".jinja", ".jinja2",
    ".sql", ".yml", ".yaml", ".toml", ".rules", ".sh", ".tf", ".graphql",
}

NOMES_CODIGO = {"Dockerfile", "Containerfile", "Procfile", "Makefile"}

TAMANHO_MAX = 1_500_000  # bytes; arquivos maiores são pulados


def eh_binario(caminho: Path) -> bool:
    try:
        with open(caminho, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def ler_texto(caminho: Path):
    try:
        if caminho.stat().st_size > TAMANHO_MAX or eh_binario(caminho):
            return None
        return caminho.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def caminhar(raiz: Path, incluir_build: bool = False):
    """Percorre a árvore devolvendo arquivos, pulando pastas irrelevantes."""
    raiz = raiz.resolve()
    for pasta, subpastas, arquivos in os.walk(raiz):
        rel_pasta = Path(pasta).relative_to(raiz)
        manter = []
        for s in subpastas:
            if s in IGNORAR_SEMPRE:
                continue
            if not incluir_build and (s in PASTAS_BUILD or str(rel_pasta / s) in PASTAS_BUILD):
                continue
            manter.append(s)
        subpastas[:] = sorted(manter)
        for nome in sorted(arquivos):
            yield Path(pasta) / nome


def eh_codigo(caminho: Path) -> bool:
    nome = caminho.name
    if nome.endswith((".min.js", ".min.css", ".map")):
        return False
    if nome in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock"}:
        return False
    if nome in NOMES_CODIGO or nome.startswith("Dockerfile") or nome.startswith("docker-compose"):
        return True
    return caminho.suffix.lower() in EXTENSOES_CODIGO or nome in {"firestore.rules", "storage.rules", "database.rules.json", ".mcp.json", "mcp.json", "claude_desktop_config.json"}


def rel(caminho: Path, raiz: Path) -> str:
    try:
        return str(caminho.resolve().relative_to(raiz.resolve()))
    except ValueError:
        return str(caminho)


def mascarar(valor: str) -> str:
    """Mostra no máximo 4 caracteres e o tamanho. Nunca o valor inteiro."""
    valor = valor.strip()
    if len(valor) <= 6:
        return f"***({len(valor)} chars)"
    return f"{valor[:4]}…({len(valor)} chars)"


def git(raiz: Path, *args, limite_bytes: int = 0):
    """Roda um comando git somente leitura. Devolve stdout ou None."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(raiz), *args],
            capture_output=True, timeout=120, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    saida = proc.stdout
    if limite_bytes and len(saida) > limite_bytes:
        saida = saida[:limite_bytes]
    return saida.decode("utf-8", errors="replace")


def eh_repo_git(raiz: Path) -> bool:
    return git(raiz, "rev-parse", "--is-inside-work-tree") is not None


def cortar(linha: str, n: int = 160) -> str:
    linha = linha.strip()
    return linha if len(linha) <= n else linha[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Argumentos e escopo (repositório inteiro, diff ou lista de arquivos)
# ---------------------------------------------------------------------------

def parser_base(descricao: str, escopo: bool = True) -> argparse.ArgumentParser:
    """Parser com os argumentos comuns a todos os scripts."""
    p = argparse.ArgumentParser(description=descricao)
    p.add_argument("raiz", nargs="?", default=".", help="pasta do projeto (padrão: diretório atual)")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    if escopo:
        g = p.add_mutually_exclusive_group()
        g.add_argument("--diff", metavar="BASE..HEAD",
                       help="analisa só os arquivos alterados no intervalo do Git (ex.: main..HEAD)")
        g.add_argument("--arquivos", metavar="LISTA",
                       help="analisa só estes arquivos (separados por vírgula, relativos à raiz)")
    return p


def normalizar_caminho(caminho: str) -> str:
    caminho = caminho.strip().replace("\\", "/")
    while caminho.startswith("./"):
        caminho = caminho[2:]
    return caminho


class Escopo:
    """Conjunto de arquivos analisados. arquivos=None significa o repositório inteiro."""

    def __init__(self, arquivos=None, descricao="repositório inteiro", intervalo=None):
        self.arquivos = arquivos
        self.descricao = descricao
        self.intervalo = intervalo

    @property
    def restrito(self) -> bool:
        return self.arquivos is not None

    def contem(self, caminho_relativo: str) -> bool:
        return self.arquivos is None or normalizar_caminho(caminho_relativo) in self.arquivos

    def como_dict(self) -> dict:
        return {"descricao": self.descricao, "intervalo": self.intervalo,
                "arquivos": sorted(self.arquivos) if self.restrito else None}


def sair_com_erro(mensagem: str, codigo: int = 2):
    print(f"ERRO: {mensagem}", file=sys.stderr)
    sys.exit(codigo)


def resolver_escopo(raiz: Path, args) -> Escopo:
    intervalo = getattr(args, "diff", None)
    if intervalo:
        saida = git(raiz, "diff", "--name-only", "--diff-filter=ACMRT", "--relative", intervalo, "--")
        if saida is None:
            sair_com_erro(f"não foi possível calcular o diff '{intervalo}'. Confira se a pasta é um "
                          "repositório Git e se as duas referências existem.")
        arquivos = {normalizar_caminho(l) for l in saida.splitlines() if l.strip()}
        return Escopo(arquivos, f"diff {intervalo}: {len(arquivos)} arquivo(s) alterado(s)", intervalo)
    lista = getattr(args, "arquivos", None)
    if lista:
        arquivos = {normalizar_caminho(a) for a in re.split(r"[,\n]", lista) if a.strip()}
        return Escopo(arquivos, f"lista informada: {len(arquivos)} arquivo(s)")
    return Escopo()


def arquivos_no_escopo(raiz: Path, escopo: Escopo, incluir_build: bool = False):
    """Arquivos a analisar: a árvore inteira ou só os do escopo."""
    raiz = raiz.resolve()
    if not escopo.restrito:
        yield from caminhar(raiz, incluir_build)
        return
    for r in sorted(escopo.arquivos):
        caminho = raiz / r
        if caminho.is_file() and not any(parte in IGNORAR_SEMPRE for parte in Path(r).parts):
            yield caminho


def linha_de_escopo(escopo: Escopo) -> str:
    texto = f"Escopo: {escopo.descricao}"
    if escopo.restrito:
        texto += ". Arquivos fora do escopo não foram analisados por este script."
    return texto
