#!/usr/bin/env python3
"""Inventário de pontos de entrada HTTP, base para a matriz de acesso.

Uso: python3 inventario_rotas.py [raiz] [--json]

Reconhece Express/Fastify/Hono/Koa, NestJS, Next.js (app e pages), SvelteKit, Nuxt,
FastAPI, Flask, Django, Supabase Edge Functions e Firebase Functions.

A coluna "auth?" é heurística: indica se há sinal textual de autenticação
na linha ou no arquivo. Confirme sempre lendo o código e testando.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _comum import caminhar, eh_codigo, ler_texto, rel  # noqa: E402

SINAIS_AUTH = re.compile(
    r"(?i)\b(auth\w*|requireAuth|isAuthenticated|ensureAuth\w*|protect\w*|guard\w*|UseGuards|verifyToken|"
    r"verifyJwt|jwtRequired|login_required|permission_required|permission_classes|IsAuthenticated|"
    r"Depends\(\s*get_current\w*|current_user|requireAdmin|requireRole|hasRole|getServerSession|"
    r"currentUser|getUser\(|getSession\(|clerk|withAuth|session)\b"
)

EXPRESS = re.compile(r"\b(app|router|server|api|r|routes)\.(get|post|put|patch|delete|all|use|route)\(\s*['\"`]([^'\"`]+)['\"`]")
NEST_CTRL = re.compile(r"@Controller\(\s*['\"]?([^'\")]*)")
NEST_ROTA = re.compile(r"@(Get|Post|Put|Patch|Delete|All)\(\s*['\"]?([^'\")]*)")
FASTAPI = re.compile(r"@(\w+)\.(get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]+)")
FLASK = re.compile(r"@(\w+)\.route\(\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?")
DJANGO = re.compile(r"\b(re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)")
NEXT_METODOS = re.compile(r"export\s+(async\s+)?(function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
FIREBASE_FN = re.compile(r"export(s)?\.?\s*(const\s+)?(\w+)\s*=\s*(functions\.https\.(onRequest|onCall)|onRequest|onCall)\(")


def rota_por_arquivo(r: str):
    """Converte caminho de arquivo em rota para frameworks com roteamento por pastas."""
    m = re.search(r"(?:^|/)(?:src/)?app/(.*)/route\.(?:[jt]sx?|m[jt]s)$", r)
    if m:
        return "Next.js (app)", "/" + re.sub(r"\([^)]*\)/?", "", m.group(1)).strip("/")
    m = re.search(r"(?:^|/)(?:src/)?pages/(api/.*)\.(?:[jt]sx?)$", r)
    if m:
        return "Next.js (pages)", "/" + re.sub(r"/index$", "", m.group(1))
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


def main():
    como_json = "--json" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    raiz = Path(args[0] if args else ".").resolve()
    rotas = []

    def add(fw, metodo, caminho, arquivo, linha, auth_linha, auth_arquivo):
        rotas.append({"framework": fw, "metodo": metodo.upper(), "rota": caminho or "/",
                      "arquivo": arquivo, "linha": linha,
                      "auth": "linha" if auth_linha else ("arquivo" if auth_arquivo else "não")})

    for arq in caminhar(raiz):
        if not eh_codigo(arq):
            continue
        r = rel(arq, raiz).replace("\\", "/")
        if re.search(r"(^|/)(test|tests|__tests__|spec|e2e)/|\.(test|spec)\.", r):
            continue
        texto = ler_texto(arq)
        if texto is None:
            continue
        linhas = texto.splitlines()
        auth_arquivo = bool(SINAIS_AUTH.search(texto))
        server_action = "'use server'" in texto or '"use server"' in texto

        fw, rota = rota_por_arquivo(r)
        if fw:
            metodos = [m.group(3) for m in NEXT_METODOS.finditer(texto)] or (
                ["(handler)"] if "pages" in fw or "Edge" in fw or "Nitro" in fw else ["(actions)"])
            for met in metodos:
                add(fw, met, rota, r, 0, False, auth_arquivo)
        if server_action and not fw:
            for n, linha in enumerate(linhas, 1):
                m = re.search(r"export\s+(async\s+)?function\s+(\w+)", linha)
                if m:
                    add("Server Action", "ACTION", m.group(2), r, n, False, auth_arquivo)

        prefixo_nest = ""
        for n, linha in enumerate(linhas, 1):
            contexto = " ".join(linhas[max(0, n - 4):n])  # 3 linhas antes (decorators, middlewares)
            auth_l = bool(SINAIS_AUTH.search(linha)) or bool(SINAIS_AUTH.search(contexto))
            for m in (EXPRESS.finditer(linha) if not r.endswith(".py") else ()):
                add("Express-like", m.group(2), m.group(3), r, n, bool(SINAIS_AUTH.search(linha)), auth_arquivo)
            m = NEST_CTRL.search(linha)
            if m:
                prefixo_nest = "/" + m.group(1).strip("/") if m.group(1) else ""
            m = NEST_ROTA.search(linha)
            if m:
                sub = ("/" + m.group(2).strip("/")) if m.group(2) else ""
                add("NestJS", m.group(1), (prefixo_nest + sub) or "/", r, n, auth_l, auth_arquivo)
            if r.endswith(".py"):
                m = FASTAPI.search(linha)
                if m:
                    prox = " ".join(linhas[n:n + 4])
                    add("FastAPI", m.group(2), m.group(3), r, n, bool(SINAIS_AUTH.search(prox)), auth_arquivo)
                m = FLASK.search(linha)
                if m:
                    metodos = re.findall(r"['\"](\w+)['\"]", m.group(3) or "") or ["GET"]
                    for met in metodos:
                        add("Flask", met, m.group(2), r, n, auth_l, auth_arquivo)
                if r.endswith("urls.py"):
                    m = DJANGO.search(linha)
                    if m:
                        add("Django", "*", "/" + m.group(2), r, n, False, auth_arquivo)
            m = FIREBASE_FN.search(linha)
            if m:
                add("Firebase Function", m.group(5) or m.group(4), m.group(3), r, n, False, auth_arquivo)

    if como_json:
        print(json.dumps(rotas, ensure_ascii=False, indent=2))
        return

    print(f"# Inventário de rotas: {raiz.name} ({len(rotas)} pontos de entrada)")
    print("Coluna auth?: 'linha' = sinal de autenticação junto da rota; 'arquivo' = só em algum lugar do arquivo;")
    print("'não' = nenhum sinal textual. É heurística: confirme lendo o código e testando sem sessão.\n")
    if not rotas:
        print("Nenhuma rota reconhecida. Procure manualmente os pontos de entrada da stack.")
        return
    print("| Método | Rota | Framework | Onde | auth? |")
    print("|---|---|---|---|---|")
    sensivel = re.compile(r"(?i)admin|debug|internal|seed|reset|backup|metrics|export|delete|users?\b")
    ordem = {"não": 0, "arquivo": 1, "linha": 2}
    for it in sorted(rotas, key=lambda x: (ordem[x["auth"]], x["rota"])):
        alerta = " ⚠️" if it["auth"] != "linha" and sensivel.search(it["rota"]) else ""
        onde = f"{it['arquivo']}:{it['linha']}" if it["linha"] else it["arquivo"]
        print(f"| {it['metodo']} | `{it['rota']}`{alerta} | {it['framework']} | {onde} | {it['auth']} |")
    print("\n⚠️ = rota com nome sensível sem sinal de autenticação na própria rota. Priorize na matriz de acesso.")
    print("Lembre: `app.use(auth)` registrado antes das rotas protege as seguintes; confira a ordem no código.")


if __name__ == "__main__":
    main()
