#!/usr/bin/env python3
"""Lista pontos quentes: trechos que merecem investigação, agrupados por risco.

Uso: python3 pontos_quentes.py [raiz] [--categoria NOME] [--max N] [--json]

Cada resultado é uma PISTA. Abra o arquivo, siga o dado e classifique.
Ausência de resultado NÃO é prova de segurança: os padrões são textuais.
Somente leitura. Não faz requisições de rede.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _comum import caminhar, cortar, eh_codigo, ler_texto, mascarar, rel  # noqa: E402

# (categoria, descrição, regex, filtro de arquivo opcional)
JS = r"\.(m?[jt]sx?|c[jt]s|vue|svelte|astro|html?|ejs|hbs)$"
PY = r"\.py$"
SQL = r"\.sql$"
DOCKER = r"(^|/)(Dockerfile|Containerfile)[^/]*$"
COMPOSE = r"(^|/)(docker-)?compose[^/]*\.ya?ml$"
GHA = r"(^|/)\.github/workflows/[^/]+\.ya?ml$"
RULES = r"(\.rules$|database\.rules\.json$)"
MCPCFG = r"(^|/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json)$"

PADROES = [
    # XSS
    ("xss", "HTML montado a partir de string", r"\.(innerHTML|outerHTML)\s*\+?=|insertAdjacentHTML\(|document\.write\(", JS),
    ("xss", "HTML bruto no framework", r"dangerouslySetInnerHTML|v-html|\{@html|bypassSecurityTrust\w+|\[innerHTML\]", JS),
    ("xss", "jQuery .html() com variável", r"\.html\(\s*[A-Za-z_$]", JS),
    ("xss", "Markdown renderizado (confira sanitização)", r"\bmarked(\.parse)?\(|markdownit\(|new\s+MarkdownIt|\.render\(\s*\w*(md|markdown)", JS),
    ("xss", "Template marcado como seguro", r"\|\s*safe\b|mark_safe\(|Markup\(|autoescape\s+false|\{\{\{", None),
    # SQL / NoSQL
    ("sql", "SQL em template string com interpolação", r"(?i)\b(select|insert\s+into|update|delete\s+from)\b[^\n]*\$\{", JS),
    ("sql", "SQL concatenado", r"(?i)['\"`]\s*(select|insert\s+into|update|delete\s+from)\b[^'\"`]*['\"`]\s*\+", None),
    ("sql", "Raw SQL sem parâmetros (Prisma unsafe)", r"\$(queryRawUnsafe|executeRawUnsafe)\(", JS),
    ("sql", "Raw SQL (confira bindings)", r"\b(knex|db|sequelize|connection|pool|client)\.(raw|query)\(\s*[`'\"]?[^)]*\$\{", JS),
    ("sql", "execute com f-string/format/% (Python)", r"\.(execute|executemany|raw)\(\s*(f['\"]|['\"][^'\"]*['\"]\s*(%|\.format))|text\(\s*f['\"]", PY),
    ("sql", "ORDER BY / identificador vindo da requisição", r"(?i)order\s+by\s*['\"`]?\s*\+?\s*\$?\{?\s*(req|request|params|query)\.", None),
    ("nosql", "Filtro Mongo vindo direto da requisição", r"\.(find|findOne|updateOne|deleteOne|updateMany|deleteMany)\(\s*req\.(body|query)|\$where", JS),
    # Execução de código / comando
    ("execucao", "Execução de comando ou código dinâmico",
     r"child_process|\bexecSync\(|\bexec\(\s*[`'\"]?[^)]*\$\{|spawn\([^)]*shell\s*:\s*true|\beval\(|new\s+Function\(|vm\.runIn\w*\(", JS),
    ("execucao", "Execução de comando ou desserialização insegura (Python)",
     r"os\.system\(|subprocess\.\w+\([^)]*shell\s*=\s*True|\beval\(|\bexec\(|pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)|marshal\.loads", PY),
    # Validação / atribuição em massa
    ("validacao", "Objeto da requisição gravado/espalhado direto",
     r"\.\.\.\s*req\.body|Object\.assign\([^)]*req\.body|\b(create|update|insert|upsert|save|insertOne|updateOne)\(\s*\{?\s*(data\s*:\s*)?req\.body\s*[},)]|new\s+\w+\(\s*req\.body\s*\)", JS),
    ("validacao", "Atribuição em massa (Python)", r"\*\*\s*request\.(data|json|POST|form)|\*\*\s*await\s+request\.json\(\)|\.objects\.create\(\s*\*\*", PY),
    # Autorização / IDOR
    ("autorizacao", "Busca/alteração por ID vindo da requisição (confira filtro de dono)",
     r"(findUnique|findFirst|findById|findByPk|findOne|update\w*|delete\w*|destroy|query|execute)\([^\n]*(req\.params\.\w+|req\.query\.\w*[iI]d\b|params\.\w*[iI]d\b)", JS),
    ("autorizacao", "Busca por ID vindo da URL (Python)", r"(get_object_or_404|\.get\(|filter\()[^)]*(pk|id)\s*=\s*(pk|id|\w+_id)\b", PY),
    ("autorizacao", "Dono/papel vindo do cliente", r"(ownerId|owner_id|userId|user_id|tenantId|tenant_id|role|isAdmin|is_admin)\s*[:=]\s*(req\.(body|query)|request\.(json|data|args|form))", None),
    # SSRF
    ("ssrf", "Requisição para URL variável",
     r"\b(fetch|axios(\.(get|post|put|request))?|got|ky|needle|superagent\.get|https?\.get|request)\(\s*(?![`'\"](https?:)?/)[A-Za-z_$`]", JS),
    ("ssrf", "Requisição para URL variável (Python)",
     r"\b(requests|httpx|aiohttp\.ClientSession\(\)|session|client)\.(get|post|put|request|head)\(\s*(?![fbr]?['\"]https?://)[A-Za-z_]|urlopen\(\s*[A-Za-z_]", PY),
    ("ssrf", "Navegador headless abrindo URL variável", r"\.goto\(\s*(?![`'\"]https?://)[A-Za-z_$`]", JS),
    # Senhas, tokens e criptografia
    ("senhas", "Hash rápido (md5/sha) — confira se é usado em senha",
     r"createHash\(\s*['\"](md5|sha1|sha256|sha512)['\"]|hashlib\.(md5|sha1|sha256|sha512)\(|\bmd5\(|\bsha1\(", None),
    ("senhas", "Aleatoriedade fraca para token/código", r"(?i)(token|secret|senha|password|otp|codigo|code|reset|nonce)[^\n]{0,60}Math\.random\(|Math\.random\(\)[^\n]{0,60}(token|otp|code|codigo)", JS),
    ("senhas", "bcrypt com custo baixo", r"(?i)(saltRounds|rounds|cost)\s*[:=]\s*[1-9]\b|bcrypt\.hash(Sync)?\([^,]+,\s*[1-9]\s*\)", None),
    ("sessao", "JWT sem verificação ou com verificação enfraquecida",
     r"jwt\.decode\(|algorithms\s*[:=]\s*\[?\s*['\"]none|ignoreExpiration\s*:\s*true|verify_signature['\"]?\s*:\s*False|verify\s*=\s*False", None),
    ("sessao", "Cookie sem proteção", r"httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*['\"]none|(SESSION|CSRF)_COOKIE_(SECURE|HTTPONLY)\s*=\s*False", None),
    # CORS / headers
    ("cors", "CORS aberto ou refletindo qualquer origem",
     r"origin\s*:\s*(['\"]\*['\"]|true)|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*", None),
    # Erros, debug e logs
    ("erros", "Erro interno devolvido ao cliente",
     r"res\.(send|json|status\([^)]*\)\.(send|json))\(\s*\{?[^)]*\b(err|error|e)\.(stack|message)|res\.(send|json)\(\s*(err|error|e)\s*\)|traceback\.format_exc\(\)", None),
    ("erros", "Modo debug ligado", r"DEBUG\s*=\s*True|\.run\([^)]*debug\s*=\s*True|FastAPI\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|debug\s*:\s*true", None),
    ("erros", "Log de corpo da requisição ou campo sensível",
     r"(console\.(log|info|debug|warn|error)|logger\.\w+|logging\.\w+|print)\([^)]*(req\.body|request\.(json|data|body)|password|senha|token|authorization|cookie)", None),
    # Rotas e redirecionamentos
    ("rotas", "Rota sensível (confira autenticação e papel)",
     r"['\"`]/(api/)?(admin|debug|internal|_debug|seed|reset|backup|metrics|swagger|api-docs|graphql|playground)\b", None),
    ("rotas", "Redirecionamento para destino vindo da requisição",
     r"(res\.redirect|redirect|RedirectResponse)\(\s*(req|request)\.(query|body|params|args|GET)", None),
    ("rotas", "Caminho de arquivo vindo da requisição (path traversal)",
     r"(sendFile|readFile|readFileSync|createReadStream|send_file|open|path\.join|path\.resolve)\([^)]*(req|request)\.(params|query|body|args|files)", None),
    # IA / LLM
    ("ia", "SDK de IA permitido no navegador (chave exposta)", r"dangerouslyAllowBrowser\s*:\s*true", JS),
    ("ia", "Conteúdo dinâmico no prompt de sistema", r"role\s*:\s*['\"]system['\"][^\n]*(\$\{|\+\s*\w)|(system|instructions)\s*[:=]\s*f['\"]", None),
    ("ia", "Definição de ferramenta para agente (confira autorização no handler)",
     r"\btools\s*:\s*\[|\btool\(\s*\{|server\.tool\(|registerTool\(|@(mcp\.)?tool\b|tool_choice|function_call", None),
    ("ia", "Chamada a LLM (confira max_tokens, cota e rate limit)",
     r"chat\.completions\.create|responses\.create|messages\.create|generateText\(|streamText\(|generateContent\(", None),
    ("mcp", "Configuração MCP com possível credencial", r"(?i)(token|key|secret|password|authorization)['\"]?\s*:\s*['\"][^'\"$]{8,}", MCPCFG),
    ("mcp", "Servidor MCP baixado na hora (confira se a versão está fixada nos args)",
     r"['\"]command['\"]\s*:\s*['\"](npx|uvx|bunx|pipx|pnpm\s+dlx)['\"]", MCPCFG),
    # Supabase / Firebase
    ("supabase", "Chave service_role / admin referenciada (só pode existir no servidor)",
     r"(?i)service_role|SERVICE_ROLE|sb_secret_|supabase\.auth\.admin", None),
    ("supabase", "user_metadata usado (o próprio usuário consegue alterar)", r"user_metadata|raw_user_meta_data", None),
    ("supabase", "RLS desligado ou concessão ampla", r"(?i)disable\s+row\s+level\s+security|grant\s+[^;]*\bto\s+(anon|public)\b|using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)", SQL),
    ("supabase", "Função SECURITY DEFINER (confira checagem de auth.uid() e search_path)", r"(?i)security\s+definer", SQL),
    ("firebase", "Regra aberta", r"if\s+true\s*;|['\"]\.(read|write)['\"]\s*:\s*(true|['\"]true['\"])|request\.time\s*<\s*timestamp\.date", RULES),
    ("firebase", "Regra que só exige login (qualquer conta acessa tudo)", r"allow\s+[\w,\s]+:\s*if\s+request\.auth\s*!=\s*null\s*;", RULES),
    ("firebase", "Credencial do Admin SDK", r"(?i)serviceAccount|firebase-adminsdk|private_key_id", None),
    # Docker / compose / CI
    ("docker", "Imagem base sem versão fixa", r"(?i)^\s*FROM\s+[\w./\-]+(:latest)?\s*(AS\s+\w+)?\s*$", DOCKER),
    ("docker", "Segredo em ENV/ARG ou .env copiado para a imagem",
     r"(?i)^\s*(ENV|ARG)\s+\w*(SECRET|PASSWORD|TOKEN|KEY|PASS)\w*|^\s*COPY\s+[^\n]*\.env", DOCKER),
    ("docker", "Porta de banco publicada em todas as interfaces",
     r"^\s*-\s*['\"]?(5432|3306|27017|6379|9200|5672|1433|11211)\s*:\s*\d+", COMPOSE),
    ("docker", "Container com privilégio elevado", r"privileged\s*:\s*true|/var/run/docker\.sock|network_mode\s*:\s*['\"]?host", COMPOSE),
    ("ci", "pull_request_target (perigoso com checkout do PR)", r"pull_request_target", GHA),
    ("ci", "Expressão controlada por terceiros em run: (injeção de script)",
     r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)[^}]*\.(title|body|message|name|ref|label|email)|head_ref)\s*\}\}", GHA),
    ("ci", "Permissões amplas do GITHUB_TOKEN", r"permissions\s*:\s*write-all|contents\s*:\s*write", GHA),
    ("ci", "Action sem SHA fixo", r"uses\s*:\s*(?!actions/|\./)[\w.\-]+/[\w.\-/]+@(?![0-9a-f]{40}\b)[\w.\-]+", GHA),
    # LGPD
    ("lgpd", "Dado pessoal em log", r"(console\.\w+|logger\.\w+|logging\.\w+|print)\([^)]*\b(cpf|rg|cnpj|telefone|celular|phone|endereco|address|nascimento|birth|email)\b", None),
    ("lgpd", "Dado pessoal enviado a analytics",
     r"(gtag|analytics\.(track|identify)|posthog\.(capture|identify)|mixpanel\.\w+|amplitude\.\w+)\([^)]*\b(cpf|email|telefone|phone|nome|name)\b", None),
    ("lgpd", "Dado pessoal em URL", r"[?&](cpf|rg|email|telefone|phone|token|senha|password)=", None),
    ("lgpd", "Monitoramento enviando dados pessoais por padrão", r"sendDefaultPii\s*:\s*true|send_default_pii\s*=\s*True", None),
]

COMPILADOS = [(c, d, re.compile(p), re.compile(f) if f else None) for c, d, p, f in PADROES]
SEGREDO_NA_LINHA = re.compile(r"(['\"])([A-Za-z0-9_\-./+=]{24,})\1")


def higienizar(trecho: str) -> str:
    """Mascara strings longas que podem ser segredos antes de exibir o trecho."""
    return SEGREDO_NA_LINHA.sub(lambda m: m.group(1) + mascarar(m.group(2)) + m.group(1), trecho)


def analisar_sql(textos):
    """Análise por instrução SQL em todas as migrations: RLS, políticas de UPDATE e views."""
    pistas = []
    criadas, com_rls = {}, set()
    for arquivo, texto in textos:
        sem_comentarios = re.sub(r"--[^\n]*", "", texto)
        for instrucao in sem_comentarios.split(";"):
            linha = texto.count("\n", 0, texto.find(instrucao.strip()[:40]) if instrucao.strip() else 0) + 1
            s = " ".join(instrucao.split()).lower()
            m = re.search(r"create table (if not exists )?(?:(\w+)\.)?\"?(\w+)\"?", s)
            if m and (m.group(2) in (None, "public")):
                criadas.setdefault(m.group(3), (arquivo, linha))
            m = re.search(r"alter table (only )?(?:(\w+)\.)?\"?(\w+)\"? enable row level security", s)
            if m:
                com_rls.add(m.group(3))
            if re.search(r"create policy .* for (update|all)\b", s):
                pistas.append({"arquivo": arquivo, "linha": linha,
                               "padrao": "Política de UPDATE: RLS não protege colunas; confira se o dono consegue "
                                         "alterar campos como role, plano ou créditos",
                               "trecho": s[:150]})
            if re.search(r"create (or replace )?view", s) and "security_invoker" not in s:
                pistas.append({"arquivo": arquivo, "linha": linha,
                               "padrao": "View sem security_invoker (pode ignorar o RLS das tabelas)",
                               "trecho": s[:150]})
    for tabela, (arquivo, linha) in sorted(criadas.items()):
        if tabela not in com_rls:
            pistas.append({"arquivo": arquivo, "linha": linha,
                           "padrao": f"Tabela public.{tabela} sem ENABLE ROW LEVEL SECURITY em nenhuma migration",
                           "trecho": ""})
    return pistas


def main():
    args = sys.argv[1:]
    como_json = "--json" in args
    filtro, maximo = None, 40
    if "--categoria" in args:
        filtro = args[args.index("--categoria") + 1]
    if "--max" in args:
        maximo = int(args[args.index("--max") + 1])
    posicionais = [a for i, a in enumerate(args) if not a.startswith("--")
                   and (i == 0 or args[i - 1] not in ("--categoria", "--max"))]
    raiz = Path(posicionais[0] if posicionais else ".").resolve()

    resultados = {}
    dockerfiles_sem_user = []
    textos_sql = []
    for arq in caminhar(raiz):
        if not eh_codigo(arq):
            continue
        r = rel(arq, raiz).replace("\\", "/")
        texto = ler_texto(arq)
        if texto is None:
            continue
        if re.search(DOCKER, r) and not re.search(r"(?im)^\s*USER\s+(?!root\b)\S+", texto):
            dockerfiles_sem_user.append(r)
        if r.endswith(".sql"):
            textos_sql.append((r, texto))
        linhas = texto.splitlines()
        for n, linha in enumerate(linhas, 1):
            if len(linha) > 2000:
                continue
            for cat, desc, rx, rx_arq in COMPILADOS:
                if filtro and cat != filtro:
                    continue
                if rx_arq and not rx_arq.search(r):
                    continue
                if rx.search(linha):
                    resultados.setdefault(cat, []).append(
                        {"arquivo": r, "linha": n, "padrao": desc, "trecho": higienizar(cortar(linha))})

    if dockerfiles_sem_user and (not filtro or filtro == "docker"):
        for d in dockerfiles_sem_user:
            resultados.setdefault("docker", []).append(
                {"arquivo": d, "linha": 0, "padrao": "Dockerfile sem USER: o processo roda como root", "trecho": ""})

    if textos_sql and (not filtro or filtro == "supabase"):
        for pista in analisar_sql(textos_sql):
            resultados.setdefault("supabase", []).append(pista)

    if como_json:
        print(json.dumps(resultados, ensure_ascii=False, indent=2))
        return

    total = sum(len(v) for v in resultados.values())
    print(f"# Pontos quentes: {raiz.name} ({total} pistas)")
    print("Pistas para investigar, não achados. Nenhum resultado não prova que está seguro.\n")
    if not resultados:
        print("Nenhum padrão encontrado. Siga a investigação manual por risco.")
    for cat in sorted(resultados):
        itens = resultados[cat]
        print(f"## {cat} ({len(itens)})")
        for it in itens[:maximo]:
            local = f"{it['arquivo']}:{it['linha']}" if it["linha"] else it["arquivo"]
            print(f"- {local} · {it['padrao']}" + (f"\n    {it['trecho']}" if it["trecho"] else ""))
        if len(itens) > maximo:
            print(f"- ... mais {len(itens) - maximo} (use --categoria {cat} --max N)")
        print()


if __name__ == "__main__":
    main()
