#!/usr/bin/env python3
"""Reconhecimento: detecta stack, serviços e sinais de risco estruturais.

Uso: <python> detectar_stack.py [raiz] [--json] [--diff BASE..HEAD | --arquivos LISTA]

A stack é detectada sempre no repositório inteiro; --diff/--arquivos só informam o escopo.

Somente leitura. Não faz requisições de rede.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _comum import caminhar, eh_repo_git, git, ler_texto, parser_base, rel, resolver_escopo  # noqa: E402

# nome do pacote -> (categoria, rótulo)
PACOTES_JS = {
    "next": ("framework", "Next.js"), "react": ("frontend", "React"),
    "vue": ("frontend", "Vue"), "nuxt": ("framework", "Nuxt"),
    "svelte": ("frontend", "Svelte"), "@sveltejs/kit": ("framework", "SvelteKit"),
    "astro": ("framework", "Astro"), "vite": ("build", "Vite"),
    "react-scripts": ("build", "Create React App"), "expo": ("mobile", "Expo"),
    "react-native": ("mobile", "React Native"), "@angular/core": ("frontend", "Angular"),
    "express": ("backend", "Express"), "@nestjs/core": ("backend", "NestJS"),
    "fastify": ("backend", "Fastify"), "hono": ("backend", "Hono"), "koa": ("backend", "Koa"),
    "prisma": ("banco", "Prisma"), "@prisma/client": ("banco", "Prisma"),
    "drizzle-orm": ("banco", "Drizzle"), "typeorm": ("banco", "TypeORM"),
    "sequelize": ("banco", "Sequelize"), "knex": ("banco", "Knex"),
    "pg": ("banco", "PostgreSQL (pg)"), "mysql2": ("banco", "MySQL"),
    "mongoose": ("banco", "MongoDB (Mongoose)"), "mongodb": ("banco", "MongoDB"),
    "better-sqlite3": ("banco", "SQLite"),
    "@supabase/supabase-js": ("baas", "Supabase"), "@supabase/ssr": ("baas", "Supabase"),
    "firebase": ("baas", "Firebase (cliente)"), "firebase-admin": ("baas", "Firebase Admin"),
    "next-auth": ("auth", "NextAuth/Auth.js"), "@auth/core": ("auth", "Auth.js"),
    "@clerk/nextjs": ("auth", "Clerk"), "@clerk/clerk-react": ("auth", "Clerk"),
    "passport": ("auth", "Passport"), "jsonwebtoken": ("auth", "jsonwebtoken (JWT)"),
    "jose": ("auth", "jose (JWT)"), "better-auth": ("auth", "Better Auth"),
    "lucia": ("auth", "Lucia"), "express-session": ("auth", "express-session"),
    "bcrypt": ("senha", "bcrypt"), "bcryptjs": ("senha", "bcryptjs"),
    "argon2": ("senha", "argon2"), "@node-rs/argon2": ("senha", "argon2"),
    "zod": ("validacao", "Zod"), "valibot": ("validacao", "Valibot"), "joi": ("validacao", "Joi"),
    "yup": ("validacao", "Yup"), "class-validator": ("validacao", "class-validator"),
    "helmet": ("protecao", "helmet"), "express-rate-limit": ("protecao", "express-rate-limit"),
    "@nestjs/throttler": ("protecao", "@nestjs/throttler"), "@upstash/ratelimit": ("protecao", "Upstash Ratelimit"),
    "rate-limiter-flexible": ("protecao", "rate-limiter-flexible"), "cors": ("protecao", "cors"),
    "csurf": ("protecao", "csurf"), "dompurify": ("protecao", "DOMPurify"),
    "isomorphic-dompurify": ("protecao", "DOMPurify"), "sanitize-html": ("protecao", "sanitize-html"),
    "marked": ("render", "marked (Markdown)"), "markdown-it": ("render", "markdown-it"),
    "react-markdown": ("render", "react-markdown"),
    "openai": ("ia", "OpenAI SDK"), "@anthropic-ai/sdk": ("ia", "Anthropic SDK"),
    "ai": ("ia", "Vercel AI SDK"), "@ai-sdk/openai": ("ia", "Vercel AI SDK"),
    "langchain": ("ia", "LangChain"), "@langchain/core": ("ia", "LangChain"),
    "llamaindex": ("ia", "LlamaIndex"), "@google/generative-ai": ("ia", "Gemini SDK"),
    "@google/genai": ("ia", "Gemini SDK"), "@modelcontextprotocol/sdk": ("mcp", "MCP SDK"),
    "@pinecone-database/pinecone": ("ia", "Pinecone (vetores)"),
    "@sentry/node": ("monitoramento", "Sentry"), "@sentry/nextjs": ("monitoramento", "Sentry"),
    "@sentry/react": ("monitoramento", "Sentry"), "posthog-js": ("analytics", "PostHog"),
    "mixpanel-browser": ("analytics", "Mixpanel"), "stripe": ("pagamento", "Stripe"),
    "@marsidev/react-turnstile": ("captcha", "Turnstile"), "react-google-recaptcha": ("captcha", "reCAPTCHA"),
    "@hcaptcha/react-hcaptcha": ("captcha", "hCaptcha"), "multer": ("upload", "multer"),
    "axios": ("http", "axios"), "got": ("http", "got"), "puppeteer": ("http", "Puppeteer"),
    "playwright": ("http", "Playwright"),
    "vitest": ("teste", "Vitest"), "jest": ("teste", "Jest"), "supertest": ("teste", "Supertest"),
    "@playwright/test": ("teste", "Playwright Test"), "mocha": ("teste", "Mocha"),
    "@firebase/rules-unit-testing": ("teste", "Firebase rules-unit-testing"),
}

PACOTES_PY = {
    "django": ("backend", "Django"), "djangorestframework": ("backend", "Django REST Framework"),
    "flask": ("backend", "Flask"), "fastapi": ("backend", "FastAPI"), "starlette": ("backend", "Starlette"),
    "sqlalchemy": ("banco", "SQLAlchemy"), "psycopg": ("banco", "PostgreSQL (psycopg)"),
    "psycopg2": ("banco", "PostgreSQL (psycopg2)"), "psycopg2-binary": ("banco", "PostgreSQL (psycopg2)"),
    "pymongo": ("banco", "MongoDB"), "supabase": ("baas", "Supabase"),
    "firebase-admin": ("baas", "Firebase Admin"), "pyjwt": ("auth", "PyJWT"),
    "python-jose": ("auth", "python-jose"), "passlib": ("senha", "passlib"),
    "argon2-cffi": ("senha", "argon2"), "bcrypt": ("senha", "bcrypt"),
    "pydantic": ("validacao", "Pydantic"), "slowapi": ("protecao", "slowapi"),
    "django-ratelimit": ("protecao", "django-ratelimit"), "flask-limiter": ("protecao", "Flask-Limiter"),
    "bleach": ("protecao", "bleach"), "requests": ("http", "requests"), "httpx": ("http", "httpx"),
    "openai": ("ia", "OpenAI SDK"), "anthropic": ("ia", "Anthropic SDK"),
    "langchain": ("ia", "LangChain"), "langchain-core": ("ia", "LangChain"),
    "llama-index": ("ia", "LlamaIndex"), "google-genai": ("ia", "Gemini SDK"),
    "google-adk": ("ia", "Google ADK"), "mcp": ("mcp", "MCP SDK"), "fastmcp": ("mcp", "FastMCP"),
    "sentry-sdk": ("monitoramento", "Sentry"), "pytest": ("teste", "pytest"),
}

ARQUIVOS_SINAL = [
    (r"(^|/)supabase/config\.toml$", "baas", "Supabase (projeto local)"),
    (r"(^|/)supabase/migrations/.+\.sql$", "baas", "Supabase (migrations)"),
    (r"(^|/)supabase/functions/[^/]+/index\.(ts|js)$", "baas", "Supabase Edge Functions"),
    (r"(^|/)firebase\.json$", "baas", "Firebase (projeto)"),
    (r"(^|/)firestore\.rules$", "baas", "Firestore rules"),
    (r"(^|/)storage\.rules$", "baas", "Firebase Storage rules"),
    (r"(^|/)database\.rules\.json$", "baas", "Realtime Database rules"),
    (r"(^|/)(Dockerfile|Containerfile)[^/]*$", "infra", "Dockerfile"),
    (r"(^|/)(docker-)?compose[^/]*\.ya?ml$", "infra", "docker-compose"),
    (r"(^|/)\.github/workflows/[^/]+\.ya?ml$", "ci", "GitHub Actions"),
    (r"(^|/)\.gitlab-ci\.yml$", "ci", "GitLab CI"),
    (r"(^|/)bitbucket-pipelines\.yml$", "ci", "Bitbucket Pipelines"),
    (r"(^|/)vercel\.json$", "hospedagem", "Vercel"),
    (r"(^|/)netlify\.toml$", "hospedagem", "Netlify"),
    (r"(^|/)(fly\.toml|render\.yaml|railway\.json)$", "hospedagem", "PaaS (Fly/Render/Railway)"),
    (r"(^|/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json)$", "mcp", "Configuração de cliente MCP"),
    (r"(^|/)prisma/schema\.prisma$", "banco", "Prisma schema"),
    (r"(^|/)\.github/dependabot\.ya?ml$", "manutencao", "Dependabot"),
    (r"(^|/)renovate\.json5?$", "manutencao", "Renovate"),
    (r"(^|/)\.dockerignore$", "infra", ".dockerignore"),
    (r"(^|/)cloudbuild\.ya?ml$", "nuvem", "Google Cloud Build"),
    (r"(^|/)[^/]+\.tf$", "nuvem", "Terraform"),
    (r"(^|/)serverless\.ya?ml$", "nuvem", "Serverless Framework"),
    (r"(^|/)cdk\.json$", "nuvem", "AWS CDK"),
    (r"(^|/)(Pulumi\.ya?ml)$", "nuvem", "Pulumi"),
]

# Sinais de nuvem pelo conteúdo: (padrão do arquivo, padrão do conteúdo, rótulo)
SINAIS_NUVEM_CONTEUDO = [
    (r"(^|/)app\.ya?ml$", r"(?m)^\s*runtime\s*:", "Google App Engine"),
    (r"(^|/)template\.ya?ml$", r"AWSTemplateFormatVersion|AWS::Serverless", "AWS SAM / CloudFormation"),
    (r"(\.ya?ml|\.sh|Makefile|package\.json|\.toml|Dockerfile[^/]*|\.md)$",
     r"gcloud\s+run\s+(deploy|services)|google-github-actions/deploy-cloudrun|\brun\.app\b", "Google Cloud Run"),
    (r"(\.ya?ml|\.sh|Makefile|package\.json|\.toml)$",
     r"gcloud\s+functions\s+deploy|google-github-actions/deploy-cloud-functions", "Google Cloud Functions"),
    (r"(\.ya?ml|\.sh|Makefile|package\.json|\.toml)$",
     r"google-github-actions/auth|gcloud\s+(auth|config|builds|scheduler|secrets)\b", "Google Cloud (gcloud)"),
    (r"(\.ya?ml|\.sh|Makefile|package\.json|\.toml)$",
     r"aws-actions/configure-aws-credentials|\baws\s+(lambda|ecs|s3|cloudformation|deploy)\b", "AWS"),
    (r"(\.ya?ml|\.sh|Makefile|package\.json|\.toml)$",
     r"azure/(login|webapps-deploy|functions-action)|\baz\s+(webapp|functionapp|containerapp)\b", "Azure"),
]

LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
             "poetry.lock", "uv.lock", "Pipfile.lock", "Gemfile.lock", "composer.lock", "go.sum", "Cargo.lock"}

LINGUAGENS = {".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
              ".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python", ".rb": "Ruby", ".php": "PHP",
              ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".rs": "Rust", ".vue": "Vue",
              ".svelte": "Svelte", ".sql": "SQL", ".dart": "Dart", ".swift": "Swift"}

ENV_SEGUROS = (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults")


def ler_deps_package_json(caminho: Path):
    try:
        dados = json.loads(caminho.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set(), {}
    deps = set()
    for chave in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps.update((dados.get(chave) or {}).keys())
    return deps, dados.get("scripts") or {}


def ler_deps_python(caminho: Path):
    texto = ler_texto(caminho) or ""
    nomes = set()
    for m in re.finditer(r"(?im)^\s*['\"]?([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([<>=!~;\s'\",]|$)", texto):
        nomes.add(m.group(1).lower().replace("_", "-"))
    return nomes


def main():
    parser = parser_base("Reconhecimento: detecta stack, serviços, nuvem e sinais estruturais.")
    args = parser.parse_args()
    raiz = Path(args.raiz).resolve()
    como_json = args.json
    # A stack é contexto: é detectada sempre no repositório inteiro, mesmo com --diff/--arquivos.
    # O escopo só é informado aqui e restringe os outros scripts.
    escopo = resolver_escopo(raiz, args)

    achados = {}  # categoria -> set(rótulos)
    onde = {}     # rótulo -> primeiro arquivo
    linguagens = Counter()
    lockfiles, envs, pkg_jsons = [], [], []
    scripts_install = []
    total = 0

    def marcar(cat, rotulo, arquivo):
        achados.setdefault(cat, set()).add(rotulo)
        onde.setdefault(rotulo, arquivo)

    arquivos = list(caminhar(raiz))
    for arq in arquivos:
        total += 1
        r = rel(arq, raiz).replace("\\", "/")
        nome = arq.name
        if arq.suffix.lower() in LINGUAGENS:
            linguagens[LINGUAGENS[arq.suffix.lower()]] += 1
        if nome in LOCKFILES:
            lockfiles.append(r)
        if nome.startswith(".env"):
            envs.append(r)
        for padrao, cat, rotulo in ARQUIVOS_SINAL:
            if re.search(padrao, r):
                marcar(cat, rotulo, r)
        for padrao_arq, padrao_txt, rotulo in SINAIS_NUVEM_CONTEUDO:
            if re.search(padrao_arq, r) and re.search(padrao_txt, ler_texto(arq) or ""):
                marcar("nuvem", rotulo, r)
        if nome == "package.json":
            pkg_jsons.append(r)
            deps, scripts = ler_deps_package_json(arq)
            for d in deps:
                if d in PACOTES_JS:
                    marcar(*PACOTES_JS[d], r)
            for gancho in ("preinstall", "install", "postinstall"):
                if gancho in scripts:
                    scripts_install.append(f"{r}: {gancho}")
        elif nome in ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile") or (
                nome.startswith("requirements") and nome.endswith(".txt")):
            for d in ler_deps_python(arq):
                if d in PACOTES_PY:
                    marcar(*PACOTES_PY[d], r)
        elif nome == "go.mod":
            marcar("linguagem", "Go modules", r)

    # Sinais de atenção imediata
    alertas = []
    eh_git = eh_repo_git(raiz)
    rastreados = set()
    if eh_git:
        saida = git(raiz, "ls-files") or ""
        rastreados = set(saida.splitlines())
        for e in envs:
            if e in rastreados and not e.endswith(ENV_SEGUROS):
                alertas.append(f"Arquivo {e} está versionado no Git. Verifique segredos e o histórico.")
    else:
        alertas.append("A pasta não é um repositório Git: histórico e arquivos versionados não serão verificados.")

    gitignore = raiz / ".gitignore"
    if envs and (not gitignore.exists() or ".env" not in (ler_texto(gitignore) or "")):
        alertas.append("Há arquivos .env, mas o .gitignore da raiz não menciona .env.")
    if (pkg_jsons or achados.get("backend")) and not lockfiles:
        alertas.append("Nenhum lockfile encontrado: instalações podem trazer versões diferentes.")
    if scripts_install:
        alertas.append("package.json com scripts de instalação: " + "; ".join(scripts_install[:5]))
    if "Dockerfile" in achados.get("infra", set()) and ".dockerignore" not in achados.get("infra", set()):
        alertas.append("Há Dockerfile, mas não há .dockerignore: .env e .git podem entrar na imagem.")
    tem_backend = bool(achados.get("backend")) or "Next.js" in achados.get("framework", set())
    if tem_backend and not achados.get("protecao", set()) & {
            "express-rate-limit", "@nestjs/throttler", "Upstash Ratelimit", "rate-limiter-flexible",
            "slowapi", "django-ratelimit", "Flask-Limiter"}:
        alertas.append("Nenhuma biblioteca de rate limit detectada (pode estar na borda ou no provedor; verificar).")
    if tem_backend and not achados.get("validacao"):
        alertas.append("Nenhuma biblioteca de validação de entrada detectada.")
    if not achados.get("teste"):
        alertas.append("Nenhum framework de testes detectado: provas e testes de regressão vão exigir configuração.")
    if "Firebase (projeto)" in achados.get("baas", set()) and "Firestore rules" not in achados.get("baas", set()):
        alertas.append("Projeto Firebase sem firestore.rules no repositório: as regras podem estar só no console.")

    # Referências recomendadas
    refs = ["references/metodo-de-evidencia.md", "references/riscos-base.md",
            "references/supply-chain-ci-docker.md (dependências)"]
    if achados.get("ia") or achados.get("mcp"):
        refs.append("references/ia-agentes-mcp.md")
    if any(x.startswith(("Supabase", "Firebase", "Firestore", "Realtime")) for x in achados.get("baas", set())):
        refs.append("references/supabase-firebase.md")
    if achados.get("ci") or achados.get("infra"):
        refs[2] = "references/supply-chain-ci-docker.md (dependências, CI e Docker)"
    if achados.get("nuvem"):
        refs.append("references/nuvem.md (checklist de configuração; a pessoa roda os comandos e cola a saída)")
    refs.append("references/lgpd.md")

    resultado = {
        "raiz": str(raiz),
        "arquivos_analisados": total,
        "repositorio_git": eh_git,
        "commit": (git(raiz, "rev-parse", "--short", "HEAD") or "").strip() or None,
        "linguagens": dict(linguagens.most_common(8)),
        "detectado": {k: sorted(v) for k, v in sorted(achados.items())},
        "lockfiles": lockfiles,
        "arquivos_env": envs,
        "alertas": alertas,
        "referencias_recomendadas": refs,
        "escopo": escopo.como_dict(),
    }

    if como_json:
        print(json.dumps(resultado, ensure_ascii=False, indent=2))
        return

    print(f"# Reconhecimento: {raiz.name}")
    print(f"Arquivos analisados: {total} · Git: {'sim' if eh_git else 'não'}"
          + (f" · commit {resultado['commit']}" if resultado["commit"] else ""))
    if linguagens:
        print("Linguagens: " + ", ".join(f"{k} ({v})" for k, v in linguagens.most_common(8)))
    if escopo.restrito:
        print(f"Escopo da auditoria: {escopo.descricao} (a stack abaixo considera o repositório inteiro)")
    print("\n## Detectado")
    if not achados:
        print("(nada reconhecido; analise manualmente)")
    for cat, rotulos in sorted(achados.items()):
        itens = ", ".join(f"{x} [{onde[x]}]" for x in sorted(rotulos))
        print(f"- {cat}: {itens}")
    print("\n## Lockfiles: " + (", ".join(lockfiles) if lockfiles else "nenhum"))
    print("## Arquivos .env: " + (", ".join(envs) if envs else "nenhum"))
    print("\n## Atenção imediata (pistas, não achados)")
    for a in alertas or ["nenhum sinal estrutural"]:
        print(f"- {a}")
    print("\n## Referências recomendadas")
    for r in refs:
        print(f"- {r}")


if __name__ == "__main__":
    main()
