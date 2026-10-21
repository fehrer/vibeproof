#!/usr/bin/env python3
"""Procura segredos expostos. Valores aparecem SEMPRE mascarados.

Uso: python3 buscar_segredos.py [raiz] [--historico] [--limite-mb N] [--json]

  --historico    também examina o histórico do Git (linhas adicionadas em todos os commits)
  --limite-mb N  teto de leitura do histórico, em MB (padrão 50)

Inclui pastas de build (dist, .next, build...), onde chaves vazam para o navegador.
Somente leitura. Não faz requisições de rede. O resultado é uma lista de PISTAS.
"""

import base64
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _comum import (PASTAS_BUILD, caminhar, eh_repo_git, git, ler_texto,  # noqa: E402
                    mascarar, rel)

# (tipo, regex com grupo 'v' para o valor, gravidade sugerida)
PADROES = [
    ("Chave privada (PEM)", r"(?P<v>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)", "crítica"),
    ("AWS access key", r"\b(?P<v>(?:AKIA|ASIA)[0-9A-Z]{16})\b", "crítica"),
    ("GitHub token", r"\b(?P<v>(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}))", "crítica"),
    ("Stripe secret key", r"\b(?P<v>(?:sk|rk)_live_[A-Za-z0-9]{16,})", "crítica"),
    ("Anthropic API key", r"\b(?P<v>sk-ant-[A-Za-z0-9_\-]{20,})", "crítica"),
    ("OpenAI API key", r"\b(?P<v>sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,})", "crítica"),
    ("Supabase secret key", r"\b(?P<v>sb_secret_[A-Za-z0-9_\-]{16,})", "crítica"),
    ("Slack token", r"\b(?P<v>xox[abprs]-[A-Za-z0-9-]{10,})", "alta"),
    ("Google API key", r"\b(?P<v>AIza[0-9A-Za-z_\-]{35})\b", "verificar"),
    ("Conexão de banco com senha", r"(?P<v>\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:\s/'\"]+:[^@\s'\"]+@[^\s'\"]+)", "alta"),
    ("JWT embutido", r"\b(?P<v>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})", "verificar"),
]

# Atribuição genérica: NOME_SENSIVEL = "valor"
_NOMES = (r"\b(?P<k>[A-Z0-9_.\-]*(?:SECRET|PASSWORD|PASSWD|SENHA|TOKEN|API[_\-]?KEY|PRIVATE[_\-]?KEY|"
          r"ACCESS[_\-]?KEY|CLIENT[_\-]?SECRET|SERVICE[_\-]?ROLE|DATABASE[_\-]?URL|CONNECTION[_\-]?STRING)"
          r"[A-Z0-9_.\-]*)")
# Em código: só valores entre aspas (evita "password = req.body.password").
GENERICO_ASPAS = re.compile(_NOMES + r"['\"]?\s*[:=]\s*['\"](?P<v>[^'\"\s]{8,})['\"]", re.IGNORECASE)
# Em arquivos de configuração (.env, YAML, TOML, INI): valor sem aspas também conta.
GENERICO_CONFIG = re.compile(r"^\s*(?:export\s+|-\s*|ENV\s+|ARG\s+)?" + _NOMES + r"\s*[:=]\s*['\"]?(?P<v>[^'\"\s#]{8,})",
                             re.IGNORECASE)
EXT_CONFIG = (".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env")

PREFIXOS_PUBLICOS = re.compile(
    r"\b(?P<k>(?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)[A-Z0-9_]*"
    r"(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|TOKEN|API_KEY|APIKEY|KEY))\b"
)
PUBLICOS_POR_DESIGN = ("ANON", "PUBLISHABLE", "FIREBASE", "PUBLIC_KEY", "SITE_KEY", "SITEKEY",
                       "STRIPE_PK", "STRIPE_PUBLISHABLE", "MAPS", "MEASUREMENT", "POSTHOG", "SENTRY_DSN")

PLACEHOLDERS = re.compile(
    r"(?i)(your[_\-]|seu[_\-]|sua[_\-]|example|exemplo|placeholder|dummy|xxx+|\*\*\*|<|\$\{|\$\(|"
    r"process\.env|import\.meta\.env|os\.environ|getenv|env\(|\{\{|secrets\.|vars\.|^\$[A-Z_]+$)"
)

ARQUIVOS_SENSIVEIS = re.compile(
    r"(?i)(^|/)(\.env(\.[\w.-]+)?|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_rsa|id_ed25519|credentials\.json|"
    r".*service[-_]?account.*\.json|.*firebase-adminsdk.*\.json|\.npmrc|\.pypirc|\.netrc|htpasswd)$"
)
ENV_SEGUROS = re.compile(r"(?i)\.env\.(example|sample|template|dist|defaults)$")


def decodificar_jwt(token: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, IndexError):
        return None


def classificar_jwt(token: str):
    dados = decodificar_jwt(token)
    if not isinstance(dados, dict):
        return "JWT embutido", "verificar", "Token JWT no código; confirme se é de teste."
    papel = dados.get("role")
    if papel == "service_role":
        return "Supabase service_role", "crítica", "Ignora o RLS. Nunca pode estar no frontend nem no repositório."
    if papel == "anon":
        return "Supabase anon key", "info", "Pública por design; só é aceitável se o RLS estiver correto."
    return "JWT embutido", "verificar", f"Claims: {sorted(dados.keys())[:6]}"


def examinar_linha(linha: str, config: bool = False):
    """Devolve lista de (tipo, gravidade, valor_mascarado, dica)."""
    resultados = []
    vistos = set()
    for tipo, padrao, grav in PADROES:
        for m in re.finditer(padrao, linha):
            v = m.group("v")
            if v in vistos:
                continue
            vistos.add(v)
            dica = ""
            if tipo == "JWT embutido":
                tipo, grav, dica = classificar_jwt(v)
            elif tipo == "Google API key":
                dica = "Pode ser a apiKey pública do Firebase; se for, restrinja a chave no Google Cloud."
            elif tipo == "Conexão de banco com senha" and PLACEHOLDERS.search(v):
                continue
            resultados.append((tipo, grav, mascarar(v), dica))
    m = GENERICO_ASPAS.search(linha) or (GENERICO_CONFIG.search(linha) if config else None)
    if m and not PLACEHOLDERS.search(m.group("v")) and not any(m.group("v") in v or v in m.group("v") for v in vistos):
        resultados.append((f"Atribuição sensível ({m.group('k')})", "verificar", mascarar(m.group("v")),
                           "Confirme se é segredo real; valor fixo no código é problema mesmo se for fraco."))
    for m in PREFIXOS_PUBLICOS.finditer(linha):
        nome = m.group("k")
        if any(p in nome for p in PUBLICOS_POR_DESIGN):
            resultados.append((f"Variável pública {nome}", "info", "-",
                               "Público por design; verifique o controle real (RLS, regras, restrições)."))
        else:
            resultados.append((f"Variável pública {nome}", "alta", "-",
                               "Prefixo público: o valor vai para o bundle do navegador."))
    return resultados


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    historico = "--historico" in sys.argv
    como_json = "--json" in sys.argv
    limite_mb = 50
    if "--limite-mb" in sys.argv:
        try:
            limite_mb = int(sys.argv[sys.argv.index("--limite-mb") + 1])
            args = [a for a in args if a != str(limite_mb)]
        except (IndexError, ValueError):
            pass
    raiz = Path(args[0] if args else ".").resolve()

    achados, source_maps = [], []
    for arq in caminhar(raiz, incluir_build=True):
        r = rel(arq, raiz).replace("\\", "/")
        if arq.name.endswith(".map"):
            if any(r.startswith(p + "/") or f"/{p}/" in r for p in PASTAS_BUILD):
                source_maps.append(r)
            continue
        if arq.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock"}:
            continue
        texto = ler_texto(arq)
        if texto is None:
            continue
        no_build = any(r.startswith(p + "/") or f"/{p}/" in r for p in PASTAS_BUILD)
        config = (arq.name.startswith((".env", "Dockerfile", "Containerfile"))
                  or arq.name.lower().endswith(EXT_CONFIG))
        for n, linha in enumerate(texto.splitlines(), 1):
            if len(linha) > 5000:  # bundles minificados: examina em pedaços
                pedacos = [linha[i:i + 2000] for i in range(0, len(linha), 2000)]
            else:
                pedacos = [linha]
            for pedaco in pedacos:
                for tipo, grav, valor, dica in examinar_linha(pedaco, config):
                    if no_build:
                        dica = ("ARTEFATO DE BUILD: se este arquivo é servido ao navegador, o valor é público. "
                                + dica).strip()
                    achados.append({"arquivo": r, "linha": n, "tipo": tipo, "gravidade": grav,
                                    "valor": valor, "dica": dica})

    versionados, historico_arquivos, historico_achados = [], [], []
    eh_git = eh_repo_git(raiz)
    if eh_git:
        for f in (git(raiz, "ls-files") or "").splitlines():
            if ARQUIVOS_SENSIVEIS.search(f) and not ENV_SEGUROS.search(f):
                versionados.append(f)
        if historico:
            saida = git(raiz, "log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:@@%h") or ""
            commit = None
            for linha in saida.splitlines():
                if linha.startswith("@@"):
                    commit = linha[2:]
                elif linha and ARQUIVOS_SENSIVEIS.search(linha) and not ENV_SEGUROS.search(linha):
                    historico_arquivos.append({"commit": commit, "arquivo": linha})
            log = git(raiz, "log", "--all", "-p", "-U0", "--no-color", "--pretty=format:@@%h",
                      limite_bytes=limite_mb * 1_000_000) or ""
            commit, arquivo = None, None
            for linha in log.splitlines():
                if linha.startswith("@@") and not linha.startswith("@@ "):
                    commit = linha[2:]
                elif linha.startswith("+++ b/"):
                    arquivo = linha[6:]
                elif linha.startswith("+") and not linha.startswith("+++"):
                    cfg = bool(arquivo) and (Path(arquivo).name.startswith(".env")
                                             or arquivo.lower().endswith(EXT_CONFIG))
                    for tipo, grav, valor, dica in examinar_linha(linha[1:], cfg):
                        if grav in ("info",):
                            continue
                        historico_achados.append({"commit": commit, "arquivo": arquivo, "tipo": tipo,
                                                  "gravidade": grav, "valor": valor})

    resultado = {
        "achados": achados, "arquivos_sensiveis_versionados": versionados,
        "source_maps_em_build": source_maps, "historico_arquivos": historico_arquivos,
        "historico_achados": historico_achados, "git": eh_git, "historico_verificado": historico,
    }
    if como_json:
        print(json.dumps(resultado, ensure_ascii=False, indent=2))
        return

    ordem = {"crítica": 0, "alta": 1, "verificar": 2, "info": 3}
    print(f"# Busca de segredos: {raiz.name}")
    print("Pistas, não achados. Valores mascarados. Confirme cada item abrindo o arquivo.\n")
    print(f"## No código e em artefatos ({len(achados)})")
    for a in sorted(achados, key=lambda x: (ordem.get(x["gravidade"], 9), x["arquivo"], x["linha"]))[:200]:
        print(f"- [{a['gravidade']}] {a['arquivo']}:{a['linha']} · {a['tipo']} · {a['valor']}"
              + (f" · {a['dica']}" if a["dica"] else ""))
    if len(achados) > 200:
        print(f"- ... mais {len(achados) - 200} (use --json para ver todos)")
    print(f"\n## Arquivos sensíveis versionados no Git ({len(versionados)})")
    for f in versionados:
        print(f"- {f}")
    if not eh_git:
        print("- (a pasta não é um repositório Git)")
    print(f"\n## Source maps em pastas de build ({len(source_maps)})")
    for f in source_maps[:30]:
        print(f"- {f}")
    if historico:
        print(f"\n## Histórico do Git: arquivos sensíveis já adicionados ({len(historico_arquivos)})")
        for h in historico_arquivos[:50]:
            print(f"- {h['commit']} · {h['arquivo']}")
        print(f"\n## Histórico do Git: segredos em linhas adicionadas ({len(historico_achados)})")
        for h in historico_achados[:100]:
            print(f"- [{h['gravidade']}] {h['commit']} · {h['arquivo']} · {h['tipo']} · {h['valor']}")
        print("\nSegredo que já esteve no histórico deve ser revogado, mesmo que tenha sido apagado depois.")
    else:
        print("\n(Histórico do Git não verificado. Rode com --historico.)")


if __name__ == "__main__":
    main()
