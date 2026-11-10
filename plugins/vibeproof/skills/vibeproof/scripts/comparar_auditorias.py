#!/usr/bin/env python3
"""Compara auditorias da vibeproof ao longo do tempo.

Uso:
  <python> comparar_auditorias.py [pasta]                    compara o achados-*.json mais recente
                                                             com os anteriores (padrão: .auditoria-seguranca)
  <python> comparar_auditorias.py --atual A.json --anterior B.json [--antigos C.json ...]
  <python> comparar_auditorias.py --id "RISCO" "ARQUIVO" "TRECHO"   imprime o id estável de um achado
  Acrescente --json para saída em JSON.

O id de um achado é um hash do risco, do arquivo e do trecho normalizado (sem número de linha),
para continuar o mesmo quando o código anda de lugar. O script recalcula o id a partir desses
campos e avisa se o id gravado no JSON estiver diferente.

Classificação:
  corrigidos     estavam ativos na auditoria anterior e sumiram (ou viraram Descartado/Coberto),
                 com o arquivo dentro do escopo atual
  novos          ativos agora e nunca vistos antes
  regressoes     ativos agora, mas já tinham sido corrigidos (sumiram ou foram resolvidos) antes
  inalterados    ativos antes e agora (mudanças de status e severidade são indicadas)
  nao_reavaliados estavam ativos antes, mas o arquivo ficou fora do escopo desta auditoria (ex.: modo diff)

Ativos: Confirmado, Suspeita e Não verificado. Resolvidos: Descartado e Coberto.
Somente leitura. Não faz requisições de rede.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _comum  # noqa: E402,F401  (saída em UTF-8 e SIGPIPE)

ATIVOS = {"confirmado", "suspeita", "não verificado", "nao verificado"}
RESOLVIDOS = {"descartado", "coberto"}


def _normalizar(texto: str) -> str:
    texto = re.sub(r"\s+", " ", (texto or "").strip().lower())
    return texto.rstrip(";, ")


def id_estavel(risco: str, arquivo: str, trecho: str) -> str:
    arquivo = _comum.normalizar_caminho(arquivo or "").lower()
    base = f"{_normalizar(risco)}|{arquivo}|{_normalizar(trecho)}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]


def carregar(caminho: Path):
    dados = json.loads(caminho.read_text(encoding="utf-8"))
    avisos, achados = [], {}
    for a in dados.get("achados", []):
        calculado = id_estavel(a.get("risco", ""), a.get("arquivo", ""), a.get("trecho", ""))
        if a.get("id") and a["id"] != calculado:
            avisos.append(f"{caminho.name}: id {a['id']} não confere com o recalculado {calculado} "
                          f"({a.get('risco')} em {a.get('arquivo')}); usando o recalculado.")
        a = {**a, "id": calculado}
        achados[calculado] = a
    escopo = (dados.get("escopo") or {}).get("arquivos")
    return {"arquivo": caminho.name, "data": dados.get("data"), "commit": dados.get("commit"),
            "nivel": dados.get("nivel"), "escopo": set(escopo) if escopo is not None else None,
            "achados": achados}, avisos


def ativo(achado) -> bool:
    return bool(achado) and str(achado.get("status", "")).strip().lower() in ATIVOS


def no_escopo(auditoria, arquivo) -> bool:
    return auditoria["escopo"] is None or arquivo in auditoria["escopo"]


def comparar(atual, anterior, antigos=()):
    resultado = {"corrigidos": [], "novos": [], "regressoes": [], "inalterados": [], "nao_reavaliados": []}
    vistos_antes = set(anterior["achados"])
    ativos_em_antigos = {i for aud in antigos for i, a in aud["achados"].items() if ativo(a)}
    for aud in antigos:
        vistos_antes |= set(aud["achados"])

    for i, a in atual["achados"].items():
        if not ativo(a):
            continue
        antes = anterior["achados"].get(i)
        if ativo(antes):
            mudancas = []
            if antes.get("status") != a.get("status"):
                mudancas.append(f"status {antes.get('status')} → {a.get('status')}")
            if antes.get("severidade") != a.get("severidade"):
                mudancas.append(f"severidade {antes.get('severidade')} → {a.get('severidade')}")
            resultado["inalterados"].append({**a, "mudancas": mudancas})
        elif (antes and not ativo(antes)) or (i in ativos_em_antigos and no_escopo(anterior, a.get("arquivo"))):
            resultado["regressoes"].append(a)
        elif i not in vistos_antes:
            resultado["novos"].append(a)
        else:
            resultado["inalterados"].append({**a, "mudancas": ["reavaliado após ficar fora do escopo"]})

    for i, antes in anterior["achados"].items():
        if not ativo(antes):
            continue
        agora = atual["achados"].get(i)
        if ativo(agora):
            continue
        if agora is None and not no_escopo(atual, antes.get("arquivo")):
            resultado["nao_reavaliados"].append(antes)
        else:
            resultado["corrigidos"].append({**antes, "agora": agora.get("status") if agora else "ausente"})
    return resultado


def listar_auditorias(pasta: Path):
    return sorted(pasta.glob("achados-*.json"))


def imprimir(resultado, atual, anterior):
    print(f"# Comparação: {atual['arquivo']} × {anterior['arquivo']}")
    if atual["escopo"] is not None:
        print(f"Escopo atual restrito a {len(atual['escopo'])} arquivo(s): itens fora dele aparecem como "
              "não reavaliados, nunca como corrigidos.")
    titulos = [("regressoes", "Regressões (voltaram)"), ("novos", "Novos"), ("corrigidos", "Corrigidos"),
               ("inalterados", "Inalterados"), ("nao_reavaliados", "Não reavaliados (fora do escopo)")]
    print("\n| " + " | ".join(t for _, t in titulos) + " |")
    print("|" + "---|" * len(titulos))
    print("| " + " | ".join(str(len(resultado[c])) for c, _ in titulos) + " |")
    for chave, titulo in titulos:
        itens = resultado[chave]
        if not itens:
            continue
        print(f"\n## {titulo}")
        for a in itens:
            local = f"{a.get('arquivo')}:{a.get('linha')}" if a.get("linha") else a.get("arquivo")
            extra = ""
            if a.get("mudancas"):
                extra = " · " + "; ".join(a["mudancas"])
            if chave == "corrigidos":
                extra = f" · agora: {a['agora']}"
            print(f"- [{a['id']}] {a.get('risco')} · {local} · {a.get('status')} · {a.get('severidade')}{extra}")


def main():
    p = argparse.ArgumentParser(description="Compara auditorias da vibeproof.")
    p.add_argument("pasta", nargs="?", default=".auditoria-seguranca")
    p.add_argument("--atual")
    p.add_argument("--anterior")
    p.add_argument("--antigos", nargs="*", default=[])
    p.add_argument("--id", nargs=3, metavar=("RISCO", "ARQUIVO", "TRECHO"))
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.id:
        print(id_estavel(*args.id))
        return

    if args.atual or args.anterior:
        if not (args.atual and args.anterior):
            p.error("--atual e --anterior precisam vir juntos")
        caminhos = [Path(c) for c in args.antigos] + [Path(args.anterior), Path(args.atual)]
    else:
        caminhos = listar_auditorias(Path(args.pasta))
        if len(caminhos) < 2:
            msg = "Sem auditoria anterior para comparar." if caminhos else "Nenhum achados-*.json encontrado."
            if args.json:
                print(json.dumps({"aviso": msg}, ensure_ascii=False))
            else:
                print(msg)
            return

    auditorias, avisos = [], []
    for c in caminhos:
        aud, av = carregar(c)
        auditorias.append(aud)
        avisos.extend(av)
    atual, anterior, antigos = auditorias[-1], auditorias[-2], auditorias[:-2]
    resultado = comparar(atual, anterior, antigos)

    if args.json:
        print(json.dumps({"atual": atual["arquivo"], "anterior": anterior["arquivo"], "avisos": avisos,
                          **resultado}, ensure_ascii=False, indent=2))
        return
    for a in avisos:
        print(f"AVISO: {a}")
    imprimir(resultado, atual, anterior)


if __name__ == "__main__":
    main()
