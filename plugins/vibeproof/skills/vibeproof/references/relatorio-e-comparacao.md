# Relatório, arquivo de máquina e comparação

Toda auditoria gera dois arquivos na pasta de saída escolhida na fase 7 do SKILL.md: `.auditoria-seguranca/` na raiz, só se o projeto não publica a raiz como site e a pasta está no `.gitignore`; senão, fora do repositório (scratchpad ou caminho escolhido pela pessoa). Use sempre a mesma pasta entre auditorias, para a comparação funcionar.

- `relatorio-AAAA-MM-DD.md`, para pessoas;
- `achados-AAAA-MM-DD.json`, para máquinas e para comparar com auditorias futuras.

Se já houver arquivos do mesmo dia, acrescente um sufixo (`-2`, `-3`). A ordem alfabética dos nomes precisa seguir a ordem cronológica, porque é assim que o comparador decide qual auditoria é a mais recente.

## Sumário
1. O relatório em dois níveis
2. O arquivo de achados (JSON)
3. Como calcular o id
4. Comparação com auditorias anteriores

## 1. O relatório em dois níveis

Use `assets/modelo-relatorio.md`.

**Primeiro nível: resumo para quem não é da área (no máximo uma página).** Responde só três perguntas, em linguagem direta, sem siglas sem explicação:
1. Posso publicar? Se não, o que impede.
2. O que arrumar antes, em ordem, com uma frase por item no formato "o que pode acontecer → o que fazer".
3. O que ainda não foi verificado e quem precisa conferir.

Não use o resumo para mostrar trabalho: placar, comandos e tabelas ficam no segundo nível. Nunca escreva que o app "está seguro".

**Segundo nível: detalhe técnico.** Tudo o que o modelo já tinha: nível usado, escopo, defesas existentes, placar, achados com evidência, descartados, não verificados, comandos executados, comparação e risco residual.

## 2. O arquivo de achados (JSON)

Modelo em `assets/modelo-achados.json`. Uma entrada por achado, em qualquer status:

| Campo | Conteúdo |
|---|---|
| `id` | Id estável (seção 3) |
| `risco` | Nome curto e consistente do risco, como "IDOR" ou "SQL injection" (use os nomes de `riscos-base.md`) |
| `titulo` | Uma frase sobre o achado |
| `status` | `Confirmado`, `Suspeita`, `Não verificado`, `Descartado` ou `Coberto` |
| `severidade` | `Crítica`, `Alta`, `Média` ou `Baixa` |
| `arquivo` | Caminho relativo à raiz do projeto |
| `linha` | Número da linha (informativo; não entra no id) |
| `trecho` | A linha relevante do código, **com segredos mascarados** |
| `teste` | Teste que prova ou cobre (`arquivo::caso`), ou `null` |
| `commit` | Commit auditado |

No topo do arquivo também vão `data`, `commit`, `nivel` e `escopo`. O `escopo.arquivos` traz a lista de arquivos analisados, ou `null` quando a auditoria cobriu o repositório inteiro. **Esse campo é obrigatório no modo diff**: sem ele, o comparador acharia que tudo o que ficou fora do diff foi corrigido.

## 3. Como calcular o id

O id é um hash do risco, do arquivo e do trecho normalizado. O número da linha fica de fora, para o id continuar o mesmo quando o código muda de lugar. Calcule sempre pelo script, para não haver divergência:

```bash
<python> ${CLAUDE_SKILL_DIR}/scripts/comparar_auditorias.py --id "IDOR" "src/rotas.js" "const p = await db.find(req.params.id)"
```

O trecho deve ser a linha como está no código, já com segredos mascarados (o comparador normaliza espaços e maiúsculas). Se o mesmo risco aparece em várias linhas do mesmo arquivo, cada linha é um achado com seu próprio trecho.

## 4. Comparação com auditorias anteriores

Depois de gravar o JSON, se já existir outro `achados-*.json` na pasta, rode:

```bash
<python> ${CLAUDE_SKILL_DIR}/scripts/comparar_auditorias.py <pasta de saída>
```

O comparador recalcula os ids a partir dos campos e avisa se algum id gravado estiver diferente. Ele separa os achados em:

- **Regressões**: falhas que já tinham sido corrigidas e voltaram. Vão para o topo do resumo leigo, porque indicam que a correção não tinha teste de regressão ou que o teste foi removido.
- **Novos**: nunca vistos antes.
- **Corrigidos**: ativos na anterior, e agora ausentes ou resolvidos (Descartado ou Coberto), com o arquivo dentro do escopo atual.
- **Inalterados**: continuam ativos, com mudanças de status e severidade indicadas.
- **Não reavaliados**: estavam ativos, mas o arquivo ficou fora do escopo desta auditoria (por exemplo, no modo diff). **Nunca** os trate como corrigidos.

Coloque a tabela de contagem e as listas no segundo nível do relatório, e cite regressões e o total de corrigidos no resumo leigo.
