# Relatório de segurança: [projeto]

> **Confidencial.** Este relatório descreve como explorar falhas reais. Não publique em repositório público antes de corrigir. Segredos aparecem mascarados.

| | |
|---|---|
| Data | AAAA-MM-DD |
| Commit | `abc1234` |
| Escopo | repositório inteiro / pasta / branch |
| Ambiente usado nos testes | local / banco de teste / sem execução |
| Stack detectada | ... |

## Resumo

Três a cinco frases em linguagem direta: o estado geral, o problema mais grave e o que fazer primeiro. Nunca afirme que o projeto "está seguro".

## Placar

| | Crítica | Alta | Média | Baixa |
|---|---|---|---|---|
| Confirmado | 0 | 0 | 0 | 0 |
| Suspeita | 0 | 0 | 0 | 0 |

Não verificado: N itens · Descartado (com motivo): N pistas

## Bloqueadores de publicação

Achados Críticos ou Altos confirmados, e segredos expostos ainda não revogados. Se não houver nenhum, diga isso e lembre o que não foi verificado.

1. **[ID] Título curto**: uma frase sobre o impacto.

## Premissas sobre regras de acesso

Quem pode fazer o quê, segundo o código ou a documentação. Marque o que foi deduzido e precisa de confirmação.

## Achados

| ID | Risco | Status | Severidade | Onde | Correção | Teste |
|---|---|---|---|---|---|---|
| S-01 | IDOR em projetos | Confirmado | Alta | `src/routes/projects.ts:42` | Filtrar por `ownerId` da sessão | `tests/projects.authz.test.ts` |

### S-01 · Título do achado

- **Status e severidade**: Confirmado · Alta, porque [quem explora, o que precisa, o que ganha].
- **Caminho do dado**: `arquivo:linha` (fonte) → ... → `arquivo:linha` (destino).
- **Reprodução**: comando ou teste, com dados fictícios.
- **Saída observada** (mascarada):
  ```
  ...
  ```
- **Impacto neste projeto**: frase concreta.
- **Correção proposta**:
  ```diff
  ...
  ```
- **Testes**: negativo `...` e positivo `...`. Resultado antes: falha. Resultado depois: passa (ou "pendente de aprovação").

(Repita o bloco para cada achado.)

## Descartados

| Pista | Onde | Por que não é falha |
|---|---|---|
| `innerHTML` | `src/ui/banner.js:10` | Recebe só texto fixo definido no código |

## Não verificado e dependências externas

Itens que exigem acesso a painéis, produção ou infraestrutura, com o que conferir em cada um. Exemplos: regras do WAF/CDN, Security Advisor do Supabase, variáveis de ambiente de produção, rate limit em várias instâncias.

## Inventário de dados pessoais (LGPD)

Tabelas e campos com dados pessoais, para onde eles vão (terceiros) e o que foi verificado sobre exclusão, exportação e retenção.

## Comandos executados

| Comando | Resultado real |
|---|---|
| `python3 .../detectar_stack.py .` | Node 20, Next.js, Prisma, Supabase |
| `npm test -- projects` | 1 falha (antes da correção) |

## Risco residual e próximos passos

O que continua arriscado mesmo depois das correções propostas, e a ordem sugerida de ação.

---
Gerado com a skill vibeproof.
