# Relatório de segurança: [projeto]

> **Confidencial.** Este relatório descreve como explorar falhas reais. Não publique em repositório público antes de corrigir. Segredos aparecem mascarados.

## Resumo (para quem não é da área)

**Posso publicar?** Sim / Não, por causa de [N] problemas graves. / Sim, mas confira os itens não verificados antes.

**O que arrumar antes, em ordem:**
1. [O que pode acontecer] → [o que fazer]. Exemplo: "Qualquer pessoa consegue baixar a lista de clientes com CPF → exigir login na rota /admin."
2. ...

**O que ainda não foi verificado:** [itens que dependem de painel de nuvem, produção ou outra pessoa], e quem precisa conferir.

(Máximo de uma página. Sem siglas sem explicação. Nunca escreva que o app "está seguro".)

---

## Detalhe técnico

| | |
|---|---|
| Data | AAAA-MM-DD |
| Commit | `abc1234` |
| Nível | rapido / padrao / completo |
| Escopo | repositório inteiro / `diff base..head` / lista de arquivos |
| Fora do escopo | o que não foi analisado e por quê |
| Ambiente usado nos testes | local / banco de teste / sem execução |
| Stack detectada | ... |
| Arquivo de máquina | `achados-AAAA-MM-DD.json` |

### Defesas existentes (fase 0)

| Controle existente | Onde está | O que cobre | Executado? |
|---|---|---|---|
| Teste de autorização | `tests/test_autorizacao.py` | IDOR em pedidos | Sim, passou (saída abaixo) |

### Placar

| | Crítica | Alta | Média | Baixa |
|---|---|---|---|---|
| Confirmado | 0 | 0 | 0 | 0 |
| Suspeita | 0 | 0 | 0 | 0 |

Coberto por teste existente: N · Não verificado: N · Descartado (com motivo): N

### Comparação com a auditoria anterior

| Regressões | Novos | Corrigidos | Inalterados | Não reavaliados |
|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 |

(Saída de `comparar_auditorias.py`. Omita a seção na primeira auditoria.)

### Bloqueadores de publicação

1. **[ID] Título curto**: uma frase sobre o impacto.

### Premissas sobre regras de acesso

Quem pode fazer o quê, segundo o código ou a documentação. Marque o que foi deduzido.

### Achados

| ID | Risco | Status | Severidade | Onde | Correção | Teste |
|---|---|---|---|---|---|---|
| a1b2c3d4e5f6 | IDOR em projetos | Confirmado | Alta | `src/rotas/projetos.js:42` | Filtrar por dono da sessão | `tests/...` |

#### a1b2c3d4e5f6 · Título do achado

- **Status e severidade**: Confirmado · Alta, porque [quem explora, o que precisa, o que ganha].
- **Caminho do dado**: `arquivo:linha` (fonte) → ... → `arquivo:linha` (destino). Indique "fora do diff, alcançado pela mudança" quando for o caso.
- **Reprodução**: comando ou teste, com dados fictícios.
- **Saída observada** (mascarada):
  ```
  ...
  ```
- **Correção proposta**:
  ```diff
  ...
  ```
- **Testes**: negativo e positivo. Resultado antes: falha. Depois: passa (ou "pendente de aprovação").

### Cobertos por testes existentes

| Risco | Onde | Teste | Saída da execução |
|---|---|---|---|

### Descartados

| Pista | Onde | Por que não é falha |
|---|---|---|

### Não verificado e dependências externas

Itens que exigem painel, produção ou infraestrutura, com o comando ou a tela a conferir (veja `references/nuvem.md`).

### Inventário de dados pessoais (LGPD)

(Obrigatório no nível completo.)

### Comandos executados

| Comando | Resultado real |
|---|---|

### O que foi criado ou instalado no projeto

Arquivos de teste, pacotes e pastas, e como remover.

### Risco residual e próximos passos

---
Gerado com a skill vibeproof.
