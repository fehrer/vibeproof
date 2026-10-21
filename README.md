# 🛡️ vibeproof

**Segurança com evidência para projetos feitos com IA.**

Uma skill para o Claude Code que audita a segurança do seu projeto e só afirma o que consegue provar.

Cada achado aponta para arquivo e linha, mostra o caminho do dado e vem com uma reprodução usando dados fictícios. Cada correção vem com um teste que falha antes e passa depois. E a skill nunca diz que o seu app "está seguro": diz o que verificou, o que falhou, o que não deu para verificar e qual risco continua existindo.

Feita pensando em quem constrói com IA (vibe coding), mas serve para qualquer projeto. O nome junta *vibe coding* e *proof* (prova), com o sentido de "à prova de", como em *bulletproof*.

## Por que mais uma skill de segurança?

Revisões de segurança feitas por IA costumam errar de dois jeitos:

- **Ruído:** dezenas de recomendações genéricas que nem se aplicam ao projeto.
- **Falsa tranquilidade:** "não encontrei problemas" porque uma busca não achou nada.

Esta skill troca os dois por **evidência**:

- Os scripts geram **pistas**, nunca conclusões.
- Cada pista é investigada até virar um de quatro status: **confirmado**, **suspeita**, **não verificado** ou **descartado (com motivo)**.

Além disso, ela cobre áreas que costumam ficar de fora:

| Área | O que a skill olha |
|---|---|
| **LGPD** | Inventário de dados pessoais, CPF em logs e URLs, envio a terceiros e IA, exclusão de conta de verdade, lembrete do prazo de comunicação de incidentes da ANPD |
| **Supabase e Firebase** | RLS desligado, política baseada em `user_metadata`, views que furam o RLS, colunas sensíveis editáveis, regras abertas do Firestore |
| **IA, agentes e MCP** | Chave de LLM no navegador, ferramentas sem autorização no backend, saída do modelo virando XSS, custo sem limite, credenciais em `.mcp.json` |
| **Supply chain, CI/CD e Docker** | Pacotes alucinados pela IA, `pull_request_target`, injeção em GitHub Actions, imagem rodando como root, banco exposto no compose |

Tudo em português, com resposta no idioma de quem pergunta (PT, ES ou EN).

## O que ela cobre

1. Segredos expostos no frontend
2. Entrada sem validação no servidor
3. SQL e NoSQL injection
4. Prompt injection
5. XSS
6. IDOR e BOLA
7. SSRF
8. Armazenamento de senhas
9. Rate limit, DoS e custo de IA
10. Rotas administrativas
11. Bots e CAPTCHA
12. Erros e logs que vazam dados

Somam-se a eles as quatro áreas da tabela acima.

## Instalação

### Como plugin (recomendado)

Dentro do Claude Code:

```
/plugin marketplace add SEU-USUARIO/vibeproof
/plugin install vibeproof@vibeproof
```

### Cópia manual

```bash
git clone https://github.com/SEU-USUARIO/vibeproof.git
cp -r vibeproof/plugins/vibeproof/skills/vibeproof ~/.claude/skills/
```

Para valer só em um projeto, copie para `.claude/skills/` dentro dele.

**Requisitos:** Claude Code e Python 3.8+. Os scripts usam só a biblioteca padrão, não instalam nada e não fazem requisições de rede. No Windows, se o comando for `python` em vez de `python3`, o Claude adapta, mas vai pedir permissão para rodar.

## Como usar

Peça naturalmente:

> dá uma olhada na segurança desse projeto antes de eu publicar

Ou chame direto, opcionalmente com um escopo:

```
/vibeproof
/vibeproof src/api
```

A skill trabalha em modo de auditoria. Ela não altera o seu código sem aprovação e gera o relatório em `.auditoria-seguranca/`. Inclua essa pasta no `.gitignore`: o relatório descreve como explorar as falhas.

## Como funciona

```
escopo → reconhecimento → pistas → investigação → prova → correção → relatório
```

| Script | O que faz |
|---|---|
| `detectar_stack.py` | Identifica frameworks, banco, auth, IA, Supabase/Firebase, Docker e CI, e diz quais referências ler |
| `inventario_rotas.py` | Lista os pontos de entrada HTTP com um sinal de autenticação; vira a matriz de acesso |
| `buscar_segredos.py` | Procura chaves no código, no build e no histórico do Git, sempre mascaradas; reconhece a `service_role` do Supabase |
| `pontos_quentes.py` | Encontra trechos que merecem investigação, agrupados por risco |

O método completo está em [`references/metodo-de-evidencia.md`](plugins/vibeproof/skills/vibeproof/references/metodo-de-evidencia.md).

## Experimente com o exemplo vulnerável

A pasta [`exemplo-vulneravel/`](exemplo-vulneravel/) tem um app mínimo com mais de 20 falhas plantadas e chaves fictícias. Abra o Claude Code nela e rode a skill para ver o resultado. **Não use esse código em nada real.**

## Limitações (com honestidade)

- **Ela lê código, não ataca o seu site.** Configurações de painel (WAF, CDN, Security Advisor do Supabase, variáveis de produção) aparecem como "não verificado", com o que você deve conferir.
- **Os scripts são heurísticos.** A investigação de verdade é feita pelo Claude lendo o código, e pode errar. Revise os achados e as correções antes de aplicar.
- **Não substitui** pentest profissional, revisão humana nem orientação jurídica sobre LGPD.

## Contribuindo

Issues e PRs são bem-vindos, principalmente:

- novos padrões para os scripts, com um caso no `exemplo-vulneravel`;
- referências para outras stacks (Rails, Laravel, Go, mobile);
- correções de conteúdo técnico, com link para a fonte oficial.

## Créditos

A ideia de exigir prova em cada achado foi inspirada no guia **"Vibe coding com segurança"**, da [KipperDev](https://youtube.com/@kipperdev). Vale muito seguir o canal. O conteúdo desta skill foi escrito de forma independente e se apoia nas referências públicas da [OWASP](https://owasp.org) e na documentação oficial de cada ferramenta.

## Licença

[MIT](LICENSE)
