# IA, agentes e MCP

Leia quando o projeto chama LLMs, expõe ferramentas para agentes, faz RAG (busca em documentos para alimentar o modelo) ou implementa/usa servidores MCP. A base conceitual é o OWASP Top 10 para Aplicações com LLM; confira a versão mais recente no site da OWASP.

## Sumário
1. O princípio que organiza tudo
2. Prompt injection (direta e indireta)
3. Ferramentas e agência excessiva
4. Saída do modelo usada sem tratamento
5. Dados sensíveis e prompt de sistema
6. RAG e isolamento entre clientes
7. Custo e consumo sem limite
8. MCP: servidores que o projeto usa
9. MCP: servidores que o projeto implementa
10. Como provar

## 1. O princípio que organiza tudo

Trate o modelo como um usuário **não confiável e manipulável**. Tudo o que ele produz (texto, chamadas de ferramenta, argumentos, código, SQL) é entrada externa e passa pelos mesmos controles de qualquer requisição de cliente. Instrução no prompt de sistema é orientação de comportamento, não controle de segurança.

## 2. Prompt injection (direta e indireta)

**Direta**: a pessoa escreve no chat algo que tenta mudar as regras. **Indireta**: a instrução vem escondida em conteúdo que o modelo lê, como página web, e-mail, PDF, ticket, resultado de ferramenta, campo de banco ou documento do RAG. A indireta é a mais perigosa, porque o usuário legítimo nem vê o ataque.

**Onde procurar.** Todo caminho por onde conteúdo externo entra no contexto do modelo: leitura de URLs, anexos, e-mails, documentos indexados, saída de outras ferramentas e dados de outros usuários (um comentário que vai ser resumido pelo agente de outra pessoa). Concatenação de conteúdo do usuário dentro do prompt de sistema.

**Como corrigir.** Não existe filtro que elimine o risco. A defesa efetiva é limitar o que o modelo consegue fazer mesmo quando for enganado (seções 3 a 5). Separar instruções de dados (delimitadores, mensagens distintas) ajuda, mas não basta.

## 3. Ferramentas e agência excessiva

**O risco.** O agente tem mais poder do que a tarefa exige: ferramentas demais, permissões amplas demais, ou ações de alto impacto sem confirmação humana.

**Onde procurar.** Definições de ferramentas (`tools: [...]`, `@tool`, `server.tool(...)`, `registerTool`, funções `execute` do AI SDK da Vercel). Para cada ferramenta, responda:
- **Quem é o usuário?** O handler deve usar a identidade da **sessão**, nunca um `userId` que veio como argumento do modelo.
- **Que recursos alcança?** A consulta filtra por dono e tenant (veja IDOR em `riscos-base.md`)?
- **Que efeitos tem?** Ler, escrever, apagar, enviar mensagem, pagar, executar código.
- **Há confirmação humana** para ações irreversíveis ou caras?
- **Os argumentos são validados** com schema estrito no backend?

**Como corrigir.** Ferramentas mínimas e específicas (`ler_meu_projeto`, e não `executar_sql`). Credenciais da ferramenta com o menor escopo possível. Autorização no handler, com a sessão. Confirmação explícita para ações de impacto. Nunca dê ao agente ferramentas genéricas de shell, SQL livre ou requisição HTTP para qualquer URL sem barreiras fortes. Nesses casos, aplique também as defesas de SSRF e de injeção de comando.

## 4. Saída do modelo usada sem tratamento

**Onde procurar.** Resposta do modelo renderizada como HTML/Markdown sem sanitização (XSS). Saída usada em `eval`, `exec`, shell, SQL, caminhos de arquivo, URLs de requisição ou redirecionamentos. JSON do modelo usado sem validar o schema.

**Como corrigir.** Os mesmos controles de qualquer entrada externa: sanitizar ao renderizar, validar com schema, parametrizar consultas, lista de destinos permitidos.

## 5. Dados sensíveis e prompt de sistema

**Onde procurar.**
- Segredos, chaves ou regras de negócio confidenciais dentro do prompt de sistema, que pode ser extraído.
- Dados de outros usuários no contexto.
- SDK de IA chamado do navegador com a chave exposta (`dangerouslyAllowBrowser: true`).
- Prompts e respostas registrados em log com dados pessoais (veja `lgpd.md`).
- Envio de dados pessoais a provedores de IA no exterior sem base legal e sem informar o titular.

**Como corrigir.** O prompt de sistema não guarda segredo nem é a única barreira de nada. A chave do provedor fica no servidor. O contexto contém só o necessário para a pessoa atual. Os logs de prompts são mascarados e têm retenção definida.

## 6. RAG e isolamento entre clientes

**Onde procurar.** Busca vetorial sem filtro por tenant ou dono, com um índice único para todos os clientes. Documentos de um usuário recuperados na resposta de outro. Ingestão de documentos sem controle de quem enviou. Metadados de permissão aplicados só depois da busca (vazam pelo ranking e pelo tamanho da resposta).

**Como corrigir.** O filtro de tenant/dono é aplicado **na consulta** ao vetor. Permissões dos documentos de origem são respeitadas na indexação e na recuperação. Rastreie de onde veio cada documento.

## 7. Custo e consumo sem limite

**Onde procurar.** Chamadas a LLM sem `max_tokens`, sem limite de tamanho da entrada, sem cota por usuário e sem rate limit. Loops de agente sem número máximo de passos. Rotas públicas (sem login) que chamam modelos.

**Como corrigir.** Limite de tokens por chamada, tamanho máximo de entrada, cota diária por usuário, número máximo de passos do agente, alerta de gasto no provedor e rate limit (veja o item 9 de `riscos-base.md`).

## 8. MCP: servidores que o projeto usa

Servidores MCP executam com as permissões de quem os roda e expõem ferramentas que o modelo vai chamar.

**Onde procurar.** `.mcp.json`, `mcp.json`, configurações de cliente MCP versionadas no repositório.
- **Tokens e chaves em texto puro** dentro dessas configurações, especialmente se versionadas.
- **Origem dos servidores**: pacotes de terceiros executados com `npx`/`uvx` sem versão fixa. Cada execução pode baixar uma versão nova, e isso é supply chain.
- **Escopo das credenciais** passadas aos servidores (token de GitHub com acesso a todos os repositórios, por exemplo).
- **Descrições de ferramentas** de servidores de terceiros: podem conter instruções ocultas para o modelo ("tool poisoning"). Revise o texto que o servidor expõe.

**Como corrigir.** Fixe versões. Use servidores de fontes confiáveis. Passe credenciais por variável de ambiente, nunca no arquivo versionado, e com escopo mínimo. Revise as ferramentas expostas e desative as desnecessárias.

## 9. MCP: servidores que o projeto implementa

**Onde procurar.** Handlers de ferramentas (`server.tool(`, `@mcp.tool`, `registerTool`). Verifique:
- **Validação de entrada** com schema estrito em cada ferramenta.
- **Injeção de comando**: argumentos repassados para shell (`exec`, `subprocess` com `shell=True`).
- **Path traversal** em ferramentas de arquivo: `../` sai do diretório permitido? Normalize o caminho e confira se continua dentro da raiz permitida.
- **SSRF** em ferramentas que buscam URLs.
- **Autorização por ferramenta** e por recurso, com a identidade do cliente autenticado.
- **Servidores HTTP remotos**: autenticação (a especificação do MCP adota OAuth), sem repassar para APIs a jusante o token recebido do cliente ("token passthrough"), e atenção ao problema do "confused deputy" em proxies OAuth.
- **Servidores HTTP locais**: escutar só em `127.0.0.1` e validar o header `Origin`, para evitar ataques de DNS rebinding a partir de páginas abertas no navegador.

Confira a especificação e as boas práticas de segurança atuais do MCP, que evoluem rápido.

## 10. Como provar

- **Injeção indireta**: crie um documento fixture com uma instrução que peça ao agente para usar uma ferramenta contra outra conta (por exemplo, ler o projeto de `usuario-b@exemplo.test`). No teste, simule o modelo devolvendo exatamente essa chamada de ferramenta, sem depender de o modelo real "cair". O teste passa quando o **backend nega** a ação.
- **Identidade na ferramenta**: chame o handler com a sessão de A e um argumento apontando para recurso de B. Deve negar.
- **Saída do modelo**: simule uma resposta contendo o marcador HTML de teste e confirme que ela é renderizada como texto.
- **Custo**: mostre que uma entrada gigante é rejeitada antes de chegar ao provedor, e que a cota por usuário retorna erro ao ser excedida.
- **MCP**: teste path traversal (`../../etc/passwd` como argumento deve ser negado) e injeção de comando com valores inofensivos (`; echo marcador` não deve executar).

Relate a barreira efetiva e as limitações que sobram. "O prompt de sistema proíbe" nunca é evidência de proteção.
