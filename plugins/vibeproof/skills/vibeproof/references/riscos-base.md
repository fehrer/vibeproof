# Os 12 riscos base

Cada seção tem cinco partes: o que é, onde procurar, como provar, como corrigir e o que **não** resolve. Pule as seções que não se aplicam à stack detectada, mas registre no relatório que foram puladas e por quê.

## Sumário
1. Segredos expostos no frontend
2. Entrada sem validação no servidor
3. SQL injection (e NoSQL injection)
4. Prompt injection (ver `ia-agentes-mcp.md`)
5. XSS
6. IDOR e BOLA
7. SSRF
8. Armazenamento de senhas
9. Abuso de requisições, DoS e custo
10. Rotas administrativas e enumeração
11. Bots em login e cadastro
12. Erros e logs que vazam dados

---

## 1. Segredos expostos no frontend

**O que é.** Todo código que roda no navegador pode ser lido por quem visita o site, inclusive as variáveis de ambiente embutidas no build. O `.env` organiza configuração, mas não esconde nada: se o valor entra no bundle, ele é público.

**Onde procurar.**
- Variáveis com prefixo público do framework: `VITE_` (Vite), `NEXT_PUBLIC_` (Next.js), `REACT_APP_` (Create React App), `EXPO_PUBLIC_` (Expo), `PUBLIC_` (SvelteKit e Astro), `NUXT_PUBLIC_` e `runtimeConfig.public` (Nuxt), `GATSBY_` (Gatsby).
- Módulos que usam segredos sendo importados por componentes de cliente. No Next.js, observe arquivos com `'use client'`.
- Build gerado (`dist/`, `build/`, `.next/static/`) e source maps (`*.map`) publicados.
- `.env` versionado no Git, inclusive no histórico.
- SDKs de IA instanciados no navegador (`dangerouslyAllowBrowser: true`).

**Atenção a chaves que são públicas por design.** Algumas chaves são feitas para ficar no navegador: a chave `anon`/`publishable` do Supabase, o `apiKey` da configuração web do Firebase e a `pk_` do Stripe. Elas só são aceitáveis se o controle real existir em outro lugar (RLS, regras do Firebase, restrições da chave). Nesses casos, o achado vira "verificar o controle", não "segredo exposto".

**Como provar.** Faça o build local e procure o valor (mascarado) nos arquivos gerados. Mostre o caminho: arquivo de origem → variável → import → bundle. Para o histórico, mostre o commit em que o arquivo entrou.

**Como corrigir.** Mova a chamada que usa o segredo para o backend (rota de API, server action, edge function) e devolva ao cliente só o resultado necessário, em uma rota autenticada. Em produção, guarde segredos no gerenciador do provedor de hospedagem. Se a chave já foi exposta: **revogue e gere outra**.

**Não resolve.** Apagar o `.env` ou reescrever o histórico sem rotacionar a chave. Ofuscar o valor. Trocar o nome da variável.

---

## 2. Entrada sem validação no servidor

**O que é.** Body, query string, parâmetros de rota, headers, cookies, uploads e webhooks são controlados pelo cliente. Validação no formulário melhora a experiência, mas qualquer pessoa pode chamar a API direto. Aceitar o objeto inteiro que chegou permite **atribuição em massa**: um campo como `role`, `isAdmin`, `ownerId` ou `plano` que o cliente não deveria controlar acaba gravado no banco.

**Onde procurar.** `...req.body`, `Object.assign(entidade, req.body)`, `create({ data: req.body })`, `update(req.body)`, `**request.data` (Django), modelos sem lista explícita de campos. Rotas sem schema (Zod, Valibot, Joi, class-validator, Pydantic, serializers do DRF). Uploads sem limite de tamanho ou validação de tipo pelo conteúdo. Ausência de limite de tamanho do body.

**Como provar.** Envie, em teste local, um payload com tipo errado, texto muito acima do limite e um campo extra privilegiado (`role: "admin"`). Mostre que o servidor aceitou, ou que o valor foi persistido.

**Como corrigir.** Schema no servidor que define tipo, formato, tamanho e regras de negócio, e que **rejeita campos não previstos** (modo estrito). Use só o resultado validado, nunca o objeto original. Campos sensíveis (`role`, `ownerId`, `tenantId`) vêm da sessão ou do banco, nunca do cliente. Uploads: limite de tamanho, tipo verificado pelo conteúdo, nome de arquivo gerado pelo servidor e armazenamento fora da pasta servida publicamente.

**Não resolve.** `required` no HTML, validação só no frontend, ou "limpar" a string removendo caracteres. Validação de formato também não é autorização: um `projectId` válido ainda pode ser de outra pessoa (veja o item 6).

---

## 3. SQL injection (e NoSQL injection)

**O que é.** Quando um valor externo é colado no texto da consulta, ele pode mudar a lógica da consulta em vez de ser tratado como dado. Isso acontece mesmo em projetos que usam ORM, sempre que alguém escreve SQL "na mão".

**Onde procurar.**
- Template strings com `${` dentro de SQL; concatenação com `+`.
- Prisma: `$queryRawUnsafe` e `$executeRawUnsafe`. As versões com tagged template (`` $queryRaw`...${valor}` ``) parametrizam.
- `knex.raw`, `sequelize.query`, `typeorm.query` e `.raw(` sem bindings.
- Python: `cursor.execute(f"...")`, `% (...)`, `.format(` dentro de `execute`, e `text(f"...")` no SQLAlchemy.
- Nomes de coluna, tabela e direção de ordenação vindos do cliente (`ORDER BY ${req.query.sort}`). Parâmetros de driver não protegem identificadores.
- NoSQL: objetos do body usados direto como filtro (`find(req.body)`), que permitem operadores como `{"$ne": null}`; e uso de `$where`.

**Como provar.** Em banco de teste, use um valor com apóstrofo (veja `metodo-de-evidencia.md`) e mostre que o filtro de dono deixou de valer ou que a consulta quebrou. Erro de sintaxe SQL causado pelo valor já é indício forte; vazamento de linhas de outra conta é confirmação.

**Como corrigir.** Parâmetros do driver ou do ORM para todo **valor**. Para **identificadores** (coluna, tabela, `ASC`/`DESC`), use uma lista fixa de opções permitidas no código. No NoSQL, valide o formato do filtro e converta para tipos primitivos antes de consultar.

**Não resolve.** Remover aspas, bloquear palavras como `DROP` ou escapar caracteres manualmente.

---

## 4. Prompt injection

Quando o projeto usa LLMs, leia `ia-agentes-mcp.md`. O ponto central: instruções escondidas em conteúdo que o modelo lê podem fazê-lo pedir ações indevidas. A defesa real fica **fora do modelo**, no backend que executa as ferramentas.

---

## 5. XSS

**O que é.** XSS acontece quando um texto controlado por outra pessoa vira HTML ou JavaScript executável no navegador de quem vê a página. Com isso, o atacante age na sessão da vítima. Comentários, nomes de perfil, mensagens de chat e **respostas de IA renderizadas como Markdown** são fontes comuns.

**Onde procurar.** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `.html(` (jQuery), `dangerouslySetInnerHTML` (React), `v-html` (Vue), `{@html}` (Svelte), `bypassSecurityTrust*` (Angular), `|safe` e `mark_safe` (Django/Jinja), `Markup(` (Flask). Renderizadores de Markdown sem sanitização. Links e `src` com URL controlada pelo usuário (`javascript:` em `href`). Templates de e-mail montados com dados do usuário.

**Como provar.** Em teste de navegador isolado (Playwright, Testing Library com jsdom), injete o marcador inofensivo descrito em `metodo-de-evidencia.md` e verifique se ele virou elemento. Mostre a origem do dado e o ponto de renderização.

**Como corrigir.** Para texto, use o escape padrão do framework ou `textContent`. Se precisar aceitar HTML rico, passe por um sanitizador mantido (por exemplo, DOMPurify) com lista restrita de tags e atributos. Valide esquemas de URL (`http:`/`https:`). Como camada extra: Content Security Policy e cookies de sessão `HttpOnly`.

**Não resolve.** Ter CSP sem corrigir a renderização. Filtrar a palavra `<script>`. Sanitizar só na entrada e depois renderizar em outro contexto (atributo, URL, JavaScript).

---

## 6. IDOR e BOLA

**O que é.** Estar logado não dá direito a todos os dados. Em uma falha IDOR (BOLA, no vocabulário de APIs), trocar o identificador na URL ou no body dá acesso ao recurso de outra pessoa. É uma das falhas mais comuns em apps gerados por IA, porque o código "funciona" no teste com uma conta só.

**Onde procurar.** Busca por ID vindo da requisição (`findUnique({ where: { id } })`, `findById(req.params.id)`, `get_object_or_404(Model, pk=pk)`) sem filtro de dono ou tenant. Updates e deletes que filtram só por `id`. Listagens sem filtro. Anexos e arquivos servidos por caminho ou URL previsível. Resolvers GraphQL. Dono ou tenant aceito do body (`ownerId: req.body.ownerId`). Use a saída de `inventario_rotas.py` para montar a lista.

**Como provar.** Duas contas, dois recursos, em banco de teste. Com a sessão de A, tente ler, editar, apagar, listar e baixar anexos do recurso de B. Veja o teste-modelo em `metodo-de-evidencia.md`.

**Como corrigir.** Toda consulta inclui a identidade autenticada (e o tenant) no filtro: `where: { id, ownerId: sessao.usuario.id }`. Aplique em leitura, atualização, exclusão e listagem. Para arquivos, use URLs assinadas e de curta duração, geradas depois da checagem. Retorne 404 em vez de 403 quando revelar a existência do recurso já for um problema.

**Não resolve.** UUID no lugar de ID sequencial. Esconder o botão. Checar a permissão só no frontend.

---

## 7. SSRF

**O que é.** O servidor é induzido a fazer uma requisição para um destino escolhido pelo atacante. A partir dele, o atacante alcança serviços internos, painéis administrativos e endpoints de metadados da nuvem, que costumam devolver credenciais.

**Onde procurar.** Funcionalidades que recebem URL: importar de link, prévia de link, webhooks configuráveis pelo usuário, download de imagem por URL, geradores de PDF e screenshot, integrações "cole a URL da sua API". Chamadas como `fetch(variavel)`, `axios.get(variavel)`, `requests.get(variavel)` e `httpx.get(variavel)`, com a URL vinda da requisição ou do banco.

**Como provar.** Com o cliente HTTP interceptado por mock, mostre que o código tentaria acessar `127.0.0.1`, `[::1]`, `10.0.0.1`, `169.254.169.254`, ou seguiria um redirecionamento para um desses. Não faça requisições reais a metadados de nuvem.

**Como corrigir.**
- **Melhor**: o cliente escolhe uma opção de negócio (`fonte: "catalogo"`) e o servidor mapeia para uma URL fixa.
- **Se URL livre for indispensável**:
  - Resolva o DNS e bloqueie faixas privadas, loopback, link-local, metadados e IPv6 equivalentes, inclusive IPv4 mapeado em IPv6.
  - Conecte no IP já validado, para evitar que o DNS mude entre a checagem e a requisição.
  - Desative redirecionamentos ou revalide cada salto.
  - Imponha timeout e limite de tamanho da resposta.
- **Na infraestrutura**: restrinja a saída de rede do servidor.

**Não resolve.** Validar a URL só como texto (por regex, `startsWith` ou verificando o hostname sem resolver o DNS).

---

## 8. Armazenamento de senhas

**O que é.** Senha em texto puro ou criptografada de forma reversível fica disponível para quem obtiver o banco (ou a chave). Para autenticação, o padrão é guardar um **hash de senha** lento, com salt, que só pode ser comparado, nunca revertido.

**Onde procurar.** Cadastro, login, troca e recuperação de senha. `md5`, `sha1`, `sha256` ou `createHash` aplicados a senhas. bcrypt com custo baixo. Senhas em logs, respostas de API, analytics ou ferramentas de monitoramento de erros. Tokens de recuperação gerados com `Math.random()`, sem expiração ou reutilizáveis.

**Como provar.** Crie duas contas com a mesma senha em banco de teste e mostre os valores gravados (mascarados): iguais, reversíveis ou em formato de hash rápido. Mostre a senha aparecendo em log, se for o caso.

**Como corrigir.** Prefira um provedor de autenticação maduro. Se guardar senhas, use **Argon2id** com parâmetros no mínimo iguais aos recomendados pela OWASP, ou bcrypt com custo adequado quando Argon2 não estiver disponível (lembre que o bcrypt ignora o que passa de 72 bytes). Compare só com a função da biblioteca. Para migrar hashes antigos, refaça o hash no próximo login bem-sucedido e force a troca de senha para quem não voltar. Tokens de recuperação: aleatoriedade criptográfica, uso único e expiração curta.

**Não resolve.** SHA-256 "com salt", criptografia simétrica, base64.

---

## 9. Abuso de requisições, DoS e custo

**O que é.** Muitas requisições, ou poucas requisições caras, esgotam CPU, memória, conexões ou dinheiro. Em apps com IA existe uma versão moderna do problema, a "negação de carteira": cada chamada ao LLM custa, e um script pode gerar uma conta enorme em horas. Rate limit no código reduz abuso, mas não absorve ataque volumétrico distribuído (DDoS); isso é papel da borda (CDN/WAF).

**Onde procurar.**
- Ausência de rate limit em login, cadastro, recuperação de senha, envio de e-mail/SMS e rotas que chamam LLMs.
- Contador em memória com várias instâncias (cada uma conta separado).
- Identidade baseada em IP com proxy mal configurado. Exemplo: `trust proxy` liberado demais no Express permite falsificar `X-Forwarded-For` e escapar do limite.
- Ausência de limite de body, paginação sem máximo, buscas e exportações sem limite, regex aplicada a texto do usuário.
- Chamadas a LLM sem `max_tokens` e sem cota por usuário.

**Como provar.** Em teste local com limite baixo, exceda a janela e verifique se vem 429. Depois, espere a janela e confirme que volta a aceitar. Mostre rotas caras sem limite. Para proxy, mostre que trocar `X-Forwarded-For` reinicia o contador.

**Como corrigir.** Limite por rota e por identidade (usuário quando houver, IP quando não), com armazenamento compartilhado (Redis ou o próprio provedor) em ambientes com várias instâncias. Configure só os proxies conhecidos como confiáveis. Imponha limite de body, timeouts, paginação máxima, cotas e orçamento de tokens por usuário. Na borda, ative proteção DDoS e regras de WAF.

**Não resolve.** Rate limit só no frontend. Achar que a CDN protege sem que as regras estejam ativas. Teste de carga em produção, que nunca deve ser feito como parte desta auditoria.

---

## 10. Rotas administrativas e enumeração

**O que é.** Qualquer pessoa pode testar caminhos (`/admin`, `/api/debug`, `/swagger`, `/.env`) para descobrir o que está exposto. Encontrar a rota não deveria dar acesso; quando a rota não checa permissão, descoberta vira incidente.

**Onde procurar.** Saída de `inventario_rotas.py`. Rotas com `admin`, `internal`, `debug`, `seed`, `reset`, `backup`, `metrics`. Documentação de API habilitada em produção. Endpoints de teste esquecidos. Papel (`role`) lido do body, da query, de cookie não assinado ou de metadados editáveis pelo próprio usuário (veja `user_metadata` em `supabase-firebase.md`). Autorização feita **só** no middleware do Next.js: atualize o framework e cheque também no handler ou na server action.

**Como provar.** Monte a matriz de acesso: para cada rota sensível, a resposta sem sessão, com usuário comum e com admin, em teste local. Mostre as células que deveriam negar e não negam.

**Como corrigir.** Negar por padrão. Autenticação e checagem de papel em toda operação sensível, no servidor, com o papel vindo de fonte confiável (sessão validada ou banco). Remova rotas de debug e seed dos builds de produção. Mantenha um inventário de rotas.

**Não resolve.** URL difícil de adivinhar. Esconder o link no menu. CORS (CORS não impede requisições feitas fora do navegador).

---

## 11. Bots em login e cadastro

**O que é.** Bots testam senhas vazadas (credential stuffing), criam contas falsas em massa e abusam de envio de e-mail/SMS. CAPTCHA ajuda, mas só se o backend validar o token, e mesmo assim é uma camada extra que automação sofisticada consegue contornar.

**Onde procurar.** Widget de CAPTCHA (Turnstile, reCAPTCHA, hCaptcha) sem chamada à API de verificação no servidor. Verificação que não confere `hostname` e `action`. Token aceito mais de uma vez. Comportamento quando o provedor falha: o código libera ("fail-open") ou bloqueia? Mensagens de login que revelam se o e-mail existe ("senha incorreta" versus "usuário não encontrado"). Ausência de limite por conta e por IP. Ausência de MFA em áreas sensíveis.

**Como provar.** Com mock ou com as chaves oficiais de teste do provedor, envie token ausente, inválido, expirado, reutilizado e com `action` errada. Simule também o provedor fora do ar. Mostre que alguma conta foi criada nesses casos, ou que a mensagem de login permite enumerar e-mails.

**Como corrigir.** Validação do token no servidor, com a chave secreta só no servidor, conferindo sucesso, `hostname` e `action`, antes de qualquer efeito colateral. Defina o comportamento em falha do provedor (para cadastro, prefira bloquear ou exigir verificação extra). Combine com rate limit por conta e por IP, mensagens neutras e MFA onde houver dado sensível. Cuidado com bloqueio de conta por tentativas: ele pode virar ferramenta para travar a conta de outra pessoa. Prefira atrasos progressivos.

**Não resolve.** O widget aparecer na tela.

---

## 12. Erros e logs que vazam dados

**O que é.** Uma exceção devolvida como resposta pode mostrar SQL, caminhos do servidor, versões de bibliotecas, tokens e dados pessoais, e cada pista facilita o próximo ataque. Logs são o vazamento silencioso: guardam corpo de requisição, headers e cookies, ficam anos armazenados e costumam ter acesso amplo.

**Onde procurar.**
- `res.send(err)`, `res.json({ error: err.message })` com mensagens internas, `err.stack` em respostas.
- Express sem `NODE_ENV=production` (mostra stack trace).
- `DEBUG = True` no Django, `app.run(debug=True)` no Flask. O debugger do Werkzeug permite executar código: é crítico se chegar à produção.
- `console.log(req.body)`, `logger.info(user)`, logs de headers com `Authorization`.
- Ferramentas de monitoramento configuradas para enviar dados pessoais por padrão.

**Como provar.** Force uma exceção controlada em teste e inspecione status, corpo e headers. Procure stack, SQL, caminhos, versões e dados pessoais. Para logs, mostre a linha que registra o dado e um exemplo mascarado do que seria gravado.

**Como corrigir.** Tratador central de erros: para o cliente, mensagem genérica e um identificador de correlação (`requestId`); os detalhes vão para log restrito, com mascaramento de campos sensíveis. Erros esperados (400, 401, 403, 404) continuam com mensagens úteis. Debug desligado em produção, garantido por configuração, não por memória.

**Não resolve.** Transformar todo erro em 500, que esconde problemas legítimos do usuário. Registrar tudo "por garantia".
