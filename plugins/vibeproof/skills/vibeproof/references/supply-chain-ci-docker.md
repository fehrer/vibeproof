# Dependências, CI/CD e Docker

Código que você não escreveu também roda com as suas permissões: pacotes, actions do GitHub, imagens base. E o pipeline de CI costuma ter os segredos mais valiosos do projeto (deploy, nuvem, registro de pacotes).

## Sumário
1. Dependências e supply chain
2. GitHub Actions e outros pipelines
3. Docker e docker-compose
4. Configuração de hospedagem

## 1. Dependências e supply chain

**O que verificar.**
- **Lockfile versionado** (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`). Sem ele, cada instalação pode trazer versões diferentes.
- **Vulnerabilidades conhecidas.** Use o comando nativo do gerenciador que o projeto já usa: `npm audit`, `pnpm audit`, `yarn npm audit` (Yarn 2+), `pip-audit` ou `osv-scanner`, se instalados. Esses comandos consultam a internet: avise antes de rodar. Não instale ferramenta nova sem autorização.
- **Pacotes inexistentes, recém-criados ou com nome parecido.** Assistentes de IA às vezes sugerem pacotes que não existem; atacantes registram esses nomes depois ("slopsquatting"), além dos nomes quase iguais aos populares ("typosquatting"). Para dependências pouco conhecidas, confira no registro: data de criação, volume de downloads, repositório de código, mantenedores e scripts de instalação.
- **Scripts de instalação** (`preinstall`, `postinstall`) em dependências pouco conhecidas: rodam código na máquina e no CI durante a instalação.
- **Dependências abandonadas ou não usadas.** Cada uma é superfície de ataque sem benefício.
- **Atualização contínua.** A presença de Dependabot ou Renovate é ponto positivo; a ausência é melhoria (não bloqueador).

**Como provar.** Mostre a saída real do comando de auditoria (resuma por severidade e por pacote) e, para cada vulnerabilidade relevante, se o código do projeto realmente usa a parte afetada. Uma vulnerabilidade em dependência de desenvolvimento que nunca roda em produção tem prioridade diferente de uma no servidor.

**Como corrigir.** Atualize para a versão corrigida, priorizando o que roda em produção e o que é alcançável. Remova o que não é usado. Versione o lockfile. No CI, instale a partir do lockfile (`npm ci`, `pnpm install --frozen-lockfile`).

## 2. GitHub Actions e outros pipelines

Arquivos em `.github/workflows/*.yml` (ou `.gitlab-ci.yml` e similares).

**O que verificar.**
- **`pull_request_target` com checkout do código do PR.** Esse gatilho roda com segredos e permissão de escrita mesmo para PRs de forks. Se o workflow faz checkout do código do PR e o executa (instalar dependências, rodar testes, build), qualquer pessoa consegue roubar os segredos abrindo um PR. Crítico em repositórios públicos.
- **Injeção de script via expressões.** `${{ github.event.issue.title }}`, `...pull_request.title`, `...comment.body`, `...head_ref` e campos parecidos, usados direto dentro de `run:`, viram código shell. Um título de issue malicioso executa comandos no runner. Correção: passe o valor por variável de ambiente (`env: TITULO: ${{ ... }}`) e use `"$TITULO"` no script.
- **Permissões do `GITHUB_TOKEN`.** Defina `permissions:` no nível do workflow com o mínimo (geralmente `contents: read`) e amplie por job só onde precisa. `write-all` ou a ausência do bloco em repositórios com padrão amplo é achado.
- **Actions de terceiros sem fixar o SHA.** `uses: alguem/action@v1` ou `@main` pode mudar a qualquer momento. Fixe o SHA completo do commit, com a versão em comentário. Actions oficiais (`actions/*`) têm risco menor, mas a boa prática vale para todas.
- **Segredos impressos em log**, segredos passados para scripts de terceiros e artefatos que contêm `.env` ou credenciais.
- **Credenciais de nuvem de longa duração** como segredo do repositório, quando o provedor aceita OIDC (credenciais temporárias).
- **Runners self-hosted em repositório público**: PRs de estranhos podem executar código na sua máquina.

Ferramentas como `actionlint` e `zizmor` fazem análise estática de workflows. Se já estiverem instaladas, use; caso contrário, sugira como próximo passo.

**Como provar.** Mostre o arquivo, a linha e o gatilho, e descreva quem consegue disparar o workflow (qualquer pessoa com conta no GitHub? só colaboradores?). Não abra PRs nem issues reais para testar.

## 3. Docker e docker-compose

**O que verificar no Dockerfile.**
- **Imagem base sem versão fixa** (`FROM node`, `FROM node:latest`). Prefira uma tag específica e, se possível, fixe o digest.
- **Processo rodando como root**: Dockerfile sem instrução `USER` para um usuário sem privilégio.
- **Segredos nas camadas da imagem**: `ENV SECRET=...`, `ARG TOKEN` usado em `RUN`, `COPY .env` ou `COPY . .` sem `.dockerignore`. Qualquer pessoa com acesso à imagem extrai esses valores com `docker history` ou abrindo as camadas. Use build secrets (`RUN --mount=type=secret`) e variáveis em tempo de execução.
- **`.dockerignore` ausente ou incompleto**: deve excluir `.env*`, `.git`, `node_modules`, chaves e arquivos de credenciais.
- **Build de estágio único** que leva compiladores, dependências de desenvolvimento e código-fonte para produção. Recomende multi-stage.

**O que verificar no docker-compose.**
- **Portas de banco publicadas para todas as interfaces** (`"5432:5432"`, `"3306:3306"`, `"27017:27017"`, `"6379:6379"`). Em um servidor, isso expõe o banco à internet. Use `"127.0.0.1:5432:5432"` ou não publique a porta.
- **Senhas em texto no arquivo versionado.** Use arquivo `.env` não versionado ou secrets.
- **`privileged: true`**, montagem de `/var/run/docker.sock` (equivale a root no host) e `network_mode: host`.

**Como provar.** Mostre a linha. Se o Docker estiver disponível localmente e a pessoa autorizar, `docker history --no-trunc <imagem>` mostra segredos nas camadas (mascare na saída).

**Como corrigir.** Dockerfile multi-stage, imagem base fixada, `USER` sem privilégio, `.dockerignore` completo, segredos só em tempo de execução, portas restritas a `127.0.0.1`. Sugira um scanner de imagem (Trivy, Docker Scout) como próximo passo, sem instalar sem pedir.

## 4. Configuração de hospedagem

- **Ambientes de preview** (Vercel, Netlify) que recebem segredos de produção e ficam acessíveis publicamente.
- **Headers de segurança** configurados em `vercel.json`, `netlify.toml`, `next.config.*` ou no servidor (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors`). Ausência é melhoria, não bloqueador, salvo quando houver XSS ou clickjacking demonstrável.
- **Source maps publicados em produção** expõem o código-fonte original. Nem sempre é falha, mas facilita o trabalho de quem ataca e às vezes revela segredos e rotas internas.

Configurações do painel do provedor (WAF, proteção DDoS, variáveis por ambiente) não estão no repositório: liste como "não verificado" com o que conferir.
