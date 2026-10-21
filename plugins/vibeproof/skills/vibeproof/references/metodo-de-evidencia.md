# Método de evidência

Este arquivo define o que significa "provar" um achado e uma correção. Leia antes de escrever qualquer reprodução ou teste.

## Sumário
1. O que conta como evidência
2. O que não conta
3. Dados fictícios
4. O ciclo "falha antes, passa depois"
5. Testes-modelo (Node e Python)
6. Ideias de teste por risco
7. Quando não dá para rodar

## 1. O que conta como evidência

Um achado completo tem quatro partes:

- **Caminho do dado**: a fonte (`arquivo:linha` onde o dado externo entra), as transformações pelo caminho e o destino sensível (`arquivo:linha` onde o dano acontece).
- **Condição de exploração**: quem consegue explorar (anônimo, qualquer conta, conta de outro tenant, admin) e o que precisa ter ou saber.
- **Reprodução mínima**: um comando, requisição ou teste, com dados fictícios, e a saída observada. Copie a saída real, com segredos mascarados.
- **Impacto concreto**: o que a pessoa ganha ao explorar, descrito para este projeto ("lê o histórico de pedidos de qualquer cliente") e não de forma genérica ("pode comprometer a confidencialidade").

Uma correção completa tem:

- o diff mínimo;
- um teste que falhava antes e passa depois;
- um teste do caso legítimo passando, para garantir que nada quebrou;
- a saída real da execução dos testes.

## 2. O que não conta

Nenhuma destas afirmações sustenta, sozinha, que algo está seguro:

- "A busca não encontrou X." Busca textual não entende fluxo de dados.
- "O projeto tem middleware de autenticação." Ele precisa estar aplicado a esta rota, nesta ordem.
- "O prompt de sistema proíbe o modelo de fazer isso." Instrução para modelo não é controle de acesso.
- "O botão está escondido", "a URL é difícil de adivinhar", "o CORS bloqueia". Nenhum desses impede uma requisição feita direto à API.
- "Usamos UUID." Dificulta adivinhar, mas não substitui checar quem é o dono.
- "Os testes passaram." Quais testes, testando o quê?
- Um teste que só verifica se uma função existe ou foi chamada, sem exercitar o comportamento.
- "O widget de CAPTCHA aparece na tela." O backend precisa validar o token.

## 3. Dados fictícios

- **Contas**: `usuario-a@exemplo.test`, `usuario-b@exemplo.test`, `admin@exemplo.test`. O domínio `.test` é reservado e nunca recebe e-mail de verdade.
- **Senhas e segredos de teste**: valores obviamente falsos (`senha-de-teste-123`, `segredo_falso_nao_usar`).
- **Documentos brasileiros (CPF, CNPJ)**: gere números válidos por algoritmo, com uma função de teste ou biblioteca já presente no projeto. Nunca use documentos de pessoas reais, mesmo que estejam "públicos".
- **XSS**: use um marcador HTML inofensivo, como `<b data-teste-xss="1">marcador</b>`. O teste passa quando o texto aparece literalmente e nenhum elemento `[data-teste-xss]` é criado. Não use payloads que executam código nem que chamam domínios externos.
- **SQL injection**: use um valor com apóstrofo que mudaria a consulta se fosse concatenado, como `teste' OR '1'='1`. O teste passa quando o valor é tratado como texto: o filtro continua restrito e nenhum dado de outra conta aparece.
- **SSRF**: use servidores locais simulados (mocks) e endereços como `127.0.0.1`, `[::1]` e `169.254.169.254`, com o cliente HTTP interceptado. Nunca faça requisições reais a metadados de nuvem.
- **Prompt injection**: crie um documento fixture contendo uma instrução que tente fazer o agente usar uma ferramenta contra outra conta. O teste passa quando o backend nega a ação, independentemente do que o modelo pediu.

## 4. O ciclo "falha antes, passa depois"

1. Escreva o teste que descreve o comportamento **correto** (por exemplo: "A não pode ler o projeto de B").
2. Rode com o código atual. Ele deve **falhar**. A falha é a evidência; copie a saída.
3. Se o teste passar com o código atual, o achado não se confirmou. Reclassifique como descartado e registre o motivo. Ou o teste está errado: revise antes de concluir.
4. Proponha a correção. Com aprovação, aplique.
5. Rode de novo. O teste deve passar, junto com o teste do caso legítimo e com a suíte que já existia.

Use o framework de testes que o projeto já tem. Se não houver nenhum, proponha o mais comum da stack e peça autorização antes de instalar.

## 5. Testes-modelo

Os exemplos usam nomes genéricos de helpers (`criarUsuario`, `autenticarComo`). Adapte às fábricas, fixtures e forma de autenticação do projeto em vez de inventar uma estrutura paralela.

### Node.js (Vitest ou Jest + Supertest): autorização por objeto

```js
import request from 'supertest';
import { app } from '../src/app.js';
import { criarUsuario, criarProjeto, autenticarComo } from './helpers.js';

describe('projetos: cada conta só acessa os próprios', () => {
  let a, b, projetoDeB;

  beforeEach(async () => {
    a = await criarUsuario('usuario-a@exemplo.test');
    b = await criarUsuario('usuario-b@exemplo.test');
    projetoDeB = await criarProjeto({ dono: b, nome: 'Projeto secreto de B' });
  });

  it('nega leitura do projeto de outra conta', async () => {
    const res = await request(app)
      .get(`/api/projects/${projetoDeB.id}`)
      .set(await autenticarComo(a));
    expect([403, 404]).toContain(res.status);
    expect(JSON.stringify(res.body)).not.toContain('Projeto secreto de B');
  });

  it('nega edição e exclusão do projeto de outra conta', async () => {
    const auth = await autenticarComo(a);
    const editar = await request(app).patch(`/api/projects/${projetoDeB.id}`).set(auth).send({ nome: 'alterado' });
    const apagar = await request(app).delete(`/api/projects/${projetoDeB.id}`).set(auth);
    expect([403, 404]).toContain(editar.status);
    expect([403, 404]).toContain(apagar.status);
  });

  it('continua permitindo que B acesse o próprio projeto', async () => {
    const res = await request(app)
      .get(`/api/projects/${projetoDeB.id}`)
      .set(await autenticarComo(b));
    expect(res.status).toBe(200);
  });
});
```

### Python (pytest + TestClient do FastAPI): erro sem vazamento

```python
def test_erro_inesperado_nao_vaza_detalhes(client, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("detalhe interno: SELECT * FROM usuarios WHERE id=1")

    monkeypatch.setattr("app.servicos.pedidos.buscar_pedido", explode)
    r = client.get("/pedidos/1", headers={"Authorization": "Bearer token-de-teste"})

    assert r.status_code == 500
    corpo = r.text
    for proibido in ("SELECT", "Traceback", "RuntimeError", "/home/", "app/servicos"):
        assert proibido not in corpo
    assert "request_id" in r.json()  # permite correlacionar com o log interno


def test_erro_esperado_continua_util(client):
    r = client.get("/pedidos/nao-existe", headers={"Authorization": "Bearer token-de-teste"})
    assert r.status_code == 404  # erro esperado não pode virar 500 genérico
```

## 6. Ideias de teste por risco

| Risco | Caso negativo (deve ser bloqueado) | Caso positivo (deve funcionar) |
|---|---|---|
| Validação de entrada | Tipo errado, texto acima do limite, campo extra `role: "admin"`; nada é gravado | Payload válido é aceito e salvo |
| SQL injection | Valor com apóstrofo não altera o filtro de dono | Busca por nome com apóstrofo legítimo (`D'Ávila`) encontra o registro |
| XSS | Marcador HTML aparece como texto, sem criar elemento | Texto comum e acentuação renderizam normalmente |
| IDOR/BOLA | Conta A não lê, edita, apaga, lista nem baixa anexos de B | Cada conta acessa os próprios recursos |
| SSRF | `127.0.0.1`, `[::1]`, IP privado, redirecionamento para interno e DNS que muda são negados | Destino permitido responde |
| Senhas | Senha errada falha; mesma senha em duas contas gera hashes diferentes | Senha correta autentica |
| Rate limit | Exceder o limite retorna 429 | Depois da janela, volta a aceitar |
| Rotas admin | Sem sessão: 401. Usuário comum: 403 | Admin acessa |
| CAPTCHA | Token ausente, inválido, reutilizado ou com `action`/hostname errado é negado; provedor fora do ar não cria conta | Token válido (chave oficial de teste ou mock) passa |
| Erros | Exceção forçada não expõe stack, SQL, caminhos ou dados pessoais | 400, 401, 403 e 404 continuam com mensagens úteis |
| Supabase RLS | Cliente com chave pública logado como A não vê linhas de B | A vê as próprias linhas |
| Regras do Firebase | `assertFails` para leitura e escrita de outro usuário | `assertSucceeds` para o próprio documento |
| LGPD | Exclusão de conta não deixa dados pessoais em outras tabelas; logs não contêm CPF | Exportação traz os dados da própria pessoa |

## 7. Quando não dá para rodar

Às vezes não há banco local, as dependências não instalam ou o teste exige um serviço externo. Nesses casos:

- Escreva o teste mesmo assim e deixe-o no projeto, marcado com o motivo (por exemplo, `it.skip` com comentário explicando o que falta).
- Classifique o achado como **suspeita**, não como confirmado.
- Liste no relatório o passo exato para confirmar ("subir o Postgres com `docker compose up db` e rodar `npm test -- projetos`").
- Nunca preencha a saída de um teste que você não executou.
