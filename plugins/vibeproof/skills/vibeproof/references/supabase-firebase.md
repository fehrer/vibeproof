# Supabase e Firebase

Nos dois serviços, o navegador fala **direto com o banco**. Isso muda tudo: não existe um backend seu no meio para checar permissões. O controle de acesso mora nas políticas de RLS (Supabase) ou nas Security Rules (Firebase). Se elas estiverem abertas, qualquer pessoa com a chave pública, que é visível no site, lê e escreve o que quiser. É a causa número um de vazamentos em apps feitos com vibe coding.

## Sumário
1. Supabase: o que verificar
2. Supabase: como provar
3. Firebase: o que verificar
4. Firebase: como provar

## 1. Supabase: o que verificar

**RLS ligado em toda tabela exposta.** Tabelas no schema `public` (e em qualquer schema exposto pela API) precisam de `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` e de políticas. Sem RLS, a chave pública dá acesso total. Procure nas migrations (`supabase/migrations/*.sql`) tabelas criadas sem o `ENABLE ROW LEVEL SECURITY` correspondente, e qualquer `DISABLE ROW LEVEL SECURITY`.

**Políticas que realmente restringem.**
- `USING (true)` ou políticas para o papel `anon` em tabelas com dados pessoais.
- Políticas para cada operação: `SELECT`, `INSERT`, `UPDATE` e `DELETE`.
- Em `UPDATE`, o `USING` define quais linhas a pessoa pode alterar e o `WITH CHECK` define como a linha pode ficar. Se o `WITH CHECK` for omitido, o Postgres reaproveita o `USING` para as duas coisas. O problema aparece quando o `WITH CHECK` é mais frouxo que o `USING` (por exemplo, `with check (true)`), o que permite gravar a linha com outro dono.
- **RLS controla linhas, não colunas.** Quem pode editar a própria linha pode editar **qualquer coluna** dela. Se a tabela `profiles` tem `role`, `plano`, `creditos` ou `is_admin`, o usuário consegue se promover com um simples `update`. Proteja colunas sensíveis com permissão por coluna (`REVOKE UPDATE` na tabela e `GRANT UPDATE (nome, avatar)` só nas colunas editáveis) ou mova esses campos para uma tabela que o usuário não altera.
- Filtro por `auth.uid()` (ou pelo tenant da pessoa) em todas as políticas que deveriam ser por dono.

**Papel nunca vem de `user_metadata`.** O `user_metadata` (`raw_user_meta_data` no banco) pode ser alterado pelo próprio usuário pela API de autenticação. Políticas ou checagens que usam esse campo para decidir papel ou plano permitem que qualquer um se promova. Use `app_metadata` (só o servidor altera) ou uma tabela de papéis protegida por RLS.

**A chave `service_role` (ou `sb_secret_...`) só no servidor.** Ela ignora RLS. Se aparecer no frontend, em variável `NEXT_PUBLIC_`/`VITE_`, no app mobile ou no repositório, é achado **crítico**: qualquer pessoa ganha acesso total ao banco. A chave `anon` (ou `sb_publishable_...`) é pública por design e só é aceitável se o RLS estiver correto.

**Views.** No Postgres, uma view executa por padrão com as permissões de quem a criou e pode ignorar o RLS das tabelas por trás dela. Em Postgres 15 ou superior, use `WITH (security_invoker = true)`, ou não exponha a view no schema público.

**Funções `SECURITY DEFINER`.** Rodam com privilégios do dono e, no schema `public`, podem ser chamadas via RPC. Confira se checam `auth.uid()` internamente e se definem `search_path`. Prefira mantê-las em um schema não exposto.

**Storage.** Buckets marcados como públicos servem qualquer arquivo para quem tiver a URL. Buckets privados precisam de políticas em `storage.objects` que restrinjam por dono (geralmente pelo caminho do arquivo).

**Edge Functions.** Verifique se validam o JWT e se usam a chave `service_role` só depois de checar quem chama.

**Ferramentas do próprio Supabase.** O painel tem um Security Advisor que aponta tabelas sem RLS e outros problemas comuns. Não dá para acessá-lo daqui; liste como item "não verificado" para a pessoa conferir.

## 2. Supabase: como provar

**Pela leitura das migrations**, mostre a tabela, a política (ou a falta dela) e o arquivo e a linha.

**Com o projeto local** (`supabase start`, se a CLI já estiver instalada), confira o estado do RLS:

```sql
select schemaname, tablename, rowsecurity
from pg_tables
where schemaname = 'public'
order by tablename;
```

**Teste de comportamento**, usando a chave **anon** (nunca a `service_role`) e duas contas de teste:
- Logado como A, tente `select` nas linhas de B. Deve voltar vazio.
- Tente `update` trocando o `owner_id` para B. Deve falhar.
- Tente `update` na coluna `role` (ou `plano`, `creditos`) do próprio perfil. Deve falhar.
- Tente `insert` com `owner_id` de B. Deve falhar.
- Altere o próprio `user_metadata` para `{ "role": "admin" }` e tente uma ação de admin. Deve falhar.
- Caso positivo: A lê e edita as próprias linhas.

Se não houver ambiente local, classifique como suspeita, com base nas migrations, e liste esses testes como próximo passo.

## 3. Firebase: o que verificar

**Regras abertas.** Em `firestore.rules`, `storage.rules` e `database.rules.json`:
- `allow read, write: if true;` ou o equivalente `".read": true` / `".write": true` no Realtime Database.
- O "modo de teste" com data de validade (`request.time < timestamp.date(...)`): libera tudo até a data e depois quebra o app, levando alguém a "consertar" abrindo de vez.
- `if request.auth != null` sozinho: qualquer conta criada (e criar conta costuma ser livre) acessa os dados de todos.

**Regras por dono.** O padrão é comparar `request.auth.uid` com o dono do documento:
- leitura, edição e exclusão olham `resource.data`;
- criação e edição olham `request.resource.data`, para impedir que alguém grave um documento em nome de outra pessoa.

**Validação de campos.** Sem checar os campos gravados, o cliente pode incluir `role: "admin"` ou mudar `ownerId`. Use `request.resource.data.keys().hasOnly([...])` e valide tipos e tamanhos.

**Regras não são filtros.** Uma consulta que poderia retornar documentos não permitidos é negada inteira. Se o app "funciona", talvez seja porque as regras estão abertas.

**SDK Admin só no servidor.** O Admin SDK ignora as regras. A credencial de conta de serviço (`*-firebase-adminsdk-*.json`, `serviceAccountKey.json`) nunca vai para o frontend nem para o repositório.

**Chave da configuração web.** O `apiKey` do Firebase no frontend é público por design. Mesmo assim, recomende restringir a chave no console do Google Cloud (APIs e domínios permitidos) e ativar o App Check como camada antiabuso.

**Cloud Functions.** Funções HTTP (`onRequest`) precisam checar autenticação manualmente. Funções `onCall` recebem o contexto de auth, mas ainda precisam checar permissão.

## 4. Firebase: como provar

**Pela leitura das regras**, mostre o arquivo, a linha e o que ela permite.

**Com o Emulator Suite e a biblioteca `@firebase/rules-unit-testing`**, se já estiverem no projeto (peça antes de instalar):

```js
import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';
import { readFileSync } from 'node:fs';
import { doc, getDoc, setDoc } from 'firebase/firestore';

const env = await initializeTestEnvironment({
  projectId: 'demo-auditoria',
  firestore: { rules: readFileSync('firestore.rules', 'utf8') },
});

const a = env.authenticatedContext('usuario-a').firestore();
const b = env.authenticatedContext('usuario-b').firestore();

await env.withSecurityRulesDisabled(async (ctx) => {
  await setDoc(doc(ctx.firestore(), 'projetos/p1'), { ownerId: 'usuario-b', nome: 'de B' });
});

await assertFails(getDoc(doc(a, 'projetos/p1')));                                          // A não lê o de B
await assertFails(setDoc(doc(a, 'projetos/p2'), { ownerId: 'usuario-b', nome: 'falso' })); // A não grava em nome de B
await assertSucceeds(getDoc(doc(b, 'projetos/p1')));                                       // B lê o próprio
```

O prefixo `demo-` no `projectId` garante que o emulador não toca em nenhum projeto real.
