# Exemplo vulnerável (NÃO USE EM PRODUÇÃO)

App mínimo **propositalmente inseguro**, usado para testar a skill `vibeproof`.
Todas as chaves e senhas aqui são fictícias.

Para testar no Claude Code, abra esta pasta e peça:

```
/vibeproof audite este projeto
```

Falhas plantadas (não leia antes de testar, se quiser medir a skill às cegas):
segredo em variável pública do Vite, SDK de IA no navegador, SQL concatenado, IDOR,
atribuição em massa, XSS por innerHTML, SSRF, hash MD5 de senha, erro com stack trace,
rota admin sem autenticação, CORS aberto com credenciais, CPF em log, tabela Supabase sem RLS,
papel lido de user_metadata, view sem security_invoker, regras do Firestore abertas,
Dockerfile como root com segredo em ENV, banco exposto no compose, workflow com
pull_request_target e injeção de script, credencial em .mcp.json e um comentário
tentando manipular o auditor.
