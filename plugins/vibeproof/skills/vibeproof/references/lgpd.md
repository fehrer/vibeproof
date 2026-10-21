# LGPD e dados pessoais no código

A Lei Geral de Proteção de Dados (Lei 13.709/2018) vale para qualquer app que trate dados de pessoas no Brasil. Esta referência cobre o que dá para **verificar no código**. Ela não substitui orientação jurídica: questões de base legal, contratos e política de privacidade são do encarregado (DPO) ou de um advogado. Diga isso no relatório quando o achado depender de interpretação jurídica. As normas da ANPD mudam: confira a versão vigente no site da autoridade antes de citar prazos.

## Sumário
1. Conceitos que importam para o código
2. Inventário de dados pessoais
3. O que verificar
4. Como provar
5. Incidentes: o que o relatório deve lembrar

## 1. Conceitos que importam para o código

- **Dado pessoal**: qualquer informação que identifica ou permite identificar uma pessoa: nome, e-mail, CPF, telefone, endereço, IP, identificadores de dispositivo, localização.
- **Dado pessoal sensível** (art. 5º, II): origem racial ou étnica, convicção religiosa, opinião política, filiação sindical ou a organização religiosa, filosófica ou política, saúde, vida sexual, dado genético ou biométrico. Tem regras mais rígidas (art. 11) e merece proteção reforçada no código.
- **Dados de crianças e adolescentes** (art. 14): exigem tratamento no melhor interesse deles e, para crianças, consentimento específico de um dos pais ou responsável.
- **Princípios** (art. 6º) que viram requisito técnico: **finalidade** e **necessidade** (coletar só o necessário para um propósito definido), **segurança** e **prevenção** (medidas técnicas para evitar incidentes), **transparência** e **livre acesso** (a pessoa consegue saber o que você tem dela).
- **Direitos do titular** (art. 18) que exigem funcionalidade no sistema: confirmação e acesso, correção, anonimização, bloqueio ou eliminação de dados desnecessários, portabilidade, eliminação de dados tratados com consentimento, informação sobre compartilhamento e revogação do consentimento.
- **Segurança** (art. 46): medidas técnicas e administrativas aptas a proteger os dados. Os outros 11 riscos desta skill são, na prática, a parte técnica desse artigo.

## 2. Inventário de dados pessoais

Antes de procurar problemas, descubra quais dados pessoais o sistema guarda e por onde eles passam:

- Schemas e migrations (`schema.prisma`, `models.py`, `supabase/migrations`, entidades do ORM): colunas como `cpf`, `rg`, `nome`, `email`, `telefone`, `celular`, `endereco`, `cep`, `data_nascimento`, `ip`, `localizacao`, `foto`, e qualquer campo de saúde, biometria ou dado sensível.
- Integrações que recebem esses dados: analytics, CRM, e-mail marketing, monitoramento de erros, provedores de IA, pagamento.
- Lugares onde os dados podem ficar sem querer: logs, filas, caches, backups, buckets de arquivos, exportações.

Inclua esse inventário resumido no relatório. Ele é útil para a pessoa mesmo sem nenhum achado.

## 3. O que verificar

**Minimização e exposição.**
- APIs devolvendo o objeto inteiro do usuário (com CPF, telefone, hash de senha) quando a tela usa só o nome. Procure `select *`, retornos de entidades completas e serialização sem lista de campos.
- Coleta de dados que nenhuma funcionalidade usa.
- CPF, e-mail, telefone ou tokens em **URLs** (query string). URLs ficam em logs de servidor, de proxy e do navegador, e no header `Referer`.
- Documentos exibidos inteiros onde bastaria mascarar (`***.456.789-**`).

**Logs e monitoramento.**
- `console.log`, `logger.*` e `print` registrando body de requisição, objetos de usuário ou campos pessoais.
- Ferramentas de monitoramento de erros configuradas para enviar dados pessoais por padrão (no Sentry, por exemplo, `sendDefaultPii: true`).
- Prompts e respostas de IA guardados com dados pessoais e sem prazo de retenção.

**Compartilhamento com terceiros.**
- Analytics recebendo e-mail, nome, CPF ou telefone (`identify`, `track`, `gtag` com esses campos).
- Dados pessoais enviados a provedores de IA ou outros serviços no exterior. Transferência internacional tem regras próprias (art. 33 e regulamento específico da ANPD). Sinalize como ponto para validação jurídica e verifique tecnicamente se o envio é necessário, se há minimização e se a pessoa foi informada.

**Direitos do titular.**
- Existe forma de a pessoa **excluir a conta**? A exclusão apaga ou anonimiza os dados em **todas** as tabelas relacionadas, nos arquivos (storage) e nos serviços terceiros? Ou só marca `ativo = false`? (Retenção por obrigação legal é legítima, mas deve ser intencional e documentada.)
- Existe forma de **exportar** os próprios dados e de **corrigi-los**?
- Se a base legal é consentimento: há registro de quando e para qual versão da política a pessoa consentiu? A revogação funciona e tem efeito real no sistema?

**Retenção.** Há rotina para apagar dados que não são mais necessários (contas inativas, logs antigos, leads)? Ausência de qualquer política de retenção é achado de melhoria.

**Proteção reforçada.**
- Dados sensíveis e de crianças com controle de acesso mais restrito.
- Criptografia em trânsito (HTTPS obrigatório, conexões com banco usando TLS) e, quando cabível, em repouso.
- Trilha de auditoria de quem acessou dados pessoais em painéis administrativos.

## 4. Como provar

- **Exposição em API**: teste que chama a rota e verifica que campos como `cpf`, `passwordHash` ou `telefone` não aparecem na resposta quando a tela não precisa deles.
- **Logs**: mostre a linha que registra o dado e um exemplo mascarado do que seria gravado. Em teste, capture a saída do logger durante uma requisição com dados fictícios e verifique a ausência do CPF de teste.
- **Exclusão de conta**: crie uma conta de teste com dados em várias tabelas e arquivos, acione a exclusão e consulte cada tabela. O teste passa quando não sobra dado pessoal fora do que a retenção legal justifica.
- **Terceiros**: mostre o ponto do código que envia o dado e quais campos vão.

Use sempre documentos fictícios gerados por algoritmo (veja `metodo-de-evidencia.md`).

## 5. Incidentes: o que o relatório deve lembrar

Se a auditoria encontrar indício de que dados pessoais **já foram expostos** (segredo de banco público há meses, bucket aberto, RLS desligado em produção), não trate só como bug:

- Recomende preservar evidências e logs.
- Recomende avaliar o incidente com o encarregado ou com orientação jurídica.
- Lembre que o regulamento de comunicação de incidentes da ANPD (Resolução CD/ANPD nº 15/2024) prevê comunicação à autoridade e aos titulares em **três dias úteis** quando o incidente puder causar risco ou dano relevante. Agentes de pequeno porte têm prazo em dobro, e os incidentes devem ficar registrados por pelo menos cinco anos. Confira a regra vigente.
- Não afirme se houve ou não incidente reportável. Isso depende de fatos (acessos, logs) que a auditoria de código não alcança.
