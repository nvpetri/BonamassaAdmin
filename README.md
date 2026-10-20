# Bonamassa Admin · 0.1.1

Console técnico semelhante ao uso de consulta da APSDU: URL própria no Render, explorador de tabelas, filtros, paginação, relações, detalhes JSON, editor SELECT, auditoria e CSV.

## Arquitetura e permissões

Este repositório contém **interface e backend técnico** no mesmo Web Service Node 24. O navegador só chama seu próprio backend; não recebe credenciais do Neon. A API comercial continua na versão 0.13.1, sem alteração neste trabalho. O Admin consulta o mesmo PostgreSQL por credenciais específicas, sem depender do login da pizzaria.

- Conta técnica única configurada por ambiente; não aceita o usuário gerente, balcão ou cozinha. Acesso técnico global às lojas da base, sem isolamento por loja. Para consultar uma loja, filtre storeId.
- Sessão de 30 minutos, absoluta, cookie HttpOnly/SameSite=Strict/Secure em produção; logout revoga a sessão. Sessões ficam na memória: reinício exige novo login. Implantar uma instância; para múltiplas instâncias, implementar armazenamento compartilhado antes.
- Somente views autorizadas no schema bonamassa_admin. Não há edição, exclusão, alteração estrutural nem SQL de manutenção.
- O usuário bonamassa_admin_reader não acessa tabelas originais. O servidor recusa papéis com privilégios administrativos, associação a outros papéis, acesso a tabelas originais ou permissão de escrita.
- SELECT é analisado como árvore sintática e regenerado. Bloqueia múltiplos comandos, CTE, UNION, catálogos, funções externas, casts arbitrários e bloqueios. Permite filtros, JOIN, subconsulta SELECT, GROUP BY, agregações e funções básicas autorizadas. Use aspas duplas em tabelas/campos camelCase.
- Transação READ ONLY, tempo máximo de 5 segundos, até 200 linhas no editor e 100 por página no explorador; duas consultas simultâneas e até 2 MB por resposta.
- Campos de autenticação são omitidos nas views; e-mail/telefone do User e dados pessoais do pedido também. JSON é redigido recursivamente. Não é uma cópia integral do banco: ProductImage.bytes, Idempotency.response e outros campos sensíveis não estão disponíveis.
- Histórico append-only em bonamassa_admin_private.AdminAccessLog. Credencial logger só insere; reader só lê a view correspondente. Registra conta técnica, requestId, evento, resultado, tabelas, duração, linhas, SHA-256 da consulta, modelo SQL sem valores literais e hash do endereço do par de rede. Não armazena resultados nem SQL bruto com valores. O par de rede pode ser o proxy do Render; não representa identidade individual ou IP garantido do operador.
- Uma entrada started e outra completed/failed compartilham requestId. Falha de registro bloqueia execução/entrega do resultado. Falha entre execução e completed deixa started sem conclusão. Não há como o histórico de escrita da API capturar SELECT; o log técnico é separado.
- Exportar reexecuta a consulta; não é um snapshot da tela. Limite de 200 registros. No explorador, preserva a consulta/página atual. CSV neutraliza início de fórmulas.
- Os horários da API são UTC e valores financeiros são centavos.

## 1. Preparar o Neon

Faça isto na base de homologação desejada, já com as **8 migrations da API 0.13.1**. Confira a branch/database antes de executar.

1. Abra o SQL Editor do Neon como proprietário.
2. Execute o conteúdo completo de [db/001_admin.sql](db/001_admin.sql). Cria dois schemas próprios, views, log técnico e os papéis reader/logger. Não modifica tabelas da API.
3. Defina senhas longas, distintas e exclusivas para os dois papéis:

```sql
ALTER ROLE bonamassa_admin_reader PASSWORD 'SUBSTITUA_POR_UMA_SENHA_FORTE';
ALTER ROLE bonamassa_admin_logger PASSWORD 'SUBSTITUA_POR_OUTRA_SENHA_FORTE';
```

Não conceda neon_superuser ou associação a outros papéis. Não coloque neondb_owner nas variáveis do Admin.

4. Monte duas URLs para o mesmo host/database do Neon, cada uma usando seu usuário e senha. Codifique caracteres especiais da senha na URL. Para este serviço node-postgres use **sslmode=verify-full**, que verifica o certificado e hostname:

```text
postgresql://bonamassa_admin_reader:SENHA_CODIFICADA@HOST/neondb?sslmode=verify-full&connect_timeout=30
postgresql://bonamassa_admin_logger:OUTRA_SENHA_CODIFICADA@HOST/neondb?sslmode=verify-full&connect_timeout=30
```

Não reutilize as credenciais de proprietário da API. O script pode ser reaplicado para atualizar as views, preservando o log e as senhas. Alterações futuras no schema da API precisam de revisão das views e do contrato de relações.

## 2. Criar o acesso técnico

No seu computador, com Node 24:

```powershell
git clone https://github.com/nvpetri/BonamassaAdmin.git
cd BonamassaAdmin
npm ci
npm run password:hash
```

Digite uma senha exclusiva, de 12 a 128 caracteres. A entrada fica oculta. Copie o hash resultante scrypt$v1$...; não use a senha do gerente. A senha não é enviada a nenhum serviço por esse comando.

A primeira versão usa uma conta técnica. Para revogar sessões, reinicie o serviço. Para trocar a senha, gere novo hash e atualize a variável no Render.

## 3. Publicar no Render

Crie **New → Web Service**, conecte nvpetri/BonamassaAdmin e use:

| Configuração | Valor |
|---|---|
| Runtime | Node |
| Branch | main |
| Build Command | npm ci --omit=dev && npm run build |
| Start Command | npm start |
| Health Check Path | /health |
| Node | 24 |

O Render fornece a URL onrender.com. Após saber a URL exata, configure APP_ORIGIN com ela, sem barra final. Há também [render.yaml](render.yaml) para criação via Blueprint; plano free é uma opção de teste e pode suspender o serviço ocioso.

Variáveis:

| Variável | Conteúdo |
|---|---|
| NODE_ENV | production |
| APP_ORIGIN | https://NOME-DO-SERVICO.onrender.com |
| ADMIN_EMAIL | Seu e-mail técnico |
| ADMIN_PASSWORD_HASH | Hash gerado pelo comando, sem aspas adicionais no painel do Render |
| SESSION_SECRET | Chave aleatória de pelo menos 32 caracteres; o Blueprint gera |
| ADMIN_READ_DATABASE_URL | URL restrita do reader |
| ADMIN_AUDIT_DATABASE_URL | URL restrita do logger |

Para gerar SESSION_SECRET no computador:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Não configurar CORS na API comercial; este backend é independente. Nenhuma URL de banco, senha ou token deve ser publicado no repositório. As variáveis não têm prefixo NEXT_PUBLIC.

O servidor só sobe após validar banco, papéis e views. /health informa status do processo, versão e commit; não executa consulta a cada chamada. Não executa migrations, seed ou o script de permissões automaticamente.

## 4. Executar localmente

Copie .env.example para .env e preencha os valores. APP_ORIGIN deve ser http://localhost:3002. Para valores com # ou $, use aspas simples no arquivo .env. Execute npm start e abra a URL.

```powershell
Copy-Item .env.example .env
npm run build
npm test
npm start
```

## Exemplos

Pedidos recentes:

```sql
SELECT "number", "storeId", status, channel, total, "createdAt"
FROM "Order"
ORDER BY "createdAt" DESC
```

Auditoria de um pedido: use o explorador AuditTrail, filtro recordId igual ao UUID. sharedAccount identifica conta compartilhada; ela não comprova qual pessoa operou no balcão/cozinha. Para condições combinadas, use o editor:

```sql
SELECT id, "tableName", "recordId", operation, "actorName",
       "sharedAccount", "changedFields", "before", "after", "requestId", "createdAt"
FROM "AuditTrail"
WHERE "tableName" = 'Order' AND "recordId" = 'UUID_DO_PEDIDO'
ORDER BY id DESC
```

Consultas do Admin: tabela AdminAccessLog. Eventos query, browse, export, login, logout e catalog.

## Validação

GitHub Actions usa PostgreSQL 17 descartável, aplica as oito migrations da API fixada em ad0093049271d925aa49d899b86e58238abdb139, cria papéis restritos e verifica privilégios, JSON, consultas, filtros contra injeção, log imutável, autenticação, cookies, logout e falha fechada da auditoria. Playwright testa o navegador em desktop/mobile e publica capturas. Não acessa Neon ou Render reais.

Para integração local, TEST_DATABASE_URL precisa apontar **exatamente para /bonamassa_admin_test**, num PostgreSQL descartável já com migrations da API. Os testes criam papéis e dados; nunca usar a base da pizzaria.

O histórico técnico cresce com o uso; acompanhar espaço no Neon e definir retenção/arquivamento com backup antes de qualquer expurgo. Manter a conta técnica individual e restrita à equipe responsável.
