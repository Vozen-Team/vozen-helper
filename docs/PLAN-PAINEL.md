# Plano — Painel web de controlo do Vozen Helper

> Historical plan: account IDs and CORS origins are generic examples. Fill in PANEL_ALLOWED_USER_ID and the exact HTTPS origin you control; dated test results are historical.

> Planeado em 2026-07-14. Painel atrás do login
> Discord já existente (site `vozen-helper-bot`, GitHub Pages) que controla A SÉRIO o bot
> que corre na VPS. **Planeamento only — não se escreve código nesta fase.**

## Objetivo

Um painel privado (só a conta `<PANEL_OWNER_DISCORD_ID>`) onde o Diogo **vê** o estado do bot
(casos, stats, config atual) e **altera** definições de moderação/comunidade **sem
redeploy**. Requer uma **API HTTP na VPS** ligada à SQLite do bot, com **HTTPS** acessível
a partir do origin `https://admin.example.com` e **auth real** via Discord OAuth.

**Assunções** (mudam a execução se erradas):

- O bot corre na VPS sob supervisor + cron `@reboot`, sem sudo (como o Vozen). A API segue o
  mesmo padrão (processo de utilizador, sem serviços de sistema).
- Usa-se **Cloudflare Tunnel** (`cloudflared`, grátis, sem sudo) para dar um URL HTTPS
  estável à API — resolve o HTTPS + alcance sem domínio próprio. Fallback: domínio + Caddy.
- A API é um serviço **novo e separado** do processo do bot, a partilhar o mesmo ficheiro
  SQLite (WAL + `busy_timeout`). Não se mete um servidor HTTP dentro do bot.
- O painel (UI) vive no repo do site `vozen-helper-bot`; a API e o refactor de settings
  vivem no repo do bot `Vozen-helper`.

## Scope

### In

- API HTTP (TypeScript, mesma stack do bot) na VPS: sessão via Discord OAuth, leitura de
  casos/stats/config, escrita de settings e ações de caso.
- **Camada de settings em runtime** no bot: tabela `settings` + resolver que sobrepõe
  overrides da BD sobre os defaults de `modConfig`; módulos passam a ler pelo resolver.
- Painel (SPA estática) atrás do gate: dashboard, moderação, comunidade, casos, definições.
- Exposição HTTPS via Cloudflare Tunnel + CORS trancado ao origin `https://admin.example.com`.
- Deploy da API (supervisor + cron `@reboot`) e do túnel.

### Out

- Multi-utilizador / permissões por cargo (é só 1 conta dona).
- Editar `modConfig` no código pelo painel (a config passa a ser overrides na BD, não edição
  de ficheiros + redeploy).
- Painel mobile-app nativo, notificações push, gráficos históricos ricos.
- Gerir vários servidores (o bot é single-guild).
- Domínio próprio / email / faturação (o túnel Cloudflare chega).

## Fases

### Fase 0 — Spike de alcance HTTPS (de-risk primeiro) ✅ FEITO (2026-07-14)

Deliverable: um endpoint trivial `GET /health` na VPS, servido por **HTTPS** através do
Cloudflare Tunnel, chamável do browser a partir de `https://admin.example.com`.
Dependências: nenhuma. **É aqui que se descobre cedo o maior desconhecido.**

- [x] Instalar `cloudflared` como binário de utilizador na VPS (sem sudo) e criar um túnel
      para um mini-servidor local (`GET /health` → `200 {ok:true}`), com CORS a permitir só o
      origin `https://admin.example.com`.
- [x] Da internet, `curl` ao URL do túnel devolve 200 `{ok:true}` sobre HTTPS; com header
      `Origin: https://admin.example.com` responde `Access-Control-Allow-Origin: https://admin.example.com`; origin não
      autorizado → sem esse header (trancado).
- **Done:** ✅ provado ponta-a-ponta (`https://<x>.trycloudflare.com/health` → `{ok:true}`,
  CORS ok). Spike desligado a seguir; bot intacto.

**Notas operacionais (Fase 0) — importam para a Fase 5:**

- **Persistência:** processos arrancados numa sessão SSH **são mortos** ao fechar a sessão
  (só cron/`atd` sobrevivem — o bot corre por `@reboot cron`). ⇒ a API + túnel de produção
  têm de ir para **cron `@reboot`** (ou supervisor lançado por cron), como o bot. No spike
  usou-se `at now` para os destacar.
- **Protocolo:** a VPS **bloqueia QUIC/UDP** (edge por QUIC falha); o `cloudflared` tem de
  correr com **`--protocol http2`** (fallback TCP), que liga bem.
- **Gotcha:** `pkill -f "cloudflared tunnel"` num script que contém essa string mata a
  própria shell remota — usar `pkill -x cloudflared` / `fuser -k <porta>/tcp`.
- Para produção o URL efémero `trycloudflare.com` não serve (muda a cada arranque): usar um
  **named tunnel** (precisa de conta Cloudflare grátis + `cloudflared login`) para URL fixo,
  ou colar o domínio quando existir.

### Fase 1 — API: esqueleto + autenticação real ✅ FEITO (2026-07-14)

Deliverable: serviço HTTP com sessão segura; só a conta permitida entra. Dep.: Fase 0.

- [x] Servidor HTTP (Fastify) no repo do bot (`src/api/`), processo separado, a abrir a
      SQLite do bot em leitura (`openReadOnly`, `busy_timeout`). Ouve só em `127.0.0.1`.
- [x] `POST /api/session`: recebe o Bearer token do Discord, chama `/users/@me` **no
      servidor** (`fetchDiscordUser`), confirma `id === PANEL_ALLOWED_USER_ID`, e emite cookie
      de sessão **assinado + httpOnly + Secure + SameSite=None**. Guarda protege `/api/me`.
- [x] CORS trancado ao `PANEL_ALLOWED_ORIGIN` (https://admin.example.com) com `credentials`.
- **Done:** ✅ 16 testes (inject) verdes: conta certa → 200+cookie; outra → 403; token
  inválido → 401; sem token → 400; Discord em baixo → 502; cookie forjado → 401.
  Suite completa 143/143, typecheck+build+lint limpos, boot local confirmado
  (`/health`, `/api/session`, `/api/me`). Ficheiros: `src/api/{config,discordAuth,db,
server,index}.ts`, `tests/api.test.ts`. Env novas em `.env.example` (`PANEL_*`).
  **Falta (Fase 5):** correr na VPS por cron `@reboot` + túnel — ainda não deployado.

### Fase 2 — Leitura: dados reais no painel (MVP) ✅ CÓDIGO FEITO (2026-07-14)

Deliverable: painel autenticado que mostra dados reais da VPS. Dep.: Fase 1 + UI base.

- [x] `GET /api/cases` (casos recentes do guild, teto 200) e `GET /api/stats`
      (mensagens/entradas/saídas + total de casos) — guardadas, SQL parametrizado, scoped ao
      `GUILD_ID`. Helpers `getRecentCases`/`countCases` em `store/cases.ts`.
- [x] Painel no site (`vozen-helper-bot`): o estado autorizado abre o painel (header +
      logout, cards de stats, tabela de casos com tags por tipo). `POST /api/session` com o
      token → cookie → `GET /api/stats` + `/api/cases`. **Degrada com elegância** se
      `API_BASE` estiver vazio (banner "API ainda não ligada") — não parte o login atual.
- **Done (código):** ✅ 22 testes API verdes (inclui cases/stats), suite 149/149,
  typecheck+lint limpos; painel verificado no browser (render de stats/casos + estado
  offline, sem erros de consola). **Falta para o MVP "ao vivo":** deploy da API na VPS +
  `API_BASE` apontado ao túnel (feito na Fase 5 / integração).

### Fase 3 — Bot: camada de settings em runtime ✅ FEITO (2026-07-14)

Deliverable: o bot passa a ler config sobreponível da BD. Dep.: antes da Fase 4.

- [x] Migração v6: tabela `settings (guild_id, key, value, updated_at)` (append-only).
- [x] Resolver `store/flags.ts`: `isFeatureEnabled` (hot-path, cache TTL 4s) +
      `getEffectiveFlags` (default do `modConfig` sob overrides da BD). Store `store/settings.ts`.
- [x] **10 guards** ligados: anti-spam/scam/nuke, join gate, raid, leveling, starboard,
      sugestões, tickets, bump reminder passam a ler pelo resolver (default = valor do modConfig).
- **Done:** ✅ escrever `flag.antispam=false` em `settings` desliga o anti-spam **sem
  redeploy** (o bot apanha via cache em ≤4s). Testado (5 testes settings/flags). Migração
  aplicada na VPS (user_version=6) e bot reiniciado (SIGKILL → supervisor respawn).

### Fase 4 — Escrita: o painel controla mesmo o bot ✅ FEITO (2026-07-14)

Deliverable: alterações no painel refletem-se no bot ao vivo. Dep.: Fases 2 + 3.

- [x] `GET /api/flags` (estado efetivo) + `PATCH /api/flags` — **allowlist** de chaves,
      validação de booleano, **rate-limit** (120/min), **auditoria** no api.log. DB read-write
      (`openApiDb`), só escreve `settings`.
- [x] Painel: secção **Definições** com toggles on/off por subsistema; PATCH otimista com
      reversão + banner de erro. Auth por token no header.
- **Done:** ✅ provado E2E no sistema live — PATCH autenticado → 200 → linha gravada em
  `settings` → bot reflete. 167 testes verdes, typecheck+lint limpos. API deployada.
  **Nota de segurança:** só toggles booleanos allowlisted (sem edição livre de config) para
  conter o risco da superfície de escrita exposta.

### Fase 5 — Deploy permanente + persistência ✅ FEITO (2026-07-14, parcial)

Deliverable: API + túnel a correr 24/7 na VPS, hands-off. Dep.: Fase 4.

- [x] API a correr na VPS (`dist/api/index.js`, 127.0.0.1:8788) + túnel Cloudflare quick
      tunnel (grátis, sem domínio — ngrok fixo passou a pago).
- [x] **Persistência hands-off:** cron `@reboot` corre `~/panel/panel-run.sh`, que arranca
      a API + túnel e **republica o URL** (efémero) em `site/api-url.js` do repo do site via
      **deploy key** (write). O site lê `window.API_BASE` desse ficheiro → segue sempre o URL
      atual, mesmo mudando em reinícios. Auth por **token no header** (à prova de Brave).
- **Done:** ✅ ciclo provado — reinício do túnel → novo URL → push automático → Pages
  redeploy → site aponta ao novo URL (`api-url.js` ao vivo confirmado). Sobrevive a reboots
  pelo cron.
- **Ainda em falta (endurecer):** rate limiting, validação estrita de input — deixado para
  antes/junto da Fase 4 (escrita), quando o risco sobe. Só-leitura por agora.

## UI Blueprint

Reutiliza os tokens da marca (já no site): dark `#05060f`, gradiente `#6672ff → #2ee6c8`,
fontes Unbounded/Outfit/JetBrains Mono, raio 22px, vidro `rgba(22,25,41,.72)`.

- **Layout:** o estado "acesso autorizado" do gate abre o **painel** — sidebar à esquerda
  (Dashboard · Moderação · Comunidade · Casos · Definições) + área de conteúdo. Responsivo:
  sidebar colapsa em topo/drawer < 720px.
- **Componentes:** cards de estado (stats), **toggles** para flags on/off, inputs para
  thresholds, **tabela** de casos com ações. Botão de logout limpa a sessão.
- **Estados (obrigatórios):** `loading` (skeletons), `empty` (sem casos), `error` (falha da
  API, com retry), `saving`/`saved` (feedback do PATCH), `403/expired` (volta ao login).
- **Acessibilidade:** foco visível, contraste AA, `prefers-reduced-motion`.

## Riscos

- **Config-as-code é o grande bloqueador da escrita.** Sem a Fase 3, o painel só LÊ config.
  "Alterar config a sério" = introduzir a camada de settings em runtime (refactor real,
  vários módulos). Assumido e faseado; é o item de maior esforço.
- **Expor a BD do bot à internet = risco alto.** Mesmo com 1 conta, um bug de auth/SQL =
  takeover do servidor. Exige auth verificada no servidor, CORS trancado, SQL parametrizado,
  allowlist de keys, rate limiting. Trata-se como superfície hostil.
- **Nunca confiar no browser.** O check de id do gate é cosmético; a API re-verifica o token
  com o Discord em cada sessão.
- **Dois processos numa SQLite.** Leitura concorrente com WAL é segura; escrita precisa de
  `busy_timeout` e disciplina (a API escreve em `settings`/casos; o bot lê). Validar cedo.
- **HTTPS sem domínio.** Resolvido pelo Cloudflare Tunnel (Fase 0). Se falhar na VPS →
  fallback domínio + Caddy/Let's Encrypt (custo pequeno, adia).
- **Token do Discord no browser.** Scope `identify` só revela o id; a sessão real é o cookie
  assinado da API, curto e revogável.

## Extra — Definições de canal (2026-07-14) ✅ FEITO

Além dos toggles, o painel escolhe **canais** por feature (settings `chan.*`/`xp.exclude`,
mesma allowlist/validação/auditoria):

- **Canal de logs** (override único p/ todas as categorias), **sugestões**, **starboard**.
- **Anúncios de nível**: canal específico OU "onde a pessoa falou" (`current`).
- **Excluir do XP**: multi-seleção de canais (`xp.exclude`, CSV).
- API: `GET /api/channels` (via token do bot, cache 30s) + `GET/PATCH /api/channel-settings`.
  Bot lê via `store/channelSettings.ts` (resolver com cache 4s). Painel: dropdowns.
- Provado E2E na VPS (lista 11 canais reais; PATCH grava; cleanup). 177 testes verdes.

**Nota (investigação stats):** stats a 0 **não era bug** — a contagem só ficou ativa
hoje e a última mensagem humana foi há 5 dias. Conta assim que houver mensagens novas.

## MVP

Fim da **Fase 2**: painel real, atrás do login, autenticado no servidor, a mostrar casos +
stats + config ao vivo da VPS (só-leitura). Já é útil e testável. O controlo a sério
(escrita) chega na Fase 4, depois do refactor de settings (Fase 3).

**Próxima ação concreta: instalar o `cloudflared` na VPS e abrir um túnel HTTPS para um
`GET /health` local, confirmando o `fetch` desde o origin https://admin.example.com sem erro de CORS (Fase 0).**
