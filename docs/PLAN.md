# Plano de desenvolvimento — Vozen Helper (bot de moderação privado)

> Bot de moderação self-hosted, **single-guild** (apenas o servidor do Diogo), irmão do Vozen-bot. Baseado em `docs/RESEARCH-FEATURES-MODERACAO.md` e `docs/RESEARCH-DISCORD-API.md`.

## Objetivo

Ter um bot de moderação completo para UM servidor: ações de mod com casos e escalação, anti-spam, filtros de conteúdo (delegando ao AutoMod nativo o bloqueio pré-publicação), anti-raid com join gate, anti-nuke via audit log, anti-scam, sticky roles e logging total — tudo config-as-code, sem dashboard.

**Assunções**: corre na mesma máquina/regime do Vozen-bot; os privileged intents (`GUILD_MEMBERS`, `MESSAGE_CONTENT`) ligam-se livremente no portal (<100 servidores, sem review); o bot recebe o role mais alto possível abaixo do owner.

## Scope

### In

- Ações de moderação: warn, timeout, mute-role (>28d), kick, ban/tempban/softban/unban, purge — com **casos numerados** persistidos, histórico por utilizador, DM ao punido, razões no audit log (`X-Audit-Log-Reason`).
- Escalação automática por warns/strikes (thresholds → timeout → ban), configurável.
- Gestão das regras do **AutoMod nativo** via API (keywords/slurs/regex, mention spam) + consumo de `AUTO_MODERATION_ACTION_EXECUTION` para alimentar os strikes.
- Anti-spam próprio (o que o AutoMod não cobre): flood, duplicados, multi-canal, caps, emoji, newlines, invites, links com whitelist.
- Anti-scam/phishing: blacklist de domínios, lookalikes de `discord.gift`, resolução de redirects, heurística "mesmo link em ≥3 canais".
- Anti-raid: janela deslizante de joins, join gate (idade de conta, avatar, padrões de username), raid mode (subir verification level + `setIncidentActions` pausa invites/DMs), lockdown.
- Anti-nuke: contagem de ações destrutivas por executor via `GuildAuditLogEntryCreate` → quarentena (strip de roles) + whitelist do owner.
- Auto-roles: role on join (após `pending: false`), **sticky roles** (mute persistence), botão de verificação.
- Logging completo: deletes/edits (cache dimensionado), joins/leaves com idade de conta, voz, roles/nick, mod actions — canais separados por categoria, ignore lists.
- Utilitários: purge com filtros, slowmode, lock/unlock, userinfo/whois com casos, auto-dehoist/decancer, notas de staff.
- Guard de `GUILD_ID` único: o bot recusa qualquer guild que não a configurada (sai dela).

### Out

- Multi-tenancy, i18n, dashboard web, site, verificação Discord (nunca chega a 100 servidores).
- **Licença do código**: AGPL-3.0-only, conforme o ficheiro `LICENSE` na raiz.
- Fora de moderação: leveling/XP, música, tickets, starboard, giveaways, welcome decorativo.
- ML/AI: classificação NSFW de imagens, OCR de scams em imagem, deteção de toxicidade por LLM (candidatos a v2).
- Backups/restore automático do servidor (estilo Wick) — apenas alerta+quarentena nesta iteração.
- Fake permissions (mods só via bot, estilo Bleed) — os mods mantêm permissões nativas.

## Fases

### Fase 1 — Fundação

Deliverable: esqueleto do projeto a arrancar, ligado ao servidor, com DB e config. Dependências: nenhumas.

- [ ] Scaffold `Vozen-helper/`: TypeScript, `NodeNext` + `strict`, discord.js v14, better-sqlite3 (WAL), vitest — copiar convenções do Vozen (`CONTRIBUTING.md`, comentários em PT, `.env.example`)
- [ ] Cliente com intents: `Guilds, GuildMembers, GuildModeration, GuildMessages, MessageContent, AutoModerationConfiguration, AutoModerationExecution, GuildWebhooks, GuildInvites` (ligar privileged no portal)
- [ ] Guard single-guild: `GUILD_ID` no `.env`; `guildCreate` noutra guild → `guild.leave()`
- [ ] `config.ts` tipado (config-as-code): roles de mod, canais de log, thresholds — validado no arranque (falha rápida)
- [ ] Registo de slash commands no guild (instantâneo, sem global) + comando `/ping`
- [ ] Migrações SQLite versionadas + testes vitest do schema e do guard

**Done**: bot online no servidor, responde a `/ping`, sai de guilds estranhas (testado com mock), `npx vitest run` + `npm run typecheck` verdes.

### Fase 2 — Ações de moderação + casos

Deliverable: comandos de mod completos com case system. Dependências: Fase 1.

- [ ] Tabela `cases` (id sequencial, tipo, alvo, mod, razão, duração, timestamp) + `notes`
- [ ] `/warn /timeout /kick /ban /tempban /softban /unban /purge /modlogs /note /reason` (editar razão de caso)
- [ ] Checks de hierarquia ANTES de agir (`moderatable/kickable/bannable`) — evita 403 (limite Cloudflare); protected roles
- [ ] DM ao punido (razão+duração, falha silenciosa se DMs fechadas) + `reason` em todas as chamadas (audit log nativo)
- [ ] Scheduler persistente: tempban/unmute expiram mesmo após restart (varredura ao arrancar + timers)
- [ ] Escalação: N warns em janela → punição mapeada (strikes configuráveis por origem, estilo Vortex)
- [ ] TDD: testes de escalação, hierarquia, expiração de tempban

**Done**: cada comando cria caso numerado consultável via `/modlogs @user`; tempban expira após restart do bot (teste com clock falso).

### Fase 3 — AutoMod nativo + filtros de conteúdo

Deliverable: regras nativas geridas por código + strikes alimentados pelos triggers. Dependências: Fase 2 (strikes).

- [ ] Sync declarativo: regras AutoMod definidas em `config.ts` (keywords/wildcards/regex Rust, preset slurs, mention spam) → criadas/atualizadas via `guild.autoModerationRules` no arranque
- [ ] Respeitar limites: 6 regras KEYWORD, 1.000 keywords/regra, 10 regex de 260 chars; exempt roles/canais
- [ ] Listener `AutoModerationActionExecution` → registar infração + strike no case system (escalação da Fase 2)
- [ ] Filtro próprio complementar (pós-publicação): normalização anti-evasão (homóglifos/acentos), matching em embeds, attachments perigosos (.exe/.bat/.scr) — o que o AutoMod não faz
- [ ] TDD: testes do diff de sync (não recriar regras iguais) e da normalização

**Done**: apagar uma regra à mão no Discord e reiniciar o bot recria-a igual; mensagem bloqueada pelo AutoMod gera strike visível em `/modlogs`.

### Fase 4 — Anti-spam paramétrico

Deliverable: heurísticas de spam com escalação. Dependências: Fases 2–3.

- [ ] Janelas deslizantes por utilizador: flood (X msgs/Y s), duplicados, mass mentions, caps %, emoji, newlines, comprimento
- [ ] Invites `discord.gg` com whitelist; rate limit de links; heurística multi-canal (mesmo conteúdo em ≥3 canais → mute imediato)
- [ ] Pontuação tipo "heat" simplificada: violações somam, punição por total (menos falsos positivos que regras isoladas)
- [ ] Overrides por canal (ex.: mais brando em #off-topic) e isenção de roles de staff
- [ ] TDD: cada heurística com casos positivos/negativos e janelas de tempo falsas

**Done**: simulação em teste de 6 msgs/3s dispara timeout+caso; membro de staff nunca dispara (teste).

### Fase 5 — Logging completo

Deliverable: canais de log por categoria com conteúdo. Dependências: Fase 1 (a Fase 2 já loga casos; esta cobre o resto).

- [ ] Cache de mensagens dimensionado (`Options.cacheWithLimits` + sweepers + `Partials.Message`) para deletes/edits com conteúdo
- [ ] Logs: message delete/edit (antes/depois), bulk delete (ficheiro), join/leave (idade da conta, roles ao sair), voz, nick/roles/avatar, canais/roles/webhooks/emojis, bans/timeouts com executor (via `GuildAuditLogEntryCreate`)
- [ ] Atribuição "quem apagou": cruzar `messageDelete` com audit log 72 (aceitar imprecisão em self-deletes — documentar)
- [ ] Ignore lists (canais de staff) + log de automod dedicado
- [ ] TDD: formatação dos embeds de log e resolução de executor

**Done**: apagar/editar mensagem, entrar/sair, mudar nick e banir aparecem nos canais certos com executor correto (verificação manual no servidor + testes de formatação).

### Fase 6 — Anti-raid, join gate e verificação

Deliverable: defesa de entrada automática. Dependências: Fases 2 e 5.

- [ ] Join gate em `GUILD_MEMBER_ADD`: idade mínima de conta (snowflake), avatar default, padrões de username — ação por filtro (timeout/kick/ban)
- [ ] Deteção de surge: N joins em M segundos → **raid mode**: subir `verification_level`, `guild.setIncidentActions()` (pausar invites+DMs 24h), alertar mods, opcional kick dos joiners do lote
- [ ] `/lockdown` e `/unlock` (lista de canais na config) + saída manual de raid mode
- [ ] Verificação: role de acesso só após `pending: false` (nunca no join — pegadinha do screening) + botão "Verificar" como gate adicional
- [ ] Sticky roles: guardar roles ao sair, reaplicar no rejoin (mute persistence — anti-evasão)
- [ ] TDD: janela de joins com clock falso, sticky roles, transições de raid mode

**Done**: 10 joins simulados/18s ativam raid mode (invites pausados via API confirmado); rejoin de membro mutado volta mutado.

### Fase 7 — Anti-nuke

Deliverable: quarentena automática de contas/mods comprometidos. Dependências: Fases 2, 5, 6.

- [ ] Contadores por executor via `GuildAuditLogEntryCreate`: `CHANNEL_DELETE`, `ROLE_DELETE`, `MEMBER_BAN_ADD`, `MEMBER_KICK`, `WEBHOOK_CREATE` — thresholds por ação na config
- [ ] Resposta = **quarentena** (strip de todos os roles — timeout não funciona em admins), nunca ban automático; caso + alerta urgente ao owner; restauro manual `/unquarantine` (roles guardados)
- [ ] Whitelist (owner + IDs de confiança) — ações deles nunca disparam
- [ ] Anti bot-add: bot adicionado por não-whitelisted → kick do bot + quarentena de quem o adicionou
- [ ] Webhooks: criação suspeita → apagar webhook + quarentena do criador
- [ ] TDD extensivo: sequências de audit log simuladas, falsos positivos (mod a limpar 3 canais legítimos ≠ nuke)

**Done**: 5 channel-deletes simulados em 10s pelo mesmo executor não-whitelisted → roles removidos e owner alertado em <5s; executor whitelisted não dispara (testes).

### Fase 8 — Anti-scam + utilitários finais

Deliverable: camada anti-phishing e QoL de mod. Dependências: Fases 3–4.

- [ ] Blacklist de domínios de phishing (lista local atualizável) + lookalikes (`dlscord.gift` etc.) + resolução de redirects até ao destino final
- [ ] Impersonation de staff: username/avatar normalizados iguais aos de mods → alerta/rename
- [ ] Auto-dehoist/decancer de nicknames; `/slowmode`, `/userinfo` com casos, `/purge` com filtros (user/bots/links/regex)
- [ ] Honeypot channel opcional (postar lá → ban)
- [ ] Supervisor de produção (padrão do Vozen: `start:prod`, lock single-instance, auto-restart) + alerta quando o bot perde permissões necessárias

**Done**: link encurtado para domínio blacklisted é apagado com caso criado (teste com resolver mockado); bot sobrevive a crash com auto-restart.

## Riscos

- **Falsos positivos do anti-nuke a atingir mods legítimos** — o maior risco real. Mitigação: quarentena reversível em vez de ban, whitelist, thresholds altos no início, modo "alerta apenas" na primeira semana em produção.
- **Timeout não funciona em admins/dono** (403): a quarentena por strip de roles é o único caminho — exige o bot com role acima de todos os mods; se o role do bot descer, o anti-nuke fica cego. Alerta ativo quando isso acontecer.
- **Cache de mensagens para logging**: sem cache, deletes/edits perdem conteúdo; com cache excessivo, memória cresce. Dimensionar sweepers cedo (Fase 5) e aceitar lacunas documentadas.
- **Anti-raid single-server sem sinal cross-server** (o truque do Beemo): compensar com join gate agressivo + verificação — assumir que raids pequenos e lentos passam.
- **Regex do AutoMod é Rust, não JS**: padrões têm de ser validados contra engine Rust ou o `POST` devolve 400 — testar todos os regex da config no sync (Fase 3).
- **Invalid request limit da Cloudflare** (10k 401/403/429 em 10 min): num raid, verificar hierarquia antes de cada chamada em massa e usar `bulkCreate` (200 bans/request).
- **Auto-atribuição de "quem apagou" é imprecisa** (self-deletes sem audit log, entradas agregadas com `count`): aceitar e documentar, não prometer 100%.
- **Scope**: "tudo o que é preciso para moderar" tende a inchar — o Out list (ML, backups, fake permissions) é vinculativo nesta iteração.

## MVP

**Fim da Fase 4** (fundação + ações/casos + AutoMod nativo + anti-spam): a partir daqui o bot já modera o servidor no dia-a-dia — comandos com casos e escalação, slurs/keywords bloqueados pré-publicação, spam controlado. As Fases 5–8 acrescentam visibilidade (logging) e defesa contra eventos raros (raid/nuke/scam). Deploy no servidor real logo após a Fase 4, com as fases seguintes a entrar incrementalmente.

---

**Próxima ação concreta: criar o scaffold de `bots-discord/Vozen-helper/` (package.json com discord.js v14 + better-sqlite3 + vitest, tsconfig NodeNext strict copiado do Vozen, `.env.example` com `DISCORD_TOKEN`/`CLIENT_ID`/`GUILD_ID`) e pôr o bot a fazer login com o guard single-guild testado.**
