# Plano — Ativar as features de comunidade no Vozen Support

> Historical configuration plan: channel/category IDs are placeholders, not server identifiers. Replace each placeholder with the corresponding ID from your own server.

> Planeado em 2026-07-13. O bot e as features já estão
> no VPS; isto é o plano de CONFIGURAÇÃO (canais, cargos, IDs) para as tornar vivas.

## Objetivo

Ligar as 6 features inertes — sugestões, contador de membros, níveis+cargos,
tickets, starboard, bump reminder — criando os canais/cargos em falta de forma
AUTOMATIZADA (o bot tem `Manage Channels`/`Manage Roles`) e preenchendo o
`community` do `src/config.ts`, com deploy no VPS no fim.

## Estado atual do servidor (2026-07-13)

Canais existentes relevantes: `general-chat` (`<GENERAL_CHAT_CHANNEL_ID>`) ·
`mod-logs` (`<MOD_LOGS_CHANNEL_ID>`) · `mod-helper-bot` (`<HELPER_MOD_CHANNEL_ID>`) ·
`bug-report` (forum) · categoria "Canais de Texto" (`<TEXT_CATEGORY_ID>`) ·
categoria "Canais de Voz" (`<VOICE_CATEGORY_ID>`) · categoria "Mod Room" (`<MOD_ROOM_CATEGORY_ID>`).

Cargos: 👑Vozen(9) · Vozen helper(8, bot) · ⭐Developer(7) · 👮Staff(6) ·
🌸Premium(5) · 🚀Boosters(4) · ☀️Member(3) · 🤖Other bots(2) · Top.gg(1).

**Em falta**: canal de sugestões, canal de starboard, canal de voz-contador,
canal de painel de tickets, canal de transcripts, cargos de nível.

## Scope

### In

- Criar 4 canais + 1 canal de voz + 3 cargos de nível (via script one-shot com o token do bot).
- Preencher `modConfig.community` com os IDs; build + deploy + restart no VPS.
- Painéis publicados (`/ticket-panel`) e verificação de cada feature.

### Out

- Boas-vindas e aniversários (REMOVIDOS a pedido do Diogo — não recriar).
- Self-roles `/rolepanel` (já funciona sem config; o Diogo publica painéis quando quiser).
- Mudanças de lógica/features novas; XP de voz; rank cards em imagem.

## Fases

### Fase 1 — Criar a infraestrutura no Discord (script one-shot)

Deliverable: canais e cargos criados, IDs impressos.

- [ ] Script `tools/setup-community.mjs` (usa DISCORD_TOKEN/GUILD_ID do .env; correr LOCALMENTE uma vez):
  - [ ] Texto `₊˚ʚ💡୧﹕sugestões` na categoria "Canais de Texto" — escrita bloqueada para @everyone (só o bot posta; membros usam /suggest)
  - [ ] Texto `₊˚ʚ⭐୧﹕destaques` (starboard) na mesma categoria — escrita bloqueada para @everyone
  - [ ] Texto `₊˚ʚ🎫୧﹕suporte` na mesma categoria — para o painel de tickets (threads privadas nascem daqui)
  - [ ] Texto `₊˚ʚ📄୧﹕transcripts` na categoria "Mod Room" — só staff vê
  - [ ] Voz `📊 Membros: 0` no topo da categoria de voz — connect bloqueado para @everyone
  - [ ] Cargos (abaixo do bot, sem permissões extra): `🥉 Nível 5`, `🥈 Nível 10`, `🥇 Nível 20`
  - [ ] Idempotente: se um canal/cargo com o mesmo nome já existir, reutiliza e imprime o ID
- **Done**: script imprime o mapa nome→ID completo, sem erros.

### Fase 2 — Preencher a config

Deliverable: `src/config.ts` com o bloco `community` real. Dependências: Fase 1 (IDs).

- [ ] `suggestions.channelId` = #sugestões
- [ ] `memberCounter.channelId` = canal de voz 📊; `template: '📊 Membros: {count}'`
- [ ] `leveling.announceChannelId` = #general-chat (servidor pequeno — canal dedicado seria deserto); `levelRoles: [{5,🥉},{10,🥈},{20,🥇}]`; `stackRoles: false` (substitui — mostra só o marco mais alto); `noXpChannelIds: [mod-helper-bot, bot-testing]` (anti-farm em canais de bot)
- [ ] `tickets.staffRoleId` = 👮Staff; `tickets.transcriptChannelId` = #transcripts
- [ ] `starboard.channelId` = #destaques (threshold 3 fica — servidor pequeno)
- [ ] `bumpReminder.channelId` = #general-chat — NOTA: só dispara se o bot do DISBOARD estiver no servidor (hoje não está; fica armado e inerte, custo zero)
- **Done**: typecheck verde; IDs todos validados contra o output da Fase 1.

### Fase 3 — Deploy + ativação

Deliverable: features vivas no servidor. Dependências: Fase 2.

- [ ] `npm run build` + `npx vitest run` verdes localmente
- [ ] tar do `src` → VPS, build no VPS, restart do bot (método habitual: matar o filho, supervisor sobe)
- [ ] Publicar o painel de tickets: `/ticket-panel` no #suporte
- **Done**: bot online (`Vozen Helper pronto` no log), contador de voz renomeado com o nº real.

### Fase 4 — Verificação feature a feature

Deliverable: prova de que cada uma funciona.

- [ ] `/suggest teste` → embed #1 em #sugestões, votos 👍/👎 respondem
- [ ] Contador de voz mostra "📊 Membros: N" correto
- [ ] Mensagem no #general-chat dá XP; `/rank` responde; (o level-up 5 só se testa com uso real)
- [ ] Botão "Abrir ticket" cria thread privada; Fechar gera transcript no #transcripts
- [ ] 3 ⭐ numa mensagem → aparece em #destaques
- [ ] `/serverstats` responde
- **Done**: checklist toda verde; pedir ao Diogo para confirmar visualmente.

## Riscos

- **Permissões do script**: criar canais/cargos exige `Manage Channels`/`Manage Roles` — o bot tem ambas; se algum overwrite falhar (ex.: connect do canal de voz), criar na mesma e avisar, não abortar.
- **Cargos de nível acima do bot**: o script cria-os automaticamente ABAIXO do cargo do bot — sem risco de hierarquia.
- **Starboard em servidor pequeno**: threshold 3 pode banalizar os destaques; é config de 1 linha se o Diogo quiser subir para 4–5.
- **Bump reminder inerte**: sem o bot DISBOARD no servidor nunca dispara — comportamento esperado, não é bug.
- **Level-ups no #general-chat**: se vier a incomodar, muda-se `announceChannelId` para um canal dedicado (1 linha).

## MVP

Fim da Fase 3: tudo configurado e vivo. A Fase 4 é a prova.

**Próxima ação concreta: escrever `tools/setup-community.mjs` (Fase 1) e corrê-lo uma vez para criar os canais/cargos e obter os IDs.**
