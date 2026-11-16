# Contribuir para o Vozen Helper

Regras e guia de desenvolvimento do **Vozen Helper** (bot de moderação privado).

## Comandos

- Instalar: `npm install`
- Build (typecheck + emit): `npm run build` (tsc)
- Typecheck com os testes: `npm run typecheck`
- Testes: `npx vitest run`
- Dev (watch): `npm run dev`
- Registar slash commands no guild: `npm run register`

## Regras

- **Single-guild / privado.** O bot só opera no `GUILD_ID` do `.env` — o guard em
  `src/bot/guildGuard.ts` fá-lo sair de qualquer outro servidor. Não introduzir
  multi-tenancy nem i18n.
- **Painel do dono (exceção sancionada, 2026-07-14).** Por decisão do dono, existe uma
  API de controlo em `src/api/` (processo SEPARADO do bot, `npm run start:api`) que serve
  um painel web privado (site `vozen-helper-bot`, GitHub Pages) acessível só a UMA conta
  Discord (`PANEL_ALLOWED_USER_ID`). Continua single-guild (só o `GUILD_ID`). Trata-se como
  superfície hostil: auth verificada no servidor, CORS trancado, SQL parametrizado. Plano e
  fases em `docs/PLAN-PAINEL.md`.
- **Licença AGPL-3.0-only.** Preservar o ficheiro `LICENSE` e os avisos e licenças
  dos componentes de terceiros.
- **TDD obrigatório.** Teste a falhar primeiro (RED) → código mínimo (GREEN) →
  refactor. Lógica pura em módulos testáveis (`config`, `guildGuard`, `db`,
  handlers) com testes em `tests/` nomeados a partir do módulo. Terminar sempre com
  `npx vitest run` + `npm run typecheck` verdes.
- **Comentários de código em português.**
- **Config-as-code.** Segredos/IDs de ambiente em `loadEnv` (validado no arranque);
  roles/canais/thresholds de moderação em `modConfig` (versionado, tipado).
- **Nunca ler nem commitar `.env`.** Usar `.env.example` como referência.
- **Migrações SQLite** em `src/store/db.ts` (`MIGRATIONS`): só ACRESCENTAR ao fim,
  nunca reordenar/editar as já lançadas (`PRAGMA user_version` controla o estado).

## Convenções

- TypeScript, `module: NodeNext`, `strict: true`. discord.js v14, better-sqlite3
  (WAL), vitest. Mesmas convenções do projeto irmão Vozen (bot TTS).
- Cada comando exporta `data` (SlashCommandBuilder) + `execute`, e regista-se em
  `src/commands/index.ts`.

## Princípio de moderação (ver `docs/`)

Delegar ao **AutoMod nativo** o bloqueio pré-publicação (slurs/keywords/mention
spam) via API; o bot implementa o que o nativo não cobre: warns/escalação,
anti-spam paramétrico, anti-raid por joins, anti-nuke via `GuildAuditLogEntryCreate`,
sticky roles e logging. Plano completo em `docs/PLAN.md`.
