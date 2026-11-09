# Vozen Helper

Bot público de Discord para moderação, automação e comunidade, multi-guild e
self-hosted. É um produto independente do Vozen TTS, Music e RPG: partilha apenas
o contrato central de entitlements.

> **Licença do código: AGPL-3.0-only.** Consulta o ficheiro [LICENSE](LICENSE).
> Os componentes de terceiros conservam as respetivas licenças e avisos.

## Módulos

O Helper organiza-se por guild e por módulo: Core, Studio, Security, Support,
Events, Community, Automate e Insights. Inclui casos de moderação, anti-raid,
quarantine com restauro de cargos, tickets, polls, giveaways, leveling, tags,
workflows bounded e endpoints de auditoria/privacidade.

O runtime de produção é Rust (Serenity + Axum + SQLite WAL). O painel React/Vite
é local e usa OAuth Discord com PKCE, estado de uso único e sessões HttpOnly.
Node permanece apenas como rollback durante o soak, não como gateway concorrente.

O plano e a evidência de rollout estão em [`docs/PLAN.md`](docs/PLAN.md),
[`deploy/PARITY-MATRIX.md`](deploy/PARITY-MATRIX.md) e
[`deploy/ROLLBACK.md`](deploy/ROLLBACK.md). A política de moderação está em
[`docs/MODERATION-POLICY.md`](docs/MODERATION-POLICY.md).

## Stack e gates locais

Rust 1.97 · Serenity 0.12 · Axum · SQLite WAL · React/Vite local. O legado
TypeScript/discord.js continua no repositório apenas para rollback controlado.

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

## Arranque Rust

```sh
cargo run -p vozen-helper
```

Configura o `.env` a partir de [`.env.example`](.env.example). O painel local é
descrito em [`docs/PLAN-PAINEL.md`](docs/PLAN-PAINEL.md); não é publicado pelo
workflow do Helper.

## Segurança e permissões

- Ativa `Server Members Intent` e `Message Content Intent` no Developer Portal.
- Dá ao bot um role acima dos moderadores, mas abaixo do owner, para que
  quarantine, restauro e timeouts respeitem a hierarquia do Discord.
- Usa OAuth2 com `bot` e `applications.commands`; o painel não aceita tokens do
  Discord no browser.
- Nunca executar Node e Rust com o mesmo token ao mesmo tempo. O procedimento de
  rollback está em [`deploy/ROLLBACK.md`](deploy/ROLLBACK.md).

## Planos e entitlements

O serviço central resolve o acesso dos quatro produtos Vozen. Para o Helper:
Plus custa €1,99; Premium custa €3,99 para 3 guilds ou €7,99 para 8 guilds.
O Free continua disponível com quotas menores. A atribuição é validada por guild
e por utilizador, com replay rejection e isolamento entre tenants.

## Estado de rollout

O branch de migração mantém uma matriz de paridade explícita em
[`deploy/PARITY-MATRIX.md`](deploy/PARITY-MATRIX.md). O goal só pode ser fechado
depois de o release Rust estar funcional na VPS e passarem os gates de memória,
segurança, paridade, rollback e soak de sete dias.
