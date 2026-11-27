# Inventário de dados pessoais — Vozen Helper (RGPD art. 30.º)

> Registo simplificado do tratamento de dados. Fase 1 do `PLAN-GDPR.md`.
> Responsável pelo tratamento (controller): o dono do bot/servidor.
> Terceiros (subcontratantes/destinatários): **Discord** (plataforma e IDs),
> **GitHub Pages** (aloja o site estático), **Cloudflare** (túnel da API),
> **host do VPS** (corre o bot + API + SQLite).

## Princípio

Quase tudo o que é "pessoal" aqui são **IDs de utilizador Discord** (snowflakes) — um
pseudónimo estável, não um nome civil. Não se recolhe email, telefone, morada, IP (o bot
não vê IPs; a API vê o IP no rate-limit mas não o persiste), nem o ano de nascimento
(aniversários guardam só dia/mês). É já um design minimizado; o trabalho é **documentar,
reter com prazo e dar direitos**.

## Tabela de tratamento (BD SQLite — `src/store/db.ts`)

| Tabela              | Dados pessoais                                               | Finalidade                                                 | Base legal                                         | Retenção proposta                                             |
| ------------------- | ------------------------------------------------------------ | ---------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------- |
| `cases`             | target_id, moderator_id, reason                              | Histórico de moderação (warns/bans/timeouts)               | Interesse legítimo (segurança do servidor)         | **2 anos** após o caso                                        |
| `activity_log`      | user_id, user_tag, actor_id, detail (convite/inviter/cargos) | Registo de atividade do painel (joins com convite, leaves) | Interesse legítimo (auditoria/segurança)           | **90 dias**                                                   |
| `notes`             | target_id, author_id, content                                | Notas de staff sobre um membro                             | Interesse legítimo                                 | **2 anos**                                                    |
| `infractions`       | target_id                                                    | Strikes que alimentam a escalação                          | Interesse legítimo                                 | **1 ano** (a escalação não precisa de histórico antigo)       |
| `scheduled_actions` | target_id, payload (reminder: texto+canal)                   | Expirações (tempban…) e lembretes                          | Interesse legítimo (mod) / ato voluntário (remind) | Apagar **ao executar** (já acontece); órfãos > 90 dias        |
| `sticky_roles`      | user_id, role_ids                                            | Repor cargos no rejoin (anti-evasão de mute)               | Interesse legítimo                                 | Apagar quando o membro sai **e** já não tem mute; senão 1 ano |
| `quarantine`        | user_id, role_ids, reason                                    | Restauro manual de cargos removidos (anti-nuke)            | Interesse legítimo                                 | **1 ano** (ou ao `/unquarantine`)                             |
| `suggestions`       | author_id, content                                           | Sugestões da comunidade                                    | Ato voluntário (o membro submeteu)                 | **1 ano** ou ao apagar a sugestão                             |
| `suggestion_votes`  | user_id, vote                                                | Um voto por pessoa                                         | Ato voluntário                                     | Enquanto a sugestão existir                                   |
| `afk`               | user_id, reason                                              | Estado AFK + razão                                         | Ato voluntário                                     | Apagar quando o membro volta (já acontece); órfãos 90 dias    |
| `tags`              | author_id                                                    | Autor da tag (staff)                                       | Interesse legítimo                                 | Enquanto a tag existir                                        |
| `birthdays`         | user_id, day, month                                          | Anúncio de aniversário (**sem ano**)                       | **Consentimento** (o membro optou por dar)         | Até o membro apagar ou sair                                   |
| `self_roles`        | — (só message/role/custom_id)                                | Mapa de botões de cargo                                    | N/A (sem dado pessoal)                             | Enquanto a mensagem existir                                   |
| `giveaways`         | host_id                                                      | Quem criou o giveaway                                      | Ato voluntário                                     | **90 dias** após terminar                                     |
| `giveaway_entries`  | user_id                                                      | Participantes                                              | Ato voluntário                                     | **90 dias** após terminar                                     |
| `levels`            | user_id, xp                                                  | XP/nível por membro                                        | Interesse legítimo (gamificação)                   | Apagar **quando o membro sai** do servidor                    |
| `tickets`           | opener_id, claimed_by                                        | Tickets de suporte                                         | Interesse legítimo                                 | **1 ano** após fechar                                         |
| `starboard`         | — (só message ids + contagem)                                | Mapa do starboard                                          | N/A                                                | Enquanto a mensagem existir                                   |
| `stats`             | — (**agregado por dia**, sem user_id)                        | /serverstats                                               | N/A (anónimo)                                      | **1 ano**                                                     |
| `settings`          | — (config do painel)                                         | Overrides de runtime                                       | N/A                                                | Permanente                                                    |
| `meta`              | —                                                            | Metadados da instalação                                    | N/A                                                | Permanente                                                    |

## Fora da BD

| Local                            | Dado                                                 | Finalidade                                  | Base legal                  | Retenção                                                    |
| -------------------------------- | ---------------------------------------------------- | ------------------------------------------- | --------------------------- | ----------------------------------------------------------- |
| DM de boas-vindas                | menção do próprio membro + contagem no texto enviado | Acolher o membro novo (welcome + mini-tour) | Interesse legítimo          | **Não persistido** (enviado no join, sem registo de envios) |
| `api.log` (VPS)                  | user_id do dono nas linhas de auditoria de escrita   | Auditoria de alterações no painel           | Interesse legítimo          | **30 dias** (rotação a criar)                               |
| Log do túnel (VPS)               | IPs de pedidos à API                                 | Diagnóstico do túnel Cloudflare             | Interesse legítimo          | **7 dias** / sem persistência                               |
| Cookie `vh_session` (browser)    | id do dono, assinado HMAC                            | Sessão do painel                            | **Estritamente necessário** | 8 h (expira sozinho)                                        |
| `localStorage vh_sess` (browser) | token de sessão + timestamp                          | Persistir sessão entre F5 (timeout 5 min)   | **Estritamente necessário** | Limpo no logout / 5 min inativo                             |
| Token OAuth Discord              | access token implícito                               | Verificar identidade no login               | **Estritamente necessário** | **Não persistido** (trocado por sessão e descartado)        |

## Helper em Rust: dados pessoais (desde 2026-11)

### Economia de quem sai (30 dias)

Quando um membro sai, é expulso ou banido, a sua economia (saldo, histórico, tempos de espera, encomendas, incluindo
as pendentes, e os avisos da loja dessas encomendas) fica guardada **30 dias** (decisão do dono de 25/11/2026). Fica
marcada na tabela `member_departures` (servidor, utilizador, hora da saída). Se o membro reentrar, a marca sai e fica
tudo como estava. Ao fim de 30 dias, a limpeza apaga a economia e a marca, salvo se houver sinal de que voltou:
entrada registada depois da saída, ou XP, comando, `/daily` ou recompensa mais de 5 minutos depois da saída. Enquanto
está fora, o membro não aparece no ranking de saldo. `/privacidade apagar` e apagar o servidor apagam logo a economia e
a marca.

### Saída de um membro e apagamento a pedido

**Quando um membro sai, é expulso ou banido**, apagam-se logo:
- votos em sugestões;
- participações em sorteios;
- votos em sondagens;
- lembretes;
- inscrições em eventos;
- estado AFK;
- níveis e eventos de XP;
- sessão de voz aberta;
- aniversário;
- tags e sugestões que criou.

As conquistas ficam (decisão do dono a 26/11). A economia tem regra própria (ver "Economia de quem sai").

**`/privacidade apagar`** apaga, além disso, as conquistas, a economia, a marca de saída e a atribuição de convite do
membro. Também retira o seu identificador das atribuições de quem ele convidou. A exportação inclui a atribuição de
convite (código e data), mas não quem convidou. Os registos de moderação ficam (art. 17.º/3-e).

**Apagar o servidor** apaga todos os dados desse servidor, incluindo as tabelas antigas do bot em Node (`notes`,
`sticky_roles`) quando existem. `invite_snapshots` guarda o criador de cada convite tal como o Discord o mostra; volta a
ser lido do Discord enquanto o convite existir e apaga-se com o servidor.

## Conclusões que alimentam as fases seguintes

- **Sem cookies não-essenciais → sem banner de consentimento.** O cookie e o localStorage
  são estritamente necessários; basta **divulgá-los na política** (Fase 2).
- **Decisão tomada (levels/stats):** `levels` apaga-se quando o membro sai; `stats` é
  agregado anónimo, retém-se 1 ano. Elimina o dado mais difícil de justificar.
- **Retenção a implementar (Fase 3):** purga diária por prazo + rotação do `api.log`.
- **Direitos (Fase 4):** exportação devolve o que é indexado por `user_id`, **exceto**
  dados de terceiros — as `notes` de staff (invisíveis ao membro) são omitidas e o
  `moderator_id` dos casos é redigido (art. 15.º/4 + considerando 63). O apagamento honra
  os dados de **ato voluntário/consentimento** e **recusa com fundamento** os de moderação
  (`cases`/`notes`/`infractions`/`quarantine`), ao abrigo do art. 17.º/3-e (defesa de
  direitos) e do interesse legítimo em segurança.
