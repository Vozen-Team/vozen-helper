# Setup do Vozen Helper — do zero até 24/7 no VPS

> The scp command uses a fictional VPS hostname. Replace it and the local source path before running the example.

Guia completo: criar o bot no Discord (dá pelo telemóvel) e pô-lo a correr sempre
ligado no **mesmo VPS do Vozen**, como serviço separado. Muito mais simples que o
Vozen: **sem** ffmpeg, Piper, modelos, Caddy ou API web.

---

## Parte A — Criar o bot no Discord (telemóvel ✅)

1. **Nova aplicação:** https://discord.com/developers/applications → **New Application** → nome "Vozen Helper".
2. **Bot + token:** separador **Bot** → **Reset Token** → copia o **DISCORD_TOKEN**. Nunca o partilhes.
3. **Privileged intents:** ainda em **Bot**, liga **Server Members Intent** e **Message Content Intent**. (Como é <100 servidores, não precisa de review.)
4. **Client ID:** separador **General Information** → copia o **Application ID** = **CLIENT_ID**.
5. **Convidar para o servidor:** **OAuth2 → URL Generator** → scopes `bot` + `applications.commands` → permissões: `Kick Members`, `Ban Members`, `Moderate Members`, `Manage Messages`, `Manage Roles`, `Manage Channels`, `View Audit Log`, `Manage Guild` → abre o URL e adiciona ao teu servidor.
6. **GUILD_ID:** na app do Discord (telemóvel) → Definições → Avançado → liga **Modo de Programador**; mantém o dedo no ícone do servidor → **Copiar ID do Servidor** = **GUILD_ID**.
7. **Cargo do bot:** nas definições de cargos do servidor, arrasta o cargo do "Vozen Helper" para **acima de todos os moderadores** (mas abaixo de ti). Sem isto, o anti-nuke e os timeouts não funcionam.

---

## Parte B — Pôr o código no VPS

O código é **privado** (não open source). Duas formas de o levar ao VPS:

### Opção 1 — Repositório Git privado (recomendado, permite auto-deploy)

1. Cria um repositório **privado** no GitHub (ex.: `vozen-helper`) e faz push da pasta `bots-discord/Vozen-helper/`.
2. No VPS, gera uma deploy key e adiciona-a como **Deploy Key** (read-only) do repo no GitHub:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/vozen_helper_deploy -N ""
   cat ~/.ssh/vozen_helper_deploy.pub   # cola em GitHub → repo → Settings → Deploy keys
   ```
   E aponta o git para usar essa chave (ou usa um `~/.ssh/config` com `Host github-helper`).
3. Clona:
   ```bash
   cd ~ && git clone git@github.com:<user>/vozen-helper.git vozen-helper
   ```

### Opção 2 — Copiar direto do PC (mais rápido, sem auto-deploy)

Do PC (Git Bash), copia a pasta para o VPS (substitui o IP):

```bash
scp -r "C:/Users/diogo/Videos/second brain/bots-discord/Vozen-helper" vozen@vps.example.com:~/vozen-helper
```

> Antes de copiar, apaga `node_modules/` e `dist/` locais para ir leve — reconstroem-se no VPS.

---

## Parte C — Build, .env e serviço 24/7 (no VPS)

O VPS já tem o Node 22 e o utilizador `vozen` (do Vozen). Como `vozen`:

```bash
cd ~/vozen-helper
npm ci
npm run build
```

**`.env` de produção** (nunca commitar):

```bash
cp .env.example .env
nano .env
```

Preenche só três linhas:

```dotenv
DISCORD_TOKEN=<o token do bot>
CLIENT_ID=<o Application ID>
GUILD_ID=<o ID do teu servidor>
```

**Registar os slash commands** (uma vez, e sempre que mudar a lista de comandos):

```bash
npm run register
```

**Serviço systemd** (mantém ligado 24/7, reinicia sozinho):

```bash
sudo cp deploy/vozen-helper.service /etc/systemd/system/vozen-helper.service
sudo systemctl daemon-reload
sudo systemctl enable --now vozen-helper.service
sudo systemctl status vozen-helper.service   # deve dizer "active (running)"
sudo journalctl -u vozen-helper.service -f    # logs em direto (Ctrl+C sai)
```

Nos logs deves ver `Ligado como Vozen Helper#...` e `Vozen Helper pronto.`. Testa
`/ping` no servidor.

---

## Parte D — Afinar a config (depois de estar online)

Edita `src/config.ts` e cola os IDs do teu servidor (clica com o direito nos
canais/cargos → Copiar ID, com o Modo de Programador ligado):

- `logging.channels` — canais para os logs (`messages`, `members`, `voice`, `server`, `mod`).
- `verification.verifiedRoleId` — cargo dado após verificação (se usares o `/verify-panel`).
- `whitelistIds` — o teu ID e o de bots de confiança (isentos de automod/anti-nuke).
- `modRoleIds` — cargos de staff (isentos de anti-spam/filtros).
- `honeypotChannelId` — canal-armadilha (opcional).
- `nickname.protectedNames` — nomes de staff a proteger de impersonation.

Depois de editar: `npm run build && sudo systemctl restart vozen-helper.service`.

> **Recomendado na 1.ª semana:** deixa `antiNuke.alertOnly: true` (já é o default).
> O bot só ALERTA no canal de mod sem punir, para calibrares os limites sem atingir
> mods legítimos. Quando confiares, muda para `false`.

---

## Parte E (opcional) — Deploy automático

Se usaste a Opção 1 (repo privado), replica o que o Vozen já faz: um workflow
`.github/workflows/deploy-bot.yml` que faz SSH ao VPS a cada push, corre
`git pull && npm ci && npm run build && sudo systemctl restart vozen-helper.service`,
com os secrets `VPS_HOST`/`VPS_USER`/`VPS_SSH_KEY` e uma regra sudoers para o
restart sem password. Ver `Vozen-bot/docs/DEPLOY-VPS.md` §12 como referência.

---

## Checklist

- [ ] App criada no Discord, token + Client ID copiados
- [ ] Server Members + Message Content intents ligados
- [ ] Bot convidado, cargo acima dos mods
- [ ] GUILD_ID copiado
- [ ] Código no VPS (`~/vozen-helper`), `npm ci && npm run build` sem erros
- [ ] `.env` com os 3 valores
- [ ] `npm run register` corrido
- [ ] `vozen-helper.service` `active (running)`, `/ping` responde
- [ ] IDs de canais/cargos colados em `src/config.ts`
