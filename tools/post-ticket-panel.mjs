// Publica o painel de tickets no #suporte e confirma o nome do canal-contador.
// Uso: node tools/post-ticket-panel.mjs
import 'dotenv/config';
import {
  Client,
  GatewayIntentBits,
  Events,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ChannelType,
} from 'discord.js';

const TICKET_CHANNEL = process.env.HELPER_TICKET_PANEL_CHANNEL_ID?.trim() || '';
const COUNTER_CHANNEL = process.env.HELPER_TICKET_COUNTER_CHANNEL_ID?.trim() || '';

for (const [name, value] of [
  ['HELPER_TICKET_PANEL_CHANNEL_ID', TICKET_CHANNEL],
  ['HELPER_TICKET_COUNTER_CHANNEL_ID', COUNTER_CHANNEL],
]) {
  if (!/^[1-9]\d{16,19}$/.test(value) || BigInt(value) > 18446744073709551615n) {
    throw new Error(`${name} must be a valid Discord snowflake.`);
  }
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once(Events.ClientReady, async (c) => {
  const guild = await c.guilds.fetch(process.env.GUILD_ID);

  const counter = await guild.channels.fetch(COUNTER_CHANNEL).catch(() => null);
  console.log('contador:', counter?.name ?? '(não encontrado)');

  const ch = await guild.channels.fetch(TICKET_CHANNEL).catch(() => null);
  if (ch && ch.type === ChannelType.GuildText) {
    // Evitar duplicar: se já houver um painel do bot, não repõe.
    const recent = await ch.messages.fetch({ limit: 20 }).catch(() => null);
    const already = recent?.some((m) => m.author.id === c.user.id && m.components.length > 0);
    if (already) {
      console.log('painel de tickets já existe — não dupliquei.');
    } else {
      const embed = new EmbedBuilder().setTitle('Suporte').setDescription('Precisas de ajuda? Abre um ticket.').setColor(0x5865f2);
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('ticket:open').setLabel('Abrir ticket').setEmoji('🎫').setStyle(ButtonStyle.Primary),
      );
      await ch.send({ embeds: [embed], components: [row] });
      console.log('painel de tickets publicado.');
    }
  } else {
    console.log('canal de tickets não encontrado.');
  }

  await c.destroy();
  process.exit(0);
});

client.login(process.env.DISCORD_TOKEN);
