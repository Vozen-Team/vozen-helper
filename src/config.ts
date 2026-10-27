// Configuração do Vozen Helper.
//
// Duas camadas:
//  1. `loadEnv` — segredos e IDs que variam por ambiente (token, guild), lidos do
//     ambiente e VALIDADOS no arranque (falha rápida com mensagem clara).
//  2. `loadModConfig` / `modConfig` - validated environment ID overrides with
//     backwards-compatible defaults; moderation thresholds remain versioned.

/** Níveis de log aceites (do menos ao mais severo). */
export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** Configuração vinda do ambiente, já validada. */
export interface EnvConfig {
  /** Token do bot. */
  token: string;
  /** Application/Client ID (para registar comandos). */
  clientId: string;
  /** ÚNICO guild onde o bot pode operar. */
  guildId: string;
  /** Caminho do ficheiro SQLite. */
  dbPath: string;
  /** Nível mínimo de log. */
  logLevel: LogLevel;
}

/** Lançada quando falta configuração obrigatória. Mensagem lista TODAS as faltas. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Valida e normaliza o ambiente. Função PURA (recebe o `env`, não lê `process`
 * diretamente) — testável sem tocar no ambiente real.
 *
 * Junta TODAS as variáveis em falta numa só mensagem, para o operador corrigir de
 * uma vez em vez de descobrir uma a uma.
 */
export function loadEnv(env: Record<string, string | undefined>): EnvConfig {
  const missing: string[] = [];

  const token = (env.DISCORD_TOKEN ?? '').trim();
  const clientId = (env.CLIENT_ID ?? '').trim();
  const guildId = (env.GUILD_ID ?? '').trim();

  if (!token) missing.push('DISCORD_TOKEN');
  if (!clientId) missing.push('CLIENT_ID');
  if (!guildId) missing.push('GUILD_ID');

  if (missing.length > 0) {
    throw new ConfigError(
      `Configuração em falta no ambiente: ${missing.join(', ')}. ` +
        'Copia o .env.example para .env e preenche estes valores.',
    );
  }

  // IDs do Discord são snowflakes: só dígitos, 17-20 chars. Validação leve para
  // apanhar erros de cópia (ex.: colar o token no lugar do ID).
  if (!/^\d{17,20}$/.test(clientId)) {
    throw new ConfigError(`CLIENT_ID não parece um ID do Discord válido: "${clientId}".`);
  }
  if (!/^\d{17,20}$/.test(guildId)) {
    throw new ConfigError(`GUILD_ID não parece um ID do Discord válido: "${guildId}".`);
  }

  const rawLevel = (env.LOG_LEVEL ?? 'info').trim().toLowerCase();
  const logLevel = (LOG_LEVELS as readonly string[]).includes(rawLevel)
    ? (rawLevel as LogLevel)
    : 'info';

  const dbPath = (env.DB_PATH ?? '').trim() || './vozen-helper.db';

  return { token, clientId, guildId, dbPath, logLevel };
}

// ─── Config-as-code (mod) ─────────────────────────────────────────────────────
// Placeholder tipado. As fases seguintes preenchem-no (roles de mod, canais de log,
// thresholds de anti-spam/anti-raid/anti-nuke). Fica aqui para o tipo existir e a
// validação de arranque crescer com o projeto.

/** Um degrau da escada de escalação: ao atingir `atStrikes` warns/strikes, aplica `action`. */
export interface EscalationStep {
  /** Nº de strikes acumulados (na janela) a partir do qual este degrau dispara. */
  atStrikes: number;
  /** Ação a aplicar. */
  action: 'timeout' | 'kick' | 'ban';
  /** Duração em ms (só para `timeout`; ignorado nos outros). */
  durationMs?: number;
}

/** Regras a delegar ao AutoMod NATIVO do Discord (bloqueio antes de publicar). */
export interface AutomodConfig {
  /** Keywords/wildcards a bloquear (ex.: 'scam*'). Máx. 1000. */
  advertisingKeywords: string[];
  /** Regexes Rust para links publicitários com domínio exato. Máx. 10. */
  advertisingRegexPatterns: string[];
  /** Ativar o preset de slurs (racismo/discurso de ódio) mantido pelo Discord. */
  enableSlurPreset: boolean;
  /** Ativar o preset de profanity. */
  enableProfanityPreset: boolean;
  /** Ativar o preset de conteúdo sexual. */
  enableSexualPreset: boolean;
  /** Limite de menções únicas por mensagem (null = não criar regra). Máx. 50. */
  mentionLimit: number | null;
  /** Proteção nativa contra rajadas coordenadas de menções. */
  mentionRaidProtectionEnabled: boolean;
}

/** Parâmetros do sistema de "heat" do anti-spam. */
export interface SpamConfig {
  enabled: boolean;
  windowMs: number;
  decayPerSec: number;
  punishAt: number;
  /** Ação ao punir: duração do timeout (ms). */
  timeoutMs: number;
  /** Janela usada para considerar uma punição de spam como reincidência. */
  repeatWindowMs: number;
  /** Teto do timeout progressivo por spam. */
  maxTimeoutMs: number;
  floodCount: number;
  floodHeat: number;
  duplicateHeat: number;
  multiChannelThreshold: number;
  multiChannelHeat: number;
  mentionLimit: number;
  mentionHeat: number;
  capsRatio: number;
  capsMinLength: number;
  capsHeat: number;
  emojiLimit: number;
  emojiHeat: number;
  newlineLimit: number;
  newlineHeat: number;
  linkLimit: number;
  linkHeat: number;
  inviteHeat: number;
}

export interface LanguageConfig {
  enabled: boolean;
  /** Palavrões comuns; slurs continuam exclusivamente no preset nativo. */
  terms: string[];
  windowMs: number;
  repeatedTermCount: number;
  excessiveTermCount: number;
}

/** Um par nível→cargo para as recompensas de leveling. */
export interface LevelRole {
  level: number;
  roleId: string;
}

/** Features de comunidade/engagement. Cada uma no-op quando não configurada. */
export interface CommunityConfig {
  suggestions: { enabled: boolean; channelId: string | null };
  welcome: { enabled: boolean; channelId: string | null; message: string };
  /** DM privada de boas-vindas + mini-tour ao membro novo (estilo Welcomer). */
  welcomeDm: { enabled: boolean; message: string };
  /** Canal de voz cujo nome é reescrito com a contagem de membros. */
  memberCounter: { channelId: string | null; template: string };
  leveling: {
    enabled: boolean;
    /** Canal dos anúncios de level-up (null = canal da mensagem). */
    announceChannelId: string | null;
    /** Canais que não dão XP. */
    noXpChannelIds: string[];
    minXp: number;
    maxXp: number;
    cooldownMs: number;
    /** Recompensas por nível. */
    levelRoles: LevelRole[];
    /** true = acumula cargos; false = substitui pelo mais alto. */
    stackRoles: boolean;
  };
  tickets: {
    enabled: boolean;
    /** Role de staff que vê todos os tickets. */
    staffRoleId: string | null;
    /** Canal para onde vão os transcripts ao fechar. */
    transcriptChannelId: string | null;
  };
  starboard: { enabled: boolean; channelId: string | null; threshold: number; emoji: string };
  birthdays: { enabled: boolean; channelId: string | null; roleId: string | null };
  /** Lembrete do /bump do DISBOARD (2h depois). */
  bumpReminder: { enabled: boolean; channelId: string | null };
}

export interface ModConfig {
  /** Canais onde os slash commands podem ser usados. Vazio = em qualquer canal. */
  commandChannelIds: string[];
  /** Roles cujos membros podem usar comandos de mod (além das permissões nativas). */
  modRoleIds: string[];
  /** Roles/utilizadores isentos de automod e anti-nuke (owner, bots de confiança). */
  whitelistIds: string[];
  /** Janela (ms) durante a qual os strikes contam para a escalação. Default 30 dias. */
  strikeWindowMs: number;
  /** Escada de escalação, ORDENADA por `atStrikes` crescente. */
  escalationLadder: EscalationStep[];
  /** Se true, envia DM ao punido com o motivo e a duração. */
  dmOnPunish: boolean;
  /** Regras do AutoMod nativo geridas pelo bot. */
  automod: AutomodConfig;
  /** Blocklist do filtro PRÓPRIO (pós-publicação, com normalização anti-evasão). */
  bannedWords: string[];
  /** Extensões de anexo perigosas a apagar (sem ponto). */
  dangerousExtensions: string[];
  /** Canais isentos do filtro próprio e do anti-spam. */
  automodExemptChannelIds: string[];
  /** Anti-spam (sistema de heat). */
  spam: SpamConfig;
  /** Linguagem: tolera uso casual isolado e modera abuso/repetição. */
  language: LanguageConfig;
  /** Features de comunidade/engagement (não-moderação). */
  community: CommunityConfig;
  /** Logging/auditoria. */
  logging: LogConfig;
  /** Join gate (filtros de entrada). */
  joinGate: JoinGateConfig;
  /** Anti-raid (deteção por taxa de joins). */
  raid: RaidConfig;
  /** Verificação e sticky roles. */
  verification: VerificationConfig;
  /** Anti-nuke (mods/bots comprometidos). */
  antiNuke: AntiNukeConfig;
  /** Anti-scam/phishing. */
  antiScam: AntiScamConfig;
  /** Moderação de nicknames (dehoist/decancer) e impersonation. */
  nickname: NicknameConfig;
  /** Canal-armadilha: quem lá escreve é banido (null = desligado). */
  honeypotChannelId: string | null;
}

export interface AntiScamConfig {
  enabled: boolean;
  /** Domínios de phishing conhecidos a apagar. */
  blacklistDomains: string[];
  /** Domínios protegidos contra typosquatting (discord.com, discord.gg, discord.gift). */
  protectedDomains: string[];
}

export interface NicknameConfig {
  /** Renomear nomes com hoisting/ilegíveis. */
  dehoistEnabled: boolean;
  /** Nome de substituição para nomes ilegíveis. */
  fallbackName: string;
  /** Nomes de staff a proteger contra impersonation (alerta). */
  protectedNames: string[];
}

export interface AntiNukeConfig {
  enabled: boolean;
  /** Modo de segurança: só ALERTA, não coloca em quarentena (recomendado na 1.ª semana). */
  alertOnly: boolean;
  /** Janela (ms) para contar ações destrutivas por executor. */
  windowMs: number;
  /** Nº de ações do mesmo tipo na janela que dispara a quarentena. */
  thresholds: {
    channelDelete: number;
    roleDelete: number;
    ban: number;
    kick: number;
    webhookCreate: number;
  };
  /** Kick + quarentena de quem adiciona um bot não autorizado. */
  quarantineBotAdds: boolean;
}

export interface JoinGateConfig {
  enabled: boolean;
  /** Idade mínima da conta (ms); 0 = desligado. */
  minAccountAgeMs: number;
  newAccountAction: 'none' | 'kick' | 'ban';
  requireAvatar: boolean;
  noAvatarAction: 'none' | 'kick' | 'ban';
  blockedUsernameSubstrings: string[];
  badUsernameAction: 'none' | 'kick' | 'ban';
}

export interface RaidConfig {
  enabled: boolean;
  joinWindowMs: number;
  joinThreshold: number;
  /** Duração do modo raid após o gatilho (ms). */
  raidModeMs: number;
  /** Subir o verification level do servidor durante o raid (0-4; null = não mexer). */
  raiseVerificationLevel: number | null;
  /** Pausar convites/DMs durante o raid (incident actions, máx. 24h). */
  pauseInvites: boolean;
  /** Canal para alertar a staff (null = usa o log de mod). */
  alertChannelId: string | null;
}

export interface VerificationConfig {
  /** Cargo dado a QUALQUER membro que entra (auto-role). null = off. */
  autoRoleId: string | null;
  /** Cargo dado só APÓS verificação (botão/screening). null = off. Gate opcional. */
  verifiedRoleId: string | null;
  /** Repor cargos guardados (sticky) quando o membro volta. */
  stickyRolesEnabled: boolean;
}

/** Categorias de log; cada uma vai para um canal (ou null = desligado). */
export type LogCategory = 'messages' | 'members' | 'voice' | 'server' | 'mod';

export interface LogConfig {
  /** Canal por categoria (null = não registar essa categoria). */
  channels: Record<LogCategory, string | null>;
  /** Canais cujo conteúdo NÃO se regista (ex.: canais de staff). */
  ignoreChannelIds: string[];
  /** Utilizadores cujas ações NÃO se registam. */
  ignoreUserIds: string[];
}

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;

// Optional ID overrides preserve legacy defaults when unset or blank.
function isSnowflake(value: string): boolean {
  return /^[1-9]\d{16,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
}

function idFromEnv(
  env: Record<string, string | undefined>,
  name: string,
  fallback: string,
): string {
  const value = env[name]?.trim() || fallback;
  if (!isSnowflake(value)) throw new ConfigError(`${name} must be a valid Discord snowflake.`);
  return value;
}

function idsFromEnv(
  env: Record<string, string | undefined>,
  name: string,
  fallback: string[],
): string[] {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const values = raw.split(',').map((value) => value.trim());
  if (!values.every(isSnowflake)) {
    throw new ConfigError(`${name} must contain comma-separated Discord snowflakes.`);
  }
  return values;
}

export function loadModConfig(env: Record<string, string | undefined>): ModConfig {
  const generalChannelId = idFromEnv(env, 'HELPER_GENERAL_CHANNEL_ID', '1523496056359489636');
  const suggestionsChannelId = idFromEnv(
    env,
    'HELPER_SUGGESTIONS_CHANNEL_ID',
    '1526360535501639771',
  );
  const starboardChannelId = idFromEnv(env, 'HELPER_STARBOARD_CHANNEL_ID', '1526360536705404948');
  const logChannelId = idFromEnv(env, 'HELPER_LOG_CHANNEL_ID', '1524488901320769666');
  return {
    // Comandos só no canal #mod-helper-bot.
    commandChannelIds: idsFromEnv(env, 'HELPER_COMMAND_CHANNEL_IDS', ['1526248625305292870']),
    // Staff isenta de automod/anti-spam/filtros: ⭐Developer + 👮Staff.
    modRoleIds: idsFromEnv(env, 'HELPER_MOD_ROLE_IDS', [
      '1523492883011997776',
      '1523499171246772355',
    ]),
    whitelistIds: [],
    strikeWindowMs: 30 * DAY,
    escalationLadder: [
      { atStrikes: 3, action: 'timeout', durationMs: HOUR },
      { atStrikes: 5, action: 'timeout', durationMs: DAY },
      { atStrikes: 7, action: 'ban' },
    ],
    dmOnPunish: true,
    automod: {
      advertisingKeywords: [],
      advertisingRegexPatterns: [
        '\\b(?:https?://)?(?:www\\.)?(?:discord\\.gg/\\S+|discord(?:app)?\\.com/(?:invite/\\S+|(?:api/)?oauth2/authorize\\S*))',
        '\\b(?:https?://)?(?:www\\.)?(?:youtube\\.com|youtu\\.be|tiktok\\.com|instagram\\.com|twitch\\.tv|twitter\\.com|x\\.com|facebook\\.com|kick\\.com)/\\S+',
      ],
      // Racismo/discurso de ódio: delegado ao preset nativo (bloqueia ANTES de publicar).
      enableSlurPreset: true,
      enableProfanityPreset: false,
      enableSexualPreset: true,
      mentionLimit: 8,
      mentionRaidProtectionEnabled: true,
    },
    bannedWords: [],
    dangerousExtensions: ['exe', 'bat', 'scr', 'cmd', 'com', 'pif', 'vbs', 'js', 'jar', 'msi'],
    automodExemptChannelIds: [],
    spam: {
      enabled: true,
      windowMs: 10_000,
      decayPerSec: 1,
      punishAt: 10,
      timeoutMs: 5 * 60 * 1000, // 5 min
      repeatWindowMs: 30 * DAY,
      maxTimeoutMs: DAY,
      floodCount: 5, // >5 mensagens em 10s soma calor
      floodHeat: 4,
      duplicateHeat: 4,
      multiChannelThreshold: 3,
      multiChannelHeat: 6,
      mentionLimit: 5,
      mentionHeat: 2,
      capsRatio: 0.7,
      capsMinLength: 10,
      capsHeat: 3,
      emojiLimit: 8,
      emojiHeat: 3,
      newlineLimit: 10,
      newlineHeat: 3,
      linkLimit: 3,
      linkHeat: 3,
      inviteHeat: 5,
    },
    language: {
      enabled: true,
      terms: [
        'fuck',
        'fucking',
        'fucked',
        'motherfucker',
        'shit',
        'bullshit',
        'bitch',
        'asshole',
        'bastard',
        'cunt',
        'dickhead',
      ],
      windowMs: 60_000,
      repeatedTermCount: 5,
      excessiveTermCount: 3,
    },
    logging: {
      // Tudo para o #mod-logs por agora (podes separar por canal quando quiseres).
      channels: {
        messages: logChannelId,
        members: logChannelId,
        voice: logChannelId,
        server: logChannelId,
        mod: logChannelId,
      },
      ignoreChannelIds: [],
      ignoreUserIds: [],
    },
    joinGate: {
      enabled: true,
      minAccountAgeMs: 3 * DAY, // contas com menos de 3 dias
      newAccountAction: 'none', // por defeito só regista; muda para 'kick' quando quiseres
      requireAvatar: false,
      noAvatarAction: 'none',
      blockedUsernameSubstrings: [],
      badUsernameAction: 'kick',
    },
    raid: {
      enabled: true,
      joinWindowMs: 10_000,
      joinThreshold: 8, // 8 joins em 10s
      raidModeMs: 10 * 60 * 1000,
      raiseVerificationLevel: 3, // HIGH
      pauseInvites: true,
      alertChannelId: null,
    },
    verification: {
      // Auto-role: toda a gente que entra recebe o ☀️Member.
      autoRoleId: idFromEnv(env, 'HELPER_AUTO_ROLE_ID', '1523498442653958294'),
      verifiedRoleId: null,
      stickyRolesEnabled: true,
    },
    antiNuke: {
      enabled: true,
      // Começa em modo alerta: observa e avisa sem punir, para calibrar thresholds sem
      // atingir mods legítimos. Passa a false quando tiveres confiança.
      alertOnly: true,
      windowMs: 10_000,
      thresholds: {
        channelDelete: 4,
        roleDelete: 4,
        ban: 5,
        kick: 5,
        webhookCreate: 3,
      },
      quarantineBotAdds: true,
    },
    antiScam: {
      enabled: true,
      blacklistDomains: [],
      protectedDomains: ['discord.com', 'discord.gg', 'discord.gift', 'discordapp.com'],
    },
    nickname: {
      dehoistEnabled: true,
      fallbackName: 'Member',
      protectedNames: [],
    },
    honeypotChannelId: null,
    community: {
      suggestions: { enabled: true, channelId: suggestionsChannelId },
      welcome: {
        enabled: false,
        channelId: null,
        message: 'Welcome {user} to **{server}**! You are member #{membercount}. 🎉',
      },
      welcomeDm: {
        // Texto voltado ao membro → em inglês (comunidade anglófona). Editável no painel.
        enabled: true,
        message:
          'Hey {user}, welcome to **{server}**! 🎉 You are member #{membercount}.\n\n' +
          "Here's a quick tour to get you started:\n" +
          `• <#${generalChannelId}> — general chat, come say hi!\n` +
          `• <#${suggestionsChannelId}> — drop your suggestions for the server\n` +
          `• <#${starboardChannelId}> — the best messages end up here ⭐\n\n` +
          'Have fun and make sure to read the rules. Any questions, reach out to the staff!',
      },
      memberCounter: {
        channelId: idFromEnv(env, 'HELPER_MEMBER_COUNTER_CHANNEL_ID', '1526361580487573635'),
        template: '📊 Members: {count}',
      },
      leveling: {
        enabled: true,
        announceChannelId: generalChannelId, // #general-chat
        noXpChannelIds: idsFromEnv(env, 'HELPER_NO_XP_CHANNEL_IDS', [
          '1526248625305292870',
          '1523486728042840124',
        ]), // mod-helper-bot, bot-testing
        minXp: 15,
        maxXp: 25,
        cooldownMs: 60_000,
        levelRoles: [
          { level: 5, roleId: idFromEnv(env, 'HELPER_LEVEL_5_ROLE_ID', '1526360728880283770') }, // 🥉 Nível 5
          { level: 10, roleId: idFromEnv(env, 'HELPER_LEVEL_10_ROLE_ID', '1526360730499285103') }, // 🥈 Nível 10
          { level: 20, roleId: idFromEnv(env, 'HELPER_LEVEL_20_ROLE_ID', '1526360731618906122') }, // 🥇 Nível 20
        ],
        stackRoles: false,
      },
      tickets: {
        enabled: true,
        staffRoleId: idFromEnv(env, 'HELPER_TICKET_STAFF_ROLE_ID', '1523499171246772355'),
        transcriptChannelId: idFromEnv(
          env,
          'HELPER_TICKET_TRANSCRIPT_CHANNEL_ID',
          '1526362020041981992',
        ),
      },
      starboard: { enabled: true, channelId: starboardChannelId, threshold: 3, emoji: '⭐' },
      birthdays: { enabled: false, channelId: null, roleId: null },
      bumpReminder: { enabled: true, channelId: generalChannelId },
    },
  };
}

export const modConfig: ModConfig = loadModConfig(process.env);
