import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import {
  api,
  type ActivityRecord,
  type AuditRecord,
  type CaseRecord,
  type CustomCommand,
  type Feature,
  type FeatureConfig,
  type FeatureSchema,
  type ExternalProvider,
  type ExternalSubscription,
  type Guild,
  type GuildContext,
  type LeaderboardEntry,
  type Me,
  type QuickSetupState,
  type QuickSetupStepKey,
  type RankCardConfig,
  type ReminderRecord,
  type RolePanelRecord,
  type RssSubscription,
  type RssSubscriptionHealth,
  type StudioTemplate,
  type TwitchSubscription,
  type TwitchSubscriptionHealth,
  type WorkflowRecord,
  type YouTubeSubscription,
  type YouTubeSubscriptionHealth,
} from './api';
import { docsProviderStatusUrl, docsTroubleshootingUrl, docsUrlForFeature } from './docs';

const defaultRankCard: RankCardConfig = {
  font: 'system',
  primary_color: '#8EE5D2',
  text_color: '#F4F7FB',
  background_color: '#101725',
  overlay_opacity: 0.36,
  background_preset: null,
  background_url: null,
  background_data: null,
  avatar_ring_color: '#8EE5D2',
  avatar_ring_width: 4,
};
const swatches = ['#8EE5D2', '#7F9CF5', '#F6AD55', '#F687B3', '#A78BFA', '#F4F7FB'];
const presetOptions = [
  ['aurora-lake', 'Aurora Lake', './rank-card-banners/banner-01-aurora-lake.png'],
  ['neon-rain', 'Neon Rain', './rank-card-banners/banner-02-neon-rain.png'],
  ['enchanted-forest', 'Enchanted Forest', './rank-card-banners/banner-03-enchanted-forest.png'],
  ['desert-ruins', 'Desert Ruins', './rank-card-banners/banner-04-desert-ruins.png'],
  ['coral-cavern', 'Coral Cavern', './rank-card-banners/banner-05-coral-cavern.png'],
  ['sky-islands', 'Sky Islands', './rank-card-banners/banner-06-sky-islands.png'],
  ['volcanic-forge', 'Volcanic Forge', './rank-card-banners/banner-07-volcanic-forge.png'],
  ['moonlit-village', 'Moonlit Village', './rank-card-banners/banner-08-moonlit-village.png'],
  ['starship-hangar', 'Starship Hangar', './rank-card-banners/banner-09-starship-hangar.png'],
  ['lavender-storm', 'Lavender Storm', './rank-card-banners/banner-10-lavender-storm.png'],
] as const;
// Production builds must talk to the Rust API even when GitHub Pages does not
// inject Vite environment variables. Local preview is opt-in so a missing build
// variable cannot silently hide the real catalogue and guild state.
const localPreviewMode =
  (import.meta.env.VITE_HELPER_LOCAL_PREVIEW as string | undefined)?.toLowerCase() === 'true';

type Category =
  'all' | 'protection' | 'community' | 'management' | 'utility' | 'social' | 'growth' | 'web3';
type Route = {
  page: 'overview' | 'features' | 'activity' | 'rank-card' | 'quick-setup' | 'detail';
  key?: string;
};
type ProviderSubscriptionHealth =
  RssSubscriptionHealth | TwitchSubscriptionHealth | YouTubeSubscriptionHealth;
type FieldSpec = {
  key: string;
  label: string;
  kind:
    | 'toggle'
    | 'text'
    | 'number'
    | 'select'
    | 'textarea'
    | 'tags'
    | 'channel'
    | 'category'
    | 'channels'
    | 'role'
    | 'roles';
  help?: string;
  options?: Array<[string, string] | string>;
  min?: number;
  max?: number;
  maxLength?: number;
  step?: number;
  advanced?: boolean;
};
type SectionSpec = { title: string; description: string; fields: FieldSpec[] };

// The API adapter owns the schema.  Persisted settings can outlive a schema
// revision, so remove fields that no longer have a runtime projection before
// they reach the editor or a subsequent publish.  Provider adapters with an
// intentionally empty schema keep their dedicated subscription payload intact.
function configForSchema(
  schema: FeatureSchema,
  defaults: FeatureConfig,
  stored: FeatureConfig,
): FeatureConfig {
  const fields = schema.sections.flatMap((section) => section.fields);
  if (fields.length === 0) return { ...defaults, ...stored };
  const supported = new Set(fields.map((field) => field.key));
  return Object.fromEntries(
    Object.entries({ ...defaults, ...stored }).filter(([key]) => supported.has(key)),
  );
}

const pages = [
  { id: 'overview', label: 'Painel', icon: '⌂', hint: 'Visão geral' },
  { id: 'quick-setup', label: 'Quick Setup', icon: '✧', hint: 'Configuração guiada' },
  { id: 'features', label: 'Funcionalidades', icon: '✦', hint: 'Configurar módulos' },
  { id: 'activity', label: 'Atividade', icon: '◷', hint: 'Histórico do servidor' },
  { id: 'rank-card', label: 'XP card', icon: '▣', hint: 'Níveis e identidade' },
] as const;
const categories: { id: Category; label: string }[] = [
  { id: 'all', label: 'Todas' },
  { id: 'protection', label: 'Proteção' },
  { id: 'community', label: 'Comunidade' },
  { id: 'management', label: 'Gestão' },
  { id: 'utility', label: 'Utilidades' },
  { id: 'social', label: 'Alertas sociais' },
  { id: 'growth', label: 'Crescimento' },
  { id: 'web3', label: 'Web3' },
];
const demoGuilds: Guild[] = [{ id: 'demo', name: 'Servidor de demonstração', canManage: true }];
const demoFeatures: Feature[] = [
  {
    key: 'protection.antispam',
    label: 'Proteção contra spam',
    description: 'Deteta flood, mensagens repetidas, excesso de menções, links e caps.',
    category: 'protection',
    capability: 'security',
    available: true,
    enabled: true,
  },
  {
    key: 'protection.antiscam',
    label: 'Proteção contra fraude',
    description: 'Bloqueia links suspeitos, convites e padrões de phishing.',
    category: 'protection',
    capability: 'security',
    available: true,
    enabled: true,
  },
  {
    key: 'protection.anti_raid',
    label: 'Anti-raid',
    description: 'Responde a entradas anormais e protege o servidor.',
    category: 'protection',
    capability: 'security',
    available: true,
    enabled: false,
  },
  {
    key: 'protection.join_gate',
    label: 'Proteção de entradas',
    description: 'Aplica verificações básicas a novos membros.',
    category: 'protection',
    capability: 'security',
    available: true,
    enabled: false,
  },
  {
    key: 'community.levels',
    label: 'Níveis e XP',
    description: 'Recompensa conversa saudável com XP e níveis.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'community.leaderboard',
    label: 'Leaderboard de XP',
    description: 'Mostra a progressão da comunidade com privacidade configurável.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'community.starboard',
    label: 'Starboard',
    description: 'Destaca mensagens populares da comunidade.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'community.suggestions',
    label: 'Sugestões',
    description: 'Recolhe ideias e deixa a comunidade votar.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'community.giveaways',
    label: 'Giveaways',
    description: 'Cria sorteios com entradas rastreáveis.',
    category: 'community',
    capability: 'events',
    available: true,
    enabled: false,
  },
  {
    key: 'support.tickets',
    label: 'Tickets',
    description: 'Organiza pedidos de suporte num só lugar.',
    category: 'management',
    capability: 'support',
    available: true,
    enabled: false,
  },
  {
    key: 'support.welcome',
    label: 'Boas-vindas',
    description: 'Recebe novos membros com uma mensagem guiada.',
    category: 'management',
    capability: 'core',
    available: true,
    enabled: false,
  },
  {
    key: 'support.welcome_channel',
    label: 'Canal de boas-vindas',
    description: 'Organiza regras, informação e primeiros passos para quem chega.',
    category: 'management',
    capability: 'core',
    available: true,
    enabled: false,
  },
  {
    key: 'management.nickname',
    label: 'Nickname',
    description: 'Define o nome que o Helper mostra neste servidor.',
    category: 'management',
    capability: 'core',
    available: true,
    enabled: false,
    maturity: 'operational',
    configurable: true,
  },
  {
    key: 'management.workflows',
    label: 'Automações',
    description: 'Liga um gatilho a uma resposta sem código.',
    category: 'management',
    capability: 'automate',
    available: true,
    enabled: false,
  },
  {
    key: 'management.polls',
    label: 'Enquetes',
    description: 'Publica votações simples para decisões rápidas.',
    category: 'management',
    capability: 'events',
    available: true,
    enabled: false,
  },
  {
    key: 'insights.stats',
    label: 'Canais de estatísticas',
    description: 'Acompanha atividade e tendências do servidor.',
    category: 'management',
    capability: 'insights',
    available: true,
    enabled: false,
  },
  {
    key: 'studio.rank_card',
    label: 'XP card',
    description: 'Personaliza a carta de nível mostrada no Discord.',
    category: 'community',
    capability: 'studio',
    available: true,
    enabled: true,
  },
];
const additionalFeatures: Feature[] = [
  {
    key: 'management.moderation',
    label: 'Moderador',
    description: 'Centraliza regras, avisos e ações de moderação do servidor.',
    category: 'management',
    capability: 'security',
    available: true,
    enabled: false,
  },
  {
    key: 'management.custom_commands',
    label: 'Comandos personalizados',
    description: 'Cria respostas reutilizáveis para perguntas e rotinas da comunidade.',
    category: 'management',
    capability: 'automate',
    available: true,
    enabled: false,
  },
  {
    key: 'management.audit',
    label: 'Auditoria e permissões',
    description: 'Acompanha alterações importantes e mantém a equipa alinhada.',
    category: 'management',
    capability: 'security',
    available: true,
    enabled: false,
  },
  {
    key: 'management.privacy',
    label: 'Privacidade e dados',
    description: 'Consulta, exporta e elimina os dados do teu servidor com segurança.',
    category: 'management',
    capability: 'core',
    available: true,
    enabled: false,
  },
  {
    key: 'management.templates',
    label: 'Modelos e importação',
    description: 'Guarda uma configuração e reutiliza-a noutro servidor.',
    category: 'management',
    capability: 'core',
    available: true,
    enabled: false,
  },
  {
    key: 'community.role_panels',
    label: 'Painéis de cargos',
    description: 'Deixa os membros escolherem cargos através de painéis simples.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'community.events',
    label: 'Eventos do servidor',
    description: 'Cria eventos, inscrições e check-ins sem sair do painel.',
    category: 'community',
    capability: 'events',
    available: true,
    enabled: false,
  },
  {
    key: 'community.achievements',
    label: 'Conquistas',
    description: 'Cria metas e celebra marcos da comunidade.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'management.invite_tracker',
    label: 'Rastreador de convites',
    description: 'Percebe quem trouxe novos membros para o servidor.',
    category: 'management',
    capability: 'insights',
    available: true,
    enabled: false,
  },
  {
    key: 'utility.help',
    label: 'Ajuda',
    description: 'Explica os módulos e mostra o próximo passo para cada equipa.',
    category: 'utility',
    capability: 'core',
    available: true,
    enabled: true,
  },
  {
    key: 'utility.reminders',
    label: 'Temporizadores',
    description: 'Agenda lembretes para mensagens, tarefas e eventos.',
    category: 'utility',
    capability: 'events',
    available: true,
    enabled: false,
  },
  {
    key: 'utility.emojis',
    label: 'Emojis',
    description: 'Organiza e melhora a utilização de emojis personalizados.',
    category: 'utility',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'utility.embeds',
    label: 'Mensagens incorporadas',
    description: 'Cria mensagens ricas para regras, anúncios e informação útil.',
    category: 'utility',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'utility.search',
    label: 'Procura algo',
    description: 'Pesquisa conteúdos, vídeos e referências sem trocar de aplicação.',
    category: 'utility',
    capability: 'utility',
    available: true,
    enabled: false,
  },
  {
    key: 'utility.temp_channels',
    label: 'Canais temporários',
    description: 'Cria canais de voz que desaparecem quando deixam de ser usados.',
    category: 'utility',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'social.twitch',
    label: 'Alertas da Twitch',
    description: 'Publica um aviso quando um canal começa uma transmissão.',
    category: 'social',
    capability: 'alerts',
    available: true,
    enabled: false,
  },
  {
    key: 'social.youtube',
    label: 'Alertas do YouTube',
    description: 'Notifica o servidor quando sai um vídeo novo.',
    category: 'social',
    capability: 'alerts',
    available: true,
    enabled: false,
    maturity: 'beta',
    configurable: true,
  },
  {
    key: 'social.instagram',
    label: 'Alertas do Instagram',
    description: 'Acompanha novas publicações de contas escolhidas.',
    category: 'social',
    capability: 'alerts',
    available: true,
    maturity: 'blocked',
    configurable: true,
    enabled: false,
  },
  {
    key: 'social.tiktok',
    label: 'Alertas do TikTok',
    description: 'Notifica o servidor sobre novos vídeos.',
    category: 'social',
    capability: 'alerts',
    available: true,
    maturity: 'blocked',
    configurable: true,
    enabled: false,
  },
  {
    key: 'social.rss',
    label: 'RSS Feeds',
    description: 'Transforma qualquer feed RSS numa atualização automática.',
    category: 'social',
    capability: 'alerts',
    available: true,
    enabled: false,
  },
  {
    key: 'social.podcasts',
    label: 'Podcasts',
    description: 'Avisa quando sai um novo episódio dos teus podcasts.',
    category: 'social',
    capability: 'alerts',
    available: true,
    enabled: false,
  },
  {
    key: 'social.kick',
    label: 'Alertas da Kick',
    description: 'Notifica quando um criador começa uma transmissão.',
    category: 'social',
    capability: 'alerts',
    available: true,
    maturity: 'blocked',
    configurable: true,
    enabled: false,
  },
  {
    key: 'social.bluesky',
    label: 'Alertas do Bluesky',
    description: 'Acompanha novas publicações de perfis escolhidos.',
    category: 'social',
    capability: 'alerts',
    available: true,
    enabled: false,
  },
  {
    key: 'community.birthdays',
    label: 'Aniversários',
    description: 'Celebra aniversários automaticamente, com privacidade configurável.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'community.economy',
    label: 'Economia',
    description: 'Cria uma economia virtual com recompensas e progressão.',
    category: 'community',
    capability: 'community',
    available: true,
    enabled: false,
  },
  {
    key: 'growth.monetization',
    label: 'Monetização',
    description: 'Prepara benefícios e cargos para apoiar o servidor.',
    category: 'growth',
    capability: 'billing',
    available: true,
    maturity: 'blocked',
    configurable: true,
    enabled: false,
  },
  {
    key: 'web3.crypto_stats',
    label: 'Estatísticas de cripto',
    description: 'Acompanha indicadores de moedas digitais.',
    category: 'web3',
    capability: 'web3',
    available: true,
    enabled: false,
  },
  {
    key: 'web3.crypto_queries',
    label: 'Consultas de criptomoedas',
    description: 'Consulta informação de criptomoedas dentro do servidor.',
    category: 'web3',
    capability: 'web3',
    available: true,
    enabled: false,
  },
  {
    key: 'web3.gas_tracker',
    label: 'Gas tracker',
    description: 'Mostra as taxas de rede atuais para a comunidade.',
    category: 'web3',
    capability: 'web3',
    available: true,
    enabled: false,
    maturity: 'beta',
    configurable: true,
  },
  {
    key: 'web3.gating',
    label: 'Gating',
    description: 'Controla acesso e cargos com base em coleções verificadas.',
    category: 'web3',
    capability: 'web3',
    available: true,
    maturity: 'blocked',
    configurable: true,
    enabled: false,
  },
];

// A disconnected production panel must never fall back to the demo catalogue
// with "available" or "active" states.  The Rust API is the source of truth;
// when it cannot be reached we keep the topics visible for navigation, but
// explicitly mark every one as blocked until the live guild state is loaded.
function unavailableFeatureCatalogue(): Feature[] {
  return demoFeatures.concat(additionalFeatures).map((feature) => ({
    ...feature,
    available: false,
    enabled: false,
    maturity: 'blocked',
    configurable: false,
    health: {
      operational: false,
      status: 'dependency_down',
      adapter: null,
      dependencies: ['Rust API'],
    },
    issues: [
      {
        path: '',
        code: 'feature_catalog_unavailable',
        message: 'Feature state unavailable until the Rust API reconnects.',
        severity: 'error',
      },
    ],
  }));
}

const featureCopy: Record<string, Pick<Feature, 'label' | 'description'>> = {
  'protection.antispam': {
    label: 'Proteção contra spam',
    description: 'Deteta flood, mensagens repetidas, excesso de menções, links e caps.',
  },
  'protection.antiscam': {
    label: 'Proteção contra fraude',
    description: 'Bloqueia links suspeitos, convites e padrões de phishing.',
  },
};
function presentFeature(feature: Feature): Feature {
  return featureCopy[feature.key] ? { ...feature, ...featureCopy[feature.key] } : feature;
}
const defaults: Record<string, FeatureConfig> = {
  'protection.antiscam': {
    blockInvites: true,
    blockedDomains: [],
    blockedKeywords: ['free nitro', 'steam gift', 'claim your prize', 'verify your wallet'],
    ignoredChannels: [],
    ignoredRoles: [],
    logChannel: '',
    timeoutSeconds: 300,
    alertOnly: false,
  },
  'protection.anti_raid': {
    joinThreshold: 10,
    windowSeconds: 10,
    incidentMinutes: 10,
    verification: 'high',
    pauseInvites: true,
    alertOnly: false,
    alertChannel: '',
  },
  'protection.join_gate': {
    minimumAccountDays: 7,
    requireAvatar: false,
    blockedNamePatterns: [],
    action: 'quarantine',
    verifiedRole: '',
    autoRole: '',
    logChannel: '',
  },
  'community.levels': {
    xpMin: 15,
    xpMax: 30,
    cooldownSeconds: 60,
    voiceXpEnabled: false,
    voiceXpPerMinute: 2,
    ignoredChannels: [],
    announceChannel: '',
    announceTemplate: '{member} chegou ao nível {level}!',
    stackRoles: true,
    levelRoles: [],
  },
  'community.leaderboard': {
    maxEntries: 10,
    public: true,
  },
  'community.starboard': {
    emoji: '⭐',
    threshold: 3,
    channel: '',
    allowSelfStar: false,
    ignoredChannels: [],
    ignoredRoles: [],
    includeImages: true,
  },
  'community.suggestions': {
    channel: '',
    anonymous: false,
    voteMode: 'up_down',
    cooldownHours: 24,
    requiredRole: '',
    staffChannel: '',
  },
  'community.giveaways': {
    defaultDurationHours: 24,
    defaultWinners: 1,
    requiredRole: '',
  },
  'support.tickets': {
    categoryId: '',
    staffRole: '',
    transcriptChannel: '',
    maxOpen: 1,
    closeAfterHours: 1,
    panelTitle: 'Need support?',
    panelDescription: 'Open a private ticket and the support team will help you.',
  },
  'support.welcome': {
    channel: '',
    message: 'Welcome {member} to {server}!',
    sendDm: false,
    dmMessage: 'Hello {member}, welcome to {server}!',
    autoRole: '',
    delaySeconds: 0,
    farewellChannel: '',
    farewellMessage: 'Goodbye {member}. We hope to see you again!',
    templateId: '',
  },
  'support.welcome_channel': {
    channelId: '',
    message:
      'Welcome {member}! Start with the rules, introduce yourself and check the server channels.',
    templateId: '',
  },
  'management.nickname': { nickname: '' },
  'management.workflows': {
    maxWorkflows: 10,
    maxReplyLength: 1000,
    allowMentions: false,
  },
  'management.polls': {
    defaultDurationHours: 24,
    channel: '',
  },
  'insights.stats': {
    windowDays: 7,
    public: false,
    channelId: '',
    intervalMinutes: 15,
    nameTemplate: 'messages-{messages}',
  },
  'utility.emojis': {
    maxEntries: 50,
    animatedOnly: false,
    allowManagement: false,
  },
  'utility.embeds': {
    maxDescription: 2000,
    defaultColor: '',
    defaultFooter: '',
  },
  'utility.search': {
    maxResults: 5,
    allowWikipedia: true,
    allowAniList: true,
    allowBluesky: true,
    allowYouTube: true,
    allowTwitch: true,
  },
  'utility.temp_channels': {
    categoryId: '',
    nameTemplate: "{user}'s room",
    maxActive: 10,
  },
  'social.youtube': {
    sourceChannelId: '',
    targetChannelId: '',
    intervalSeconds: 300,
    messageTemplate: 'Novo vídeo de {channel}: **{title}**\n{url}',
    mention: '',
  },
  'social.rss': {
    feedUrl: '',
    targetChannelId: '',
    intervalSeconds: 900,
    messageTemplate: 'Nova publicação em {feed}: **{title}**\n{url}',
    mention: '',
  },
  'social.podcasts': {
    feedUrl: '',
    targetChannelId: '',
    intervalSeconds: 900,
    messageTemplate: 'New episode from {feed}: **{title}**\n{url}',
    mention: '',
  },
  'social.twitch': {
    sourceLogin: '',
    targetChannelId: '',
    messageTemplate: '{broadcaster} está ao vivo!\nhttps://twitch.tv/{login}',
    mention: '',
  },
  'management.moderation': {
    requireReason: true,
    maxPurge: 100,
  },
  'management.custom_commands': {
    triggerPrefix: '!',
    ignoredChannels: [],
    staffOnly: false,
    maxTags: 100,
    maxResponseLength: 1000,
  },
  'management.audit': {
    threshold: 3,
    windowSeconds: 10,
    shadowMode: false,
    logChannel: '',
    includeContent: false,
  },
  'management.privacy': {
    allowMemberExport: true,
    allowMemberErase: true,
    maxExportBytes: 1000000,
  },
  // Templates use the dedicated StudioTemplate manager below.  Do not expose
  // generic JSON switches that are not part of the API's template contract.
  'management.templates': {},
  'community.role_panels': {
    channel: '',
    roleIds: [],
    panelTitle: 'Escolhe os teus cargos',
    panelDescription: 'Seleciona as opções que combinam contigo.',
    maxRoles: 5,
    selectionMode: 'multiple',
    removeOnUnselect: true,
  },
  'community.events': {
    defaultDurationHours: 2,
    defaultCapacity: 0,
    announcementChannel: '',
    reminders: true,
    reminderHours: 1,
  },
  'utility.help': { showModules: true, showDashboard: true },
  'utility.reminders': {
    maxDelayHours: 168,
    maxTextLength: 500,
    timezone: 'UTC',
    notifyUser: true,
    allowRecurring: false,
    maxRecurrences: 12,
  },
};

const additionalSpecs: Record<string, SectionSpec[]> = {
  'community.leaderboard': [
    {
      title: 'Leaderboard privacy',
      description: 'Control how many members appear in the XP leaderboard.',
      fields: [
        {
          key: 'maxEntries',
          label: 'Members shown',
          kind: 'number',
          min: 1,
          max: 100,
        },
        { key: 'public', label: 'Show the leaderboard publicly', kind: 'toggle' },
      ],
    },
  ],
  'support.welcome_channel': [
    {
      title: 'Primeiros passos',
      description: 'Escolhe onde novos membros encontram as informações essenciais.',
      fields: [
        { key: 'channelId', label: 'Canal de entrada', kind: 'channel' },
        {
          key: 'message',
          label: 'Mensagem de primeiros passos',
          kind: 'textarea',
          maxLength: 2000,
        },
        { key: 'templateId', label: 'Modelo reutilizável', kind: 'select', advanced: true },
      ],
    },
  ],
  'management.moderation': [
    {
      title: 'Moderation safety',
      description: 'Set guardrails used by manual moderation commands.',
      fields: [
        {
          key: 'requireReason',
          label: 'Require a reason',
          kind: 'toggle',
        },
        {
          key: 'maxPurge',
          label: 'Maximum purge count',
          kind: 'number',
          min: 1,
          max: 100,
        },
      ],
    },
  ],
  'management.custom_commands': [
    {
      title: 'Comandos e respostas',
      description: 'Cria respostas curtas para perguntas frequentes.',
      fields: [
        { key: 'triggerPrefix', label: 'Prefixo do comando', kind: 'text', maxLength: 3 },
        {
          key: 'maxTags',
          label: 'Máximo de comandos guardados',
          kind: 'number',
          min: 1,
          max: 100,
          help: 'Limita quantas respostas este servidor pode guardar.',
          advanced: true,
        },
      ],
    },
    {
      title: 'Regras de utilização',
      description: 'Controla onde e por quem as respostas podem ser usadas.',
      fields: [
        { key: 'ignoredChannels', label: 'Canais ignorados', kind: 'channels', advanced: true },
        { key: 'staffOnly', label: 'Apenas equipa', kind: 'toggle', advanced: true },
        {
          key: 'maxResponseLength',
          label: 'Tamanho máximo da resposta',
          kind: 'number',
          min: 1,
          max: 2000,
          help: 'Impede respostas demasiado longas no Discord.',
        },
      ],
    },
  ],
  'management.audit': [
    {
      title: 'Registo de alterações',
      description: 'Escolhe o que a equipa deve conseguir rever.',
      fields: [
        { key: 'threshold', label: 'Actions before containment', kind: 'number', min: 2, max: 25 },
        {
          key: 'windowSeconds',
          label: 'Detection window (seconds)',
          kind: 'number',
          min: 3,
          max: 60,
        },
        { key: 'shadowMode', label: 'Shadow mode', kind: 'toggle' },
        {
          key: 'logChannel',
          label: 'Audit log channel (optional)',
          kind: 'channel',
          advanced: true,
        },
        {
          key: 'includeContent',
          label: 'Include cached message content',
          kind: 'toggle',
          advanced: true,
        },
      ],
    },
  ],
  'management.privacy': [
    {
      title: 'Retenção',
      description: 'Define quanto tempo os dados opcionais ficam guardados.',
      fields: [
        { key: 'allowMemberErase', label: 'Allow member erasure', kind: 'toggle' },
        {
          key: 'maxExportBytes',
          label: 'Maximum export size',
          kind: 'number',
          min: 65536,
          max: 10000000,
        },
      ],
    },
    {
      title: 'Pedidos de dados',
      description: 'Mantém os pedidos de privacidade claros.',
      fields: [{ key: 'allowMemberExport', label: 'Allow member exports', kind: 'toggle' }],
    },
  ],
  'social.tiktok': [
    {
      title: 'Criador acompanhado',
      description: 'Acompanha vídeos de um criador que autorizou o Vozen pela Display API.',
      fields: [
        { key: 'username', label: 'Nome do criador', kind: 'text' },
        { key: 'targetChannelId', label: 'Canal Discord', kind: 'channel' },
      ],
    },
    {
      title: 'Mensagem',
      description: 'Define o formato dos alertas de vídeo.',
      fields: [
        { key: 'messageTemplate', label: 'Mensagem', kind: 'textarea', maxLength: 1800 },
        { key: 'mention', label: 'Menção opcional', kind: 'text', advanced: true },
        {
          key: 'intervalSeconds',
          label: 'Intervalo (segundos)',
          kind: 'number',
          min: 900,
          max: 86400,
          advanced: true,
        },
      ],
    },
  ],
  'social.instagram': [
    {
      title: 'Conta acompanhada',
      description: 'Acompanha publicações de uma conta profissional autorizada pela Meta.',
      fields: [
        { key: 'username', label: 'Nome de utilizador', kind: 'text' },
        { key: 'targetChannelId', label: 'Canal Discord', kind: 'channel' },
      ],
    },
    {
      title: 'Mensagem',
      description: 'Define o formato dos alertas de publicação.',
      fields: [
        { key: 'messageTemplate', label: 'Mensagem', kind: 'textarea', maxLength: 1800 },
        { key: 'mention', label: 'Menção opcional', kind: 'text', advanced: true },
        {
          key: 'intervalSeconds',
          label: 'Intervalo (segundos)',
          kind: 'number',
          min: 900,
          max: 86400,
          advanced: true,
        },
      ],
    },
  ],
  'social.kick': [
    {
      title: 'Canal acompanhado',
      description: 'Acompanha transmissões através da API oficial da Kick, quando disponível.',
      fields: [
        {
          key: 'sourceHandle',
          label: 'Handle da Kick',
          kind: 'text',
          help: 'Exemplo: vozen (sem @).',
        },
        { key: 'targetChannelId', label: 'Canal Discord', kind: 'channel' },
      ],
    },
    {
      title: 'Mensagem',
      description: 'Personaliza o alerta de transmissão.',
      fields: [
        { key: 'messageTemplate', label: 'Mensagem', kind: 'textarea', maxLength: 1800 },
        { key: 'mention', label: 'Menção opcional', kind: 'text', advanced: true },
        {
          key: 'intervalSeconds',
          label: 'Intervalo (segundos)',
          kind: 'number',
          min: 300,
          max: 86400,
          advanced: true,
        },
      ],
    },
  ],
  'growth.monetization': [
    {
      title: 'Benefício do servidor',
      description:
        'Define um produto de apoio; pagamentos a servidores só ficam disponíveis após a configuração legal do Stripe Connect.',
      fields: [
        { key: 'productName', label: 'Nome do produto', kind: 'text' },
        { key: 'targetRoleId', label: 'Cargo atribuído', kind: 'role' },
        {
          key: 'priceCents',
          label: 'Preço (cêntimos)',
          kind: 'number',
          min: 50,
          max: 100000,
          advanced: true,
        },
        {
          key: 'currency',
          label: 'Moeda',
          kind: 'select',
          options: [
            ['eur', 'EUR'],
            ['usd', 'USD'],
          ],
          advanced: true,
        },
        {
          key: 'trialDays',
          label: 'Período experimental (dias)',
          kind: 'number',
          min: 0,
          max: 90,
          advanced: true,
        },
      ],
    },
  ],
  'web3.gating': [
    {
      title: 'Regra de acesso',
      description:
        'Configura uma verificação read-only; nunca introduzas uma seed phrase ou chave privada.',
      fields: [
        {
          key: 'chain',
          label: 'Rede',
          kind: 'select',
          options: [
            ['ethereum', 'Ethereum'],
            ['polygon', 'Polygon'],
            ['base', 'Base'],
          ],
        },
        { key: 'contractAddress', label: 'Endereço do contrato', kind: 'text' },
        {
          key: 'assetType',
          label: 'Tipo de ativo',
          kind: 'select',
          options: [
            ['erc20', 'ERC-20'],
            ['erc721', 'ERC-721'],
            ['erc1155', 'ERC-1155'],
          ],
        },
        { key: 'tokenId', label: 'Token ID', kind: 'text', advanced: true },
        { key: 'targetRoleId', label: 'Cargo atribuído', kind: 'role' },
        {
          key: 'minimumBalance',
          label: 'Saldo mínimo',
          kind: 'number',
          min: 0,
          max: 1000000000,
          advanced: true,
        },
        {
          key: 'intervalSeconds',
          label: 'Intervalo de verificação (segundos)',
          kind: 'number',
          min: 300,
          max: 86400,
          advanced: true,
        },
      ],
    },
  ],
  'community.role_panels': [
    {
      title: 'Painel de escolha',
      description: 'Prepara a mensagem onde os membros escolhem cargos.',
      fields: [
        { key: 'channel', label: 'Canal do painel', kind: 'channel' },
        { key: 'roleIds', label: 'Role options', kind: 'roles', max: 5 },
        { key: 'panelTitle', label: 'Título do painel', kind: 'text' },
        { key: 'panelDescription', label: 'Descrição do painel', kind: 'textarea' },
      ],
    },
    {
      title: 'Limites',
      description: 'Evita escolhas excessivas.',
      fields: [
        { key: 'maxRoles', label: 'Máximo de cargos por membro', kind: 'number', min: 1, max: 5 },
        {
          key: 'selectionMode',
          label: 'Selection mode',
          kind: 'select',
          options: [
            ['multiple', 'Several roles'],
            ['unique', 'One role'],
          ],
        },
        { key: 'removeOnUnselect', label: 'Remover cargo ao desselecionar', kind: 'toggle' },
      ],
    },
  ],
  'community.events': [
    {
      title: 'Evento predefinido',
      description: 'Define defaults para criares eventos com menos passos.',
      fields: [
        {
          key: 'defaultDurationHours',
          label: 'Duração predefinida (horas)',
          kind: 'number',
          min: 1,
          max: 8760,
        },
        {
          key: 'defaultCapacity',
          label: 'Limite de participantes',
          kind: 'number',
          min: 0,
          max: 100000,
        },
        { key: 'announcementChannel', label: 'Canal de anúncios', kind: 'channel' },
      ],
    },
    {
      title: 'Acompanhamento',
      description: 'Ajuda os membros a não perderem o início.',
      fields: [
        { key: 'reminders', label: 'Enviar lembretes', kind: 'toggle' },
        {
          key: 'reminderHours',
          label: 'Horas antes do evento',
          kind: 'number',
          min: 1,
          max: 168,
          advanced: true,
        },
      ],
    },
  ],
  'utility.help': [
    {
      title: 'Ajuda no servidor',
      description: 'Escolhe como o Helper explica os seus módulos.',
      fields: [
        { key: 'showModules', label: 'Show module list', kind: 'toggle' },
        { key: 'showDashboard', label: 'Include dashboard link', kind: 'toggle' },
      ],
    },
  ],
  'utility.reminders': [
    {
      title: 'Lembretes',
      description: 'Prepara lembretes consistentes para a comunidade.',
      fields: [
        {
          key: 'maxDelayHours',
          label: 'Maximum delay (hours)',
          kind: 'number',
          min: 1,
          max: 8760,
        },
        {
          key: 'maxTextLength',
          label: 'Maximum message length',
          kind: 'number',
          min: 50,
          max: 500,
        },
        {
          key: 'timezone',
          label: 'Reminder timezone',
          kind: 'select',
          options: [
            ['UTC', 'UTC'],
            ['UTC-05:00', 'UTC-05:00'],
            ['UTC+01:00', 'UTC+01:00'],
            ['UTC+02:00', 'UTC+02:00'],
            ['UTC+05:30', 'UTC+05:30'],
            ['UTC+08:00', 'UTC+08:00'],
          ],
        },
        { key: 'notifyUser', label: 'Mention the member when it fires', kind: 'toggle' },
        { key: 'allowRecurring', label: 'Allow recurring reminders', kind: 'toggle' },
        { key: 'maxRecurrences', label: 'Maximum repeats', kind: 'number', min: 1, max: 52 },
      ],
    },
  ],
};

const twitchSpec: SectionSpec[] = [
  {
    title: 'Canal acompanhado',
    description: 'Indica o nome do canal Twitch e valida-o pela API oficial antes de publicar.',
    fields: [
      {
        key: 'sourceLogin',
        label: 'Nome do canal Twitch',
        kind: 'text',
        help: 'Exemplo: rexy40407 (sem twitch.tv/).',
      },
      {
        key: 'targetChannelId',
        label: 'ID do canal Discord',
        kind: 'text',
        help: 'O canal onde o alerta será publicado.',
      },
    ],
  },
  {
    title: 'Mensagem',
    description: 'Personaliza o aviso enviado quando a transmissão começa.',
    fields: [
      {
        key: 'messageTemplate',
        label: 'Mensagem do alerta',
        kind: 'textarea',
        help: 'Variáveis: {broadcaster}, {login}, {url}, {stream_id}, {started_at}.',
      },
      {
        key: 'mention',
        label: 'Menção opcional',
        kind: 'text',
        help: 'Vazio, @here, @everyone ou uma menção de cargo.',
        advanced: true,
      },
    ],
  },
];
additionalSpecs['social.twitch'] = twitchSpec;
// Podcasts use the same validated RSS/Atom transport and editor, but keep a
// separate catalog key so the product surface is discoverable.
additionalSpecs['social.podcasts'] = additionalSpecs['social.rss'];
const spec = (key: string): SectionSpec[] => {
  const map: Record<string, SectionSpec[]> = {
    'protection.antiscam': [
      {
        title: 'Deteção de fraude',
        description: 'Controla como o Helper reage a convites, domínios e frases suspeitas.',
        fields: [
          {
            key: 'blockInvites',
            label: 'Bloquear convites Discord não solicitados',
            kind: 'toggle',
          },
          { key: 'blockedDomains', label: 'Domínios bloqueados', kind: 'tags', advanced: true },
          { key: 'blockedKeywords', label: 'Frases bloqueadas', kind: 'tags', advanced: true },
          {
            key: 'timeoutSeconds',
            label: 'Timeout (segundos)',
            kind: 'number',
            min: 0,
            max: 86400,
            advanced: true,
          },
          { key: 'alertOnly', label: 'Apenas monitorizar', kind: 'toggle', advanced: true },
        ],
      },
      {
        title: 'Exceções e registo',
        description: 'Escolhe recursos reais do servidor para reduzir falsos positivos.',
        fields: [
          { key: 'ignoredChannels', label: 'Canais ignorados', kind: 'channels', advanced: true },
          { key: 'ignoredRoles', label: 'Cargos ignorados', kind: 'roles', advanced: true },
          { key: 'logChannel', label: 'Canal de registo', kind: 'channel', advanced: true },
        ],
      },
    ],
    'protection.anti_raid': [
      {
        title: 'Deteção de entradas',
        description: 'Define quando uma sequência de entradas passa a ser considerada raid.',
        fields: [
          {
            key: 'joinThreshold',
            label: 'Entradas para iniciar alerta',
            kind: 'number',
            min: 2,
            max: 100,
          },
          {
            key: 'windowSeconds',
            label: 'Janela de tempo (segundos)',
            kind: 'number',
            min: 3,
            max: 60,
          },
          {
            key: 'incidentMinutes',
            label: 'Duração da proteção (minutos)',
            kind: 'number',
            min: 1,
            max: 120,
          },
        ],
      },
      {
        title: 'Resposta e recuperação',
        description: 'Escolhe o nível de verificação e onde a equipa é avisada.',
        fields: [
          {
            key: 'verification',
            label: 'Nível de verificação',
            kind: 'select',
            options: [
              ['medium', 'Médio'],
              ['high', 'Alto'],
              ['very_high', 'Muito alto'],
            ],
          },
          { key: 'pauseInvites', label: 'Pausar convites durante o incidente', kind: 'toggle' },
          { key: 'alertOnly', label: 'Apenas alertar', kind: 'toggle', advanced: true },
          { key: 'alertChannel', label: 'Canal de alerta', kind: 'text', advanced: true },
        ],
      },
    ],
    'protection.join_gate': [
      {
        title: 'Entrada segura',
        description: 'Filtra contas novas antes de lhes dar acesso completo.',
        fields: [
          {
            key: 'minimumAccountDays',
            label: 'Idade mínima da conta (dias)',
            kind: 'number',
            min: 0,
            max: 365,
          },
          { key: 'requireAvatar', label: 'Exigir avatar', kind: 'toggle' },
          {
            key: 'action',
            label: 'Ação para contas suspeitas',
            kind: 'select',
            options: [
              ['quarantine', 'Quarentena'],
              ['alert', 'Apenas alertar'],
            ],
          },
        ],
      },
      {
        title: 'Cargos e registo',
        description: 'Liga a verificação ao fluxo da tua comunidade.',
        fields: [
          { key: 'verifiedRole', label: 'Cargo verificado', kind: 'text' },
          { key: 'autoRole', label: 'Cargo inicial', kind: 'text' },
          {
            key: 'blockedNamePatterns',
            label: 'Padrões de nome bloqueados',
            kind: 'tags',
            advanced: true,
          },
          { key: 'logChannel', label: 'Canal de registo', kind: 'text', advanced: true },
        ],
      },
    ],
    'community.levels': [
      {
        title: 'Progressão',
        description: 'Cria um ritmo justo para membros ativos.',
        fields: [
          { key: 'xpMin', label: 'XP mínimo por mensagem', kind: 'number', min: 1, max: 1000 },
          { key: 'xpMax', label: 'XP máximo por mensagem', kind: 'number', min: 1, max: 2000 },
          {
            key: 'cooldownSeconds',
            label: 'Cooldown entre mensagens (segundos)',
            kind: 'number',
            min: 0,
            max: 3600,
          },
          {
            key: 'voiceXpEnabled',
            label: 'Dar XP em canais de voz',
            kind: 'toggle',
            advanced: true,
          },
          {
            key: 'voiceXpPerMinute',
            label: 'XP por minuto em voz',
            kind: 'number',
            min: 0,
            max: 30,
            advanced: true,
          },
          { key: 'stackRoles', label: 'Acumular cargos de nível', kind: 'toggle' },
        ],
      },
      {
        title: 'Mensagens e recompensas',
        description: 'Personaliza o anúncio e os cargos sem editar comandos.',
        fields: [
          { key: 'announceChannel', label: 'Canal de anúncio', kind: 'channel' },
          {
            key: 'announceTemplate',
            label: 'Mensagem de subida de nível',
            kind: 'textarea',
            help: 'Variáveis: {member}, {level}, {server}.',
            advanced: true,
          },
          { key: 'ignoredChannels', label: 'Canais sem XP', kind: 'channels', advanced: true },
          { key: 'levelRoles', label: 'Recompensas por nível', kind: 'tags', advanced: true },
        ],
      },
    ],
    'community.starboard': [
      {
        title: 'Destaques',
        description: 'Escolhe quando uma mensagem merece aparecer no canal especial.',
        fields: [
          { key: 'emoji', label: 'Emoji de destaque', kind: 'text' },
          { key: 'threshold', label: 'Reações necessárias', kind: 'number', min: 1, max: 100 },
          { key: 'channel', label: 'Canal starboard', kind: 'channel' },
        ],
      },
      {
        title: 'Regras da comunidade',
        description: 'Mantém o destaque relevante e seguro.',
        fields: [
          {
            key: 'allowSelfStar',
            label: 'Permitir reação do autor',
            kind: 'toggle',
            advanced: true,
          },
          { key: 'includeImages', label: 'Incluir imagens', kind: 'toggle', advanced: true },
          { key: 'ignoredChannels', label: 'Canais ignorados', kind: 'channels', advanced: true },
          { key: 'ignoredRoles', label: 'Cargos ignorados', kind: 'roles', advanced: true },
        ],
      },
    ],
    'community.suggestions': [
      {
        title: 'Caixa de ideias',
        description: 'Define como os membros enviam e votam nas sugestões.',
        fields: [
          { key: 'channel', label: 'Canal de sugestões', kind: 'text' },
          {
            key: 'voteMode',
            label: 'Modo de votação',
            kind: 'select',
            options: [
              ['up_down', 'Apoiar / não apoiar'],
              ['up_only', 'Apenas apoiar'],
            ],
          },
          { key: 'anonymous', label: 'Permitir sugestões anónimas', kind: 'toggle' },
        ],
      },
      {
        title: 'Moderação',
        description: 'Dá à equipa contexto e controlo sobre o fluxo.',
        fields: [
          {
            key: 'cooldownHours',
            label: 'Cooldown por membro (horas)',
            kind: 'number',
            min: 0,
            max: 720,
            advanced: true,
          },
          { key: 'requiredRole', label: 'Cargo necessário', kind: 'text', advanced: true },
          { key: 'staffChannel', label: 'Canal privado da equipa', kind: 'text', advanced: true },
        ],
      },
    ],
    'community.giveaways': [
      {
        title: 'Valores predefinidos',
        description: 'Acelera a criação de sorteios no Discord.',
        fields: [
          {
            key: 'defaultDurationHours',
            label: 'Duração predefinida (horas)',
            kind: 'number',
            min: 1,
            max: 168,
          },
          {
            key: 'defaultWinners',
            label: 'Vencedores predefinidos',
            kind: 'number',
            min: 1,
            max: 20,
          },
          { key: 'requiredRole', label: 'Cargo necessário', kind: 'role' },
        ],
      },
    ],
    'support.tickets': [
      {
        title: 'Atendimento',
        description: 'Prepara o espaço para a equipa responder aos membros.',
        fields: [
          { key: 'categoryId', label: 'Categoria dos tickets', kind: 'category' },
          { key: 'staffRole', label: 'Cargo da equipa', kind: 'role' },
          { key: 'transcriptChannel', label: 'Canal de transcrições', kind: 'channel' },
          { key: 'maxOpen', label: 'Tickets abertos por membro', kind: 'number', min: 1, max: 10 },
        ],
      },
      {
        title: 'Painel de abertura',
        description: 'A primeira mensagem deve explicar claramente o próximo passo.',
        fields: [
          { key: 'panelTitle', label: 'Título do painel', kind: 'text' },
          { key: 'panelDescription', label: 'Descrição do painel', kind: 'textarea' },
          {
            key: 'closeAfterHours',
            label: 'Fechar por inatividade (horas)',
            kind: 'number',
            min: 1,
            max: 168,
            advanced: true,
          },
        ],
      },
    ],
    'support.welcome': [
      {
        title: 'Mensagem de entrada',
        description: 'Dá boas-vindas sem obrigar a editar código.',
        fields: [
          { key: 'channel', label: 'Canal público', kind: 'channel' },
          {
            key: 'message',
            label: 'Mensagem pública',
            kind: 'textarea',
            help: 'Variáveis: {member}, {server}, {count}.',
          },
          { key: 'delaySeconds', label: 'Atraso (segundos)', kind: 'number', min: 0, max: 3600 },
        ],
      },
      {
        title: 'Mensagem privada e cargo',
        description: 'Completa o onboarding para novos membros.',
        fields: [
          { key: 'sendDm', label: 'Enviar mensagem privada', kind: 'toggle' },
          { key: 'dmMessage', label: 'Mensagem privada', kind: 'textarea', advanced: true },
          { key: 'autoRole', label: 'Cargo inicial', kind: 'role', advanced: true },
        ],
      },
      {
        title: 'Saída e modelos',
        description: 'Escolhe onde despedidas são publicadas e reutiliza um modelo aprovado.',
        fields: [
          { key: 'farewellChannel', label: 'Canal de despedidas', kind: 'channel', advanced: true },
          {
            key: 'farewellMessage',
            label: 'Mensagem de despedida',
            kind: 'textarea',
            advanced: true,
          },
          { key: 'templateId', label: 'Modelo reutilizável', kind: 'select', advanced: true },
        ],
      },
    ],
    'management.nickname': [
      {
        title: 'Nome no servidor',
        description: 'Escolhe como o Helper aparece na lista de membros deste servidor.',
        fields: [
          {
            key: 'nickname',
            label: 'Nickname do Helper',
            kind: 'text',
            maxLength: 32,
            help: 'Até 32 caracteres. Deixa vazio para remover o nome personalizado.',
          },
        ],
      },
    ],
    'management.workflows': [
      {
        title: 'Automation safety limits',
        description: 'Bounded message automations keep your server responsive.',
        fields: [
          {
            key: 'maxWorkflows',
            label: 'Maximum workflows',
            kind: 'number',
            min: 1,
            max: 100,
          },
          {
            key: 'maxReplyLength',
            label: 'Maximum reply length',
            kind: 'number',
            min: 1,
            max: 1500,
          },
          { key: 'allowMentions', label: 'Allow mentions in replies', kind: 'toggle' },
        ],
      },
    ],
    'management.polls': [
      {
        title: 'Votações',
        description: 'Define defaults para enquetes rápidas.',
        fields: [
          { key: 'channel', label: 'Canal predefinido', kind: 'channel' },
          {
            key: 'defaultDurationHours',
            label: 'Duração predefinida (horas)',
            kind: 'number',
            min: 1,
            max: 168,
          },
        ],
      },
    ],
    'insights.stats': [
      {
        title: 'Server statistics',
        description:
          'Control the period, visibility and optional live counter channel for server statistics.',
        fields: [
          { key: 'windowDays', label: 'Reporting window (days)', kind: 'number', min: 1, max: 30 },
          { key: 'public', label: 'Show publicly', kind: 'toggle' },
          { key: 'channelId', label: 'Live counter channel', kind: 'channel' },
          {
            key: 'intervalMinutes',
            label: 'Counter refresh (minutes)',
            kind: 'number',
            min: 5,
            max: 1440,
            advanced: true,
          },
          { key: 'nameTemplate', label: 'Channel name template', kind: 'text', maxLength: 100 },
        ],
      },
    ],
    'utility.emojis': [
      {
        title: 'Emoji inventory',
        description:
          'List custom emojis safely, with optional staff-only rename and delete controls.',
        fields: [
          { key: 'maxEntries', label: 'Emojis shown', kind: 'number', min: 1, max: 100 },
          { key: 'animatedOnly', label: 'Only animated emojis', kind: 'toggle' },
          {
            key: 'allowManagement',
            label: 'Allow staff to rename or delete emojis',
            kind: 'toggle',
            advanced: true,
          },
        ],
      },
    ],
    'utility.embeds': [
      {
        title: 'Safe embed publishing',
        description: 'Publish bounded embeds with mentions disabled by default.',
        fields: [
          {
            key: 'maxDescription',
            label: 'Maximum description length',
            kind: 'number',
            min: 1,
            max: 4000,
          },
          { key: 'defaultColor', label: 'Default colour (hex)', kind: 'text', maxLength: 7 },
          { key: 'defaultFooter', label: 'Default footer', kind: 'text', maxLength: 2048 },
        ],
      },
    ],
    'utility.search': [
      {
        title: 'Approved search sources',
        description: 'Search is limited to documented providers; arbitrary URLs are never fetched.',
        fields: [
          { key: 'maxResults', label: 'Results per search', kind: 'number', min: 1, max: 5 },
          { key: 'allowWikipedia', label: 'Wikipedia', kind: 'toggle' },
          { key: 'allowAniList', label: 'AniList', kind: 'toggle' },
          { key: 'allowBluesky', label: 'Bluesky', kind: 'toggle' },
          { key: 'allowYouTube', label: 'YouTube', kind: 'toggle' },
          { key: 'allowTwitch', label: 'Twitch', kind: 'toggle' },
        ],
      },
    ],
    'utility.temp_channels': [
      {
        title: 'Temporary voice rooms',
        description: 'Create bounded rooms with a predictable name and optional category.',
        fields: [
          { key: 'categoryId', label: 'Category', kind: 'category' },
          { key: 'nameTemplate', label: 'Room name template', kind: 'text', maxLength: 80 },
          { key: 'maxActive', label: 'Maximum active rooms', kind: 'number', min: 1, max: 50 },
        ],
      },
    ],
    'social.rss': [
      {
        title: 'Feed acompanhado',
        description: 'Indica um feed RSS ou Atom público e confirma-o antes de guardar.',
        fields: [
          {
            key: 'feedUrl',
            label: 'URL do feed RSS/Atom',
            kind: 'text',
            help: 'Usa um URL HTTPS de um feed público.',
          },
          {
            key: 'targetChannelId',
            label: 'ID do canal Discord',
            kind: 'text',
            help: 'O canal onde a publicação será enviada.',
          },
          {
            key: 'intervalSeconds',
            label: 'Verificar a cada (segundos)',
            kind: 'number',
            min: 300,
            max: 86400,
          },
        ],
      },
      {
        title: 'Mensagem',
        description: 'Personaliza o aviso sem expor credenciais.',
        fields: [
          {
            key: 'messageTemplate',
            label: 'Mensagem do alerta',
            kind: 'textarea',
            help: 'Variáveis: {feed}, {title}, {url}, {published_at}.',
          },
          {
            key: 'mention',
            label: 'Menção opcional',
            kind: 'text',
            help: 'Vazio, @here, @everyone ou uma menção de cargo.',
            advanced: true,
          },
        ],
      },
    ],
    'social.youtube': [
      {
        title: 'Canal acompanhado',
        description: 'Indica o ID do canal do YouTube e confirma-o antes de guardar.',
        fields: [
          {
            key: 'sourceChannelId',
            label: 'ID do canal YouTube',
            kind: 'text',
            help: 'Usa o ID que começa normalmente por UC…',
          },
          {
            key: 'targetChannelId',
            label: 'ID do canal Discord',
            kind: 'text',
            help: 'O canal onde o alerta será publicado.',
          },
          {
            key: 'intervalSeconds',
            label: 'Verificar a cada (segundos)',
            kind: 'number',
            min: 300,
            max: 86400,
          },
        ],
      },
      {
        title: 'Mensagem',
        description: 'Personaliza o aviso sem expor a chave da API.',
        fields: [
          {
            key: 'messageTemplate',
            label: 'Mensagem do alerta',
            kind: 'textarea',
            help: 'Variáveis: {title}, {url}, {channel}, {published_at}.',
          },
          {
            key: 'mention',
            label: 'Menção opcional',
            kind: 'text',
            help: 'Vazio, @here, @everyone ou uma menção de cargo.',
            advanced: true,
          },
        ],
      },
    ],
  };
  // Keep the offline preview aligned with the Rust adapter contracts.  When
  // the API is available it is still the source of truth; these entries only
  // prevent the fallback page from rendering fields that the runtime ignores.
  if (key === 'insights.stats') {
    return [
      {
        title: 'Server statistics',
        description: 'Control the reporting window and an optional live counter channel.',
        fields: [
          { key: 'windowDays', label: 'Reporting window (days)', kind: 'number', min: 1, max: 30 },
          { key: 'public', label: 'Show publicly', kind: 'toggle' },
          { key: 'channelId', label: 'Live counter channel', kind: 'text' },
          {
            key: 'intervalMinutes',
            label: 'Counter refresh (minutes)',
            kind: 'number',
            min: 5,
            max: 1440,
            advanced: true,
          },
          { key: 'nameTemplate', label: 'Channel name template', kind: 'text', maxLength: 100 },
        ] as FieldSpec[],
      },
    ];
  }
  if (key === 'web3.gas_tracker') {
    return [
      {
        title: 'Gas tracker',
        description: 'Publish read-only gas prices from an approved HTTPS RPC.',
        fields: [
          {
            key: 'network',
            label: 'Network',
            kind: 'select',
            options: [
              ['ethereum', 'Ethereum'],
              ['polygon', 'Polygon'],
              ['arbitrum', 'Arbitrum'],
              ['base', 'Base'],
            ],
          },
          { key: 'targetChannelId', label: 'Discord channel', kind: 'text' },
          {
            key: 'intervalSeconds',
            label: 'Update interval (seconds)',
            kind: 'number',
            min: 300,
            max: 86400,
          },
          { key: 'messageTemplate', label: 'Statistics message', kind: 'textarea', advanced: true },
        ] as FieldSpec[],
      },
    ];
  }
  if (key === 'web3.crypto_stats' || key === 'web3.crypto_queries') {
    const stats = key === 'web3.crypto_stats';
    return [
      {
        title: stats ? 'Crypto statistics' : 'Crypto queries',
        description: 'Use the official CoinGecko read-only API with bounded symbols and results.',
        fields: [
          { key: 'coinIds', label: 'CoinGecko IDs', kind: 'text' },
          { key: 'currency', label: 'Currency', kind: 'text' },
          ...(stats
            ? [
                { key: 'targetChannelId', label: 'Discord channel', kind: 'text' },
                {
                  key: 'intervalSeconds',
                  label: 'Update interval (seconds)',
                  kind: 'number',
                  min: 300,
                  max: 86400,
                },
                {
                  key: 'messageTemplate',
                  label: 'Statistics message',
                  kind: 'textarea',
                  advanced: true,
                },
              ]
            : [
                {
                  key: 'maxResults',
                  label: 'Maximum results',
                  kind: 'number',
                  min: 1,
                  max: 10,
                  advanced: true,
                },
              ]),
        ] as FieldSpec[],
      },
    ];
  }
  if (key === 'social.bluesky') {
    return [
      {
        title: 'Bluesky alerts',
        description: 'Poll a public profile through the official Bluesky AppView API.',
        fields: [
          { key: 'sourceHandle', label: 'Bluesky handle', kind: 'text' },
          { key: 'targetChannelId', label: 'Discord channel', kind: 'text' },
          {
            key: 'intervalSeconds',
            label: 'Polling interval (seconds)',
            kind: 'number',
            min: 300,
            max: 86400,
          },
          { key: 'messageTemplate', label: 'Alert message', kind: 'textarea', advanced: true },
          { key: 'mention', label: 'Optional mention', kind: 'text', advanced: true },
        ] as FieldSpec[],
      },
    ];
  }
  return (
    map[key] ??
    additionalSpecs[key] ?? [
      {
        title: 'Configuração',
        description: 'Ajusta esta funcionalidade ao teu servidor.',
        fields: [
          { key: 'notes', label: 'Notas da equipa', kind: 'textarea' },
          { key: 'alertOnly', label: 'Apenas alertar', kind: 'toggle' },
        ],
      },
    ]
  );
};

function parseRoute(hash: string): Route {
  const value = hash.replace(/^#/, '') || '/';
  if (value === '/' || value === '') return { page: 'overview' };
  if (value === '/quick-setup') return { page: 'quick-setup' };
  if (value === '/features' || value === '/config') return { page: 'features' };
  if (value === '/activity') return { page: 'activity' };
  if (value === '/rank-card') return { page: 'rank-card' };
  if (value.startsWith('/config/'))
    return { page: 'detail', key: decodeURIComponent(value.slice('/config/'.length)) };
  return { page: 'overview' };
}

const quickSetupSteps: Array<{ key: QuickSetupStepKey; label: string; description: string }> = [
  { key: 'welcome', label: 'Receber quem chega', description: 'Mensagem, canal e cargo inicial.' },
  { key: 'roles', label: 'Dar escolhas aos membros', description: 'Painel de cargos com botões.' },
  { key: 'moderation', label: 'Moderação base', description: 'Registos e ações consistentes.' },
  { key: 'protection', label: 'Proteção automática', description: 'Perfis anti-spam e anti-raid.' },
];

const externalProviderForFeature = (key: string): ExternalProvider | null => {
  if (key === 'social.tiktok') return 'tiktok';
  if (key === 'social.instagram') return 'instagram';
  if (key === 'social.kick') return 'kick';
  if (key === 'social.bluesky') return 'bluesky';
  return null;
};

const externalSourceKey = (provider: ExternalProvider): string => {
  if (provider === 'tiktok' || provider === 'instagram') return 'username';
  return 'sourceHandle';
};

function defaultQuickSetupState(guildId: string): QuickSetupState {
  return {
    guildId,
    status: 'not_started',
    currentStep: 'welcome',
    revision: 0,
    steps: quickSetupSteps.map(({ key }) => ({ key, status: 'pending' })),
    createdResources: [],
  };
}

type QuickSetupFeatureDefaults = Partial<{
  welcome: FeatureConfig;
  roles: FeatureConfig;
  moderation: FeatureConfig;
  antiRaid: FeatureConfig;
  antiSpam: FeatureConfig;
}>;

function quickSetupDraft(
  featureDefaults: QuickSetupFeatureDefaults,
  useLocalCompatibilityDefaults: boolean,
): Record<QuickSetupStepKey, FeatureConfig> {
  // In the deployed panel the adapter response is authoritative.  The old
  // catalogue remains available only for the explicit local preview so a
  // disconnected designer preview does not pretend to be a server schema.
  const legacy = (key: string) => (useLocalCompatibilityDefaults ? (defaults[key] ?? {}) : {});
  const api = (key: keyof QuickSetupFeatureDefaults) => featureDefaults[key] ?? {};
  return {
    welcome: {
      ...legacy('support.welcome'),
      ...api('welcome'),
      mode: 'recommended',
      createChannel: true,
    },
    roles: {
      ...legacy('community.role_panels'),
      ...api('roles'),
      template: 'notifications',
      createChannel: true,
      roleNames: 'Announcements, Events, News',
    },
    moderation: { ...legacy('management.moderation'), ...api('moderation') },
    protection: { profile: 'balanced', logChannel: '', createChannel: true },
  };
}

function App() {
  const [youtubeSubscriptions, setYoutubeSubscriptions] = useState<YouTubeSubscription[]>([]);
  const [rssSubscriptions, setRssSubscriptions] = useState<RssSubscription[]>([]);
  const [twitchSubscriptions, setTwitchSubscriptions] = useState<TwitchSubscription[]>([]);
  const [externalSubscriptions, setExternalSubscriptions] = useState<
    Partial<Record<ExternalProvider, ExternalSubscription[]>>
  >({});
  const [studioTemplates, setStudioTemplates] = useState<StudioTemplate[]>([]);
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  const [me, setMe] = useState<Me | null>(null);
  const [guilds, setGuilds] = useState<Guild[]>(demoGuilds);
  const [guildContext, setGuildContext] = useState<GuildContext | null>(null);
  const [quickSetup, setQuickSetup] = useState<QuickSetupState | null>(null);
  const [quickSetupDefaults, setQuickSetupDefaults] = useState<QuickSetupFeatureDefaults>({});
  const [features, setFeatures] = useState<Feature[]>(() =>
    localPreviewMode ? demoFeatures.concat(additionalFeatures).map(presentFeature) : [],
  );
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [audit, setAudit] = useState<AuditRecord[]>([]);
  const [activity, setActivity] = useState<ActivityRecord[]>([]);
  const [stats, setStats] = useState({ totalCases: 0 });
  const [quota, setQuota] = useState({
    plan: 'Free',
    limits: {} as Record<string, number>,
    usage: {} as Record<string, number>,
  });
  const [rankConfig, setRankConfig] = useState(defaultRankCard);
  const [savedRankConfig, setSavedRankConfig] = useState(defaultRankCard);
  const [detailConfig, setDetailConfig] = useState<FeatureConfig>({});
  const [savedDetailConfig, setSavedDetailConfig] = useState<FeatureConfig>({});
  const [detailSchema, setDetailSchema] = useState<FeatureSchema | null>(null);
  const [detailEnabled, setDetailEnabled] = useState(false);
  const [detailRevision, setDetailRevision] = useState(0);
  const [providerHealth, setProviderHealth] = useState<ProviderSubscriptionHealth | null>(null);
  const [status, setStatus] = useState<'loading' | 'ready' | 'error' | 'auth' | 'saving'>(
    'loading',
  );
  const [message, setMessage] = useState('');
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<Category>('all');
  const [detailLoading, setDetailLoading] = useState(false);

  const navigate = (path: string) => {
    const next = parseRoute(path);
    if (window.location.hash === path) setRoute(next);
    else window.location.hash = path;
  };
  useEffect(() => {
    const onHash = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener('hashchange', onHash);
    if (!window.location.hash) window.location.hash = '#/';
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
      document.querySelector<HTMLElement>('[data-route-heading]')?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [route.page, route.key]);
  useEffect(() => {
    if (localPreviewMode) {
      setMe({
        id: 'demo',
        guildId: 'demo',
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        dbOk: true,
      });
      setStatus('ready');
      return;
    }
    void Promise.all([
      api.me(),
      api.guilds().catch(() => ({ guilds: demoGuilds })),
      api.features().catch(() => {
        // Do not present stale/demo state as the real guild catalogue.  Keep
        // the topics discoverable, but make every state explicitly blocked so
        // a failed API request cannot lead to a misleading publish action.
        setMessage('Feature state is unavailable until the Rust API reconnects.');
        return { guildId: '', features: unavailableFeatureCatalogue() };
      }),
      api.stats().catch(() => ({ totalCases: 0, guildId: '' })),
      api.cases().catch(() => ({ cases: [] })),
      api.audit().catch(() => ({ events: [] })),
      api.activity().catch(() => ({ activity: [] })),
      api.quotas().catch(() => ({ plan: 'Free', limits: {}, usage: {} })),
      api.rankCard().catch(() => ({ guildId: '', config: defaultRankCard })),
    ])
      .then(
        ([
          nextMe,
          nextGuilds,
          nextFeatures,
          nextStats,
          nextCases,
          nextAudit,
          nextActivity,
          nextQuota,
          nextRank,
        ]) => {
          setMe(nextMe);
          setGuilds(nextGuilds.guilds);
          setFeatures(nextFeatures.features.map(presentFeature));
          setStats(nextStats);
          setCases(nextCases.cases);
          setAudit(nextAudit.events);
          setActivity(nextActivity.activity);
          setQuota(nextQuota);
          setRankConfig(nextRank.config);
          setSavedRankConfig(nextRank.config);
          setStatus('ready');
        },
      )
      .catch((cause: unknown) => {
        setMessage(cause instanceof Error ? cause.message : 'Não foi possível carregar o painel.');
        setStatus('error');
      });
  }, []);
  useEffect(() => {
    const guildId = me?.guildId ?? 'demo';
    if (localPreviewMode) {
      try {
        const stored = localStorage.getItem(`vh_quick_setup_${guildId}`);
        setQuickSetup(
          stored ? (JSON.parse(stored) as QuickSetupState) : defaultQuickSetupState(guildId),
        );
      } catch {
        setQuickSetup(defaultQuickSetupState(guildId));
      }
      setGuildContext({
        guildId,
        name: guilds[0]?.name ?? 'Servidor de demonstração',
        permissions: 'demo',
        channels: [
          { id: 'demo-general', name: 'geral', type: 'text' },
          { id: 'demo-rules', name: 'regras', type: 'text' },
        ],
        roles: [{ id: 'demo-member', name: 'Membro', position: 1 }],
        hierarchy: { known: true },
        capabilities: { channelSelectors: true, roleSelectors: true, permissionPreflight: true },
        stale: false,
      });
      setQuickSetupDefaults({
        welcome: defaults['support.welcome'],
        roles: defaults['community.role_panels'],
        moderation: defaults['management.moderation'],
        antiRaid: defaults['protection.anti_raid'],
        antiSpam: defaults['protection.antispam'],
      });
      return;
    }
    void api
      .quickSetup()
      .then(setQuickSetup)
      .catch(() => setQuickSetup(defaultQuickSetupState(guildId)));
    void api
      .guildContext()
      .then(setGuildContext)
      .catch(() => undefined);
    // Quick Setup is a composition of real feature adapters.  Fetch their
    // defaults from Rust instead of reconstructing a second schema in React.
    void Promise.all(
      [
        ['welcome', 'support.welcome'],
        ['roles', 'community.role_panels'],
        ['moderation', 'management.moderation'],
        ['antiRaid', 'protection.anti_raid'],
        ['antiSpam', 'protection.antispam'],
      ].map(async ([name, key]) => {
        try {
          const detail = await api.feature(key);
          return [name, { ...(detail.defaults ?? {}), ...detail.config }] as const;
        } catch {
          return [name, {}] as const;
        }
      }),
    ).then((entries) => {
      setQuickSetupDefaults(Object.fromEntries(entries) as QuickSetupFeatureDefaults);
    });
  }, [me?.guildId, guilds]);
  useEffect(() => {
    if (route.page !== 'overview' || !quickSetup || quickSetup.status !== 'not_started') return;
    const key = `vh_quick_setup_intro_${quickSetup.guildId}`;
    try {
      if (sessionStorage.getItem(key)) return;
      sessionStorage.setItem(key, '1');
    } catch {
      /* storage opcional */
    }
    window.location.hash = '#/quick-setup';
  }, [route.page, quickSetup]);
  async function startLogin() {
    setAuthLoading(true);
    setAuthError('');
    try {
      await api.startOAuth();
    } catch (cause) {
      setAuthError(
        cause instanceof Error ? cause.message : 'Não foi possível iniciar o acesso com Discord.',
      );
      setAuthLoading(false);
    }
  }
  useEffect(() => {
    if (!localPreviewMode) {
      void api
        .youtubeSubscriptions()
        .then((result) => setYoutubeSubscriptions(result.subscriptions))
        .catch(() => undefined);
      void api
        .rssSubscriptions()
        .then((result) => setRssSubscriptions(result.subscriptions))
        .catch(() => undefined);
      void api
        .twitchSubscriptions()
        .then((result) => setTwitchSubscriptions(result.subscriptions))
        .catch(() => undefined);
      (['tiktok', 'instagram', 'kick', 'bluesky'] as ExternalProvider[]).forEach((provider) => {
        void api
          .externalSubscriptions(provider)
          .then((result) =>
            setExternalSubscriptions((current) => ({
              ...current,
              [provider]: result.subscriptions,
            })),
          )
          .catch(() => undefined);
      });
    }
  }, []);
  useEffect(() => {
    if (route.page !== 'detail' || !route.key) return;
    setDetailLoading(true);
    // Production configuration must never be reconstructed from a stale
    // client-side form.  Local defaults remain useful for the explicit
    // preview mode, but the Rust adapter is the only source of truth for the
    // deployed panel.
    const fallback = localPreviewMode ? (defaults[route.key] ?? {}) : {};
    if (localPreviewMode) {
      setDetailSchema(null);
      setDetailConfig({ ...fallback });
      setSavedDetailConfig({ ...fallback });
      setDetailEnabled(features.find((item) => item.key === route.key)?.enabled ?? false);
      setDetailLoading(false);
      return;
    }
    void api
      .feature(route.key)
      .then((result) => {
        setDetailSchema(result.schema ?? null);
        const apiDefaults = result.defaults ?? {};
        // The API adapter is the source of truth whenever it exposes a schema.
        // Local specs are only a compatibility fallback for the explicit
        // preview mode. In production, an API response without a schema is an
        // adapter outage, not permission to invent controls in the browser.
        const resolvedConfig = result.schema
          ? configForSchema(result.schema, apiDefaults, result.config)
          : localPreviewMode
            ? { ...fallback, ...apiDefaults, ...result.config }
            : { ...apiDefaults, ...result.config };
        setDetailConfig(resolvedConfig);
        setSavedDetailConfig(resolvedConfig);
        setDetailEnabled(result.enabled);
        setDetailRevision(result.revision ?? 0);
      })
      .catch(() => {
        setDetailSchema(null);
        setDetailConfig(localPreviewMode ? { ...fallback } : {});
        setSavedDetailConfig(localPreviewMode ? { ...fallback } : {});
        setDetailEnabled(features.find((item) => item.key === route.key)?.enabled ?? false);
        setDetailRevision(0);
      })
      .finally(() => setDetailLoading(false));
  }, [route.page, route.key, features]);
  useEffect(() => {
    if (
      route.page !== 'detail' ||
      !route.key ||
      !['management.templates', 'support.welcome', 'support.welcome_channel'].includes(route.key) ||
      localPreviewMode
    )
      return;
    void api
      .studioTemplates()
      .then((result) => setStudioTemplates(result.templates))
      .catch(() => setStudioTemplates([]));
  }, [route.page, route.key]);
  useEffect(() => {
    const subscription = route.key === 'social.youtube' ? youtubeSubscriptions[0] : undefined;
    if (route.page === 'detail' && route.key === 'social.youtube' && subscription) {
      setDetailConfig((current) => ({
        ...current,
        sourceChannelId: subscription.sourceChannelId,
        targetChannelId: subscription.targetChannelId,
        messageTemplate: subscription.messageTemplate,
        mention: subscription.mention,
        intervalSeconds: subscription.intervalSeconds,
      }));
      setSavedDetailConfig((current) => ({
        ...current,
        sourceChannelId: subscription.sourceChannelId,
        targetChannelId: subscription.targetChannelId,
        messageTemplate: subscription.messageTemplate,
        mention: subscription.mention,
        intervalSeconds: subscription.intervalSeconds,
      }));
      setDetailEnabled(subscription.enabled);
    }
  }, [route.page, route.key, youtubeSubscriptions]);
  useEffect(() => {
    const subscription =
      route.key === 'social.rss' || route.key === 'social.podcasts'
        ? rssSubscriptions[0]
        : undefined;
    if (
      route.page === 'detail' &&
      (route.key === 'social.rss' || route.key === 'social.podcasts') &&
      subscription
    ) {
      setDetailConfig((current) => ({
        ...current,
        feedUrl: subscription.feedUrl,
        targetChannelId: subscription.targetChannelId,
        messageTemplate: subscription.messageTemplate,
        mention: subscription.mention,
        intervalSeconds: subscription.intervalSeconds,
      }));
      setSavedDetailConfig((current) => ({
        ...current,
        feedUrl: subscription.feedUrl,
        targetChannelId: subscription.targetChannelId,
        messageTemplate: subscription.messageTemplate,
        mention: subscription.mention,
        intervalSeconds: subscription.intervalSeconds,
      }));
      setDetailEnabled(subscription.enabled);
    }
  }, [route.page, route.key, rssSubscriptions]);
  useEffect(() => {
    const subscription = route.key === 'social.twitch' ? twitchSubscriptions[0] : undefined;
    if (route.page === 'detail' && route.key === 'social.twitch' && subscription) {
      setDetailConfig((current) => ({
        ...current,
        sourceLogin: subscription.sourceLogin,
        targetChannelId: subscription.targetChannelId,
        messageTemplate: subscription.messageTemplate,
        mention: subscription.mention,
      }));
      setSavedDetailConfig((current) => ({
        ...current,
        sourceLogin: subscription.sourceLogin,
        targetChannelId: subscription.targetChannelId,
        messageTemplate: subscription.messageTemplate,
        mention: subscription.mention,
      }));
      setDetailEnabled(subscription.enabled);
    }
  }, [route.page, route.key, twitchSubscriptions]);
  useEffect(() => {
    setProviderHealth(null);
    if (localPreviewMode || route.page !== 'detail') return;
    let cancelled = false;
    const load = async () => {
      try {
        let health: ProviderSubscriptionHealth | null = null;
        if (route.key === 'social.youtube' && youtubeSubscriptions[0]) {
          health = await api.youtubeHealth(youtubeSubscriptions[0].id);
        } else if (
          (route.key === 'social.rss' || route.key === 'social.podcasts') &&
          rssSubscriptions[0]
        ) {
          health = await api.rssHealth(rssSubscriptions[0].id);
        } else if (route.key === 'social.twitch' && twitchSubscriptions[0]) {
          health = await api.twitchHealth(twitchSubscriptions[0].id);
        }
        if (!cancelled) setProviderHealth(health);
      } catch {
        if (!cancelled) setProviderHealth(null);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [route.page, route.key, youtubeSubscriptions, rssSubscriptions, twitchSubscriptions]);
  useEffect(() => {
    const provider = route.key ? externalProviderForFeature(route.key) : null;
    const subscription = provider ? externalSubscriptions[provider]?.[0] : undefined;
    if (route.page !== 'detail' || !provider || !subscription) return;
    const sourceKey = externalSourceKey(provider);
    const sourceValue = subscription[sourceKey as keyof ExternalSubscription];
    setDetailConfig((current) => ({
      ...current,
      [sourceKey]: typeof sourceValue === 'string' ? sourceValue : '',
      targetChannelId: subscription.targetChannelId,
      messageTemplate: subscription.messageTemplate,
      mention: subscription.mention,
      intervalSeconds: subscription.intervalSeconds,
    }));
    setSavedDetailConfig((current) => ({
      ...current,
      [sourceKey]: typeof sourceValue === 'string' ? sourceValue : '',
      targetChannelId: subscription.targetChannelId,
      messageTemplate: subscription.messageTemplate,
      mention: subscription.mention,
      intervalSeconds: subscription.intervalSeconds,
    }));
    setDetailEnabled(subscription.enabled);
  }, [route.page, route.key, externalSubscriptions]);

  const currentGuild = guilds.find((guild) => guild.id === me?.guildId) ?? guilds[0];
  const currentFeature = features.find((item) => item.key === route.key);
  const detailDirty = JSON.stringify(detailConfig) !== JSON.stringify(savedDetailConfig);
  const rankDirty = JSON.stringify(rankConfig) !== JSON.stringify(savedRankConfig);
  const dirty =
    route.page === 'detail' ? detailDirty : route.page === 'rank-card' ? rankDirty : false;
  const filteredFeatures = useMemo(() => {
    const unique = Array.from(new Map(features.map((item) => [item.key, item])).values());
    return unique.filter(
      (item) =>
        (filter === 'all' || item.category === filter) &&
        item.label.toLocaleLowerCase().includes(search.toLocaleLowerCase()),
    );
  }, [features, filter, search]);
  async function switchGuild(guildId: string) {
    if (localPreviewMode) {
      setMe((current) => (current ? { ...current, guildId } : current));
      return;
    }
    try {
      await api.switchGuild(guildId);
      window.location.reload();
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : 'Não foi possível trocar de servidor.');
    }
  }
  async function saveDetail() {
    if (!route.key) return;
    setStatus('saving');
    try {
      if (!localPreviewMode) {
        const preflight = await api.featurePreflight(route.key, detailConfig, detailEnabled);
        if (!preflight.ok) {
          setStatus('ready');
          setMessage(preflight.issues.map((issue) => issue.message).join(' '));
          return;
        }
      }
      const result = localPreviewMode
        ? { enabled: detailEnabled, config: detailConfig, revision: detailRevision }
        : await api.saveFeature(route.key, detailEnabled, detailConfig, detailRevision);
      if (
        !localPreviewMode &&
        route.key === 'community.role_panels' &&
        detailEnabled &&
        typeof detailConfig.channel === 'string' &&
        Array.isArray(detailConfig.roleIds) &&
        detailConfig.roleIds.length > 0
      ) {
        const existingPanels = await api.rolePanels();
        const panelPayload = {
          channel: detailConfig.channel,
          title: String(detailConfig.panelTitle ?? 'Choose your roles'),
          description: String(detailConfig.panelDescription ?? ''),
          roleIds: detailConfig.roleIds.map(String),
          selectionMode:
            detailConfig.selectionMode === 'unique' ? ('unique' as const) : ('multiple' as const),
          removeOnUnselect: detailConfig.removeOnUnselect !== false,
        };
        if (existingPanels.panels[0]) {
          await api.updateRolePanel(existingPanels.panels[0].message_id, panelPayload);
        } else {
          await api.createRolePanel(panelPayload);
        }
      }
      setFeatures((items) =>
        items.map((item) => (item.key === route.key ? { ...item, enabled: result.enabled } : item)),
      );
      setDetailConfig(result.config);
      setSavedDetailConfig(result.config);
      setDetailRevision(result.revision ?? detailRevision);
      setStatus('ready');
      setMessage(
        localPreviewMode
          ? 'Pré-visualização guardada neste navegador.'
          : 'Configuração publicada no servidor.',
      );
    } catch (cause) {
      setStatus('error');
      setMessage(cause instanceof Error ? cause.message : 'Não foi possível guardar.');
    }
  }
  async function repairDetail() {
    if (!route.key || localPreviewMode) return;
    setStatus('saving');
    try {
      const result = await api.repairFeature(route.key);
      setDetailConfig(result.config);
      setSavedDetailConfig(result.config);
      setDetailEnabled(result.enabled);
      setDetailRevision(result.revision ?? detailRevision);
      setFeatures((items) =>
        items.map((item) =>
          item.key === route.key
            ? { ...item, enabled: result.enabled, health: result.health, maturity: result.maturity }
            : item,
        ),
      );
      setStatus('ready');
      setMessage('A publicação foi reparada e uma nova revisão foi criada.');
    } catch (cause) {
      setStatus('error');
      setMessage(cause instanceof Error ? cause.message : 'Não foi possível reparar a publicação.');
    }
  }
  async function testDetail() {
    if (!route.key) return;
    try {
      if (route.key === 'social.youtube') {
        const sourceChannelId = String(detailConfig.sourceChannelId ?? '').trim();
        if (!sourceChannelId) {
          setMessage('Indica primeiro o ID do canal YouTube.');
          return;
        }
        if (localPreviewMode) {
          setMessage('A validação do canal YouTube aparece quando o painel estiver ligado à API.');
          return;
        }
        const subscription = youtubeSubscriptions[0];
        if (!subscription) {
          setMessage('Guarda primeiro a subscrição para poderes enviar um teste para o Discord.');
          return;
        }
        const result = await api.testYoutubeDelivery(subscription.id, {
          sourceChannelId,
          targetChannelId: String(detailConfig.targetChannelId ?? subscription.targetChannelId),
          messageTemplate: String(detailConfig.messageTemplate ?? subscription.messageTemplate),
          mention: String(detailConfig.mention ?? subscription.mention),
          intervalSeconds: Number(detailConfig.intervalSeconds ?? subscription.intervalSeconds),
          enabled: Boolean(detailEnabled),
        });
        setMessage(
          result.delivered
            ? 'Mensagem de teste enviada para o canal Discord configurado. O cursor do YouTube não foi alterado.'
            : 'O teste não foi entregue.',
        );
        return;
      }
      if (route.key === 'social.rss' || route.key === 'social.podcasts') {
        const feedUrl = String(detailConfig.feedUrl ?? '').trim();
        if (!feedUrl) {
          setMessage('Indica primeiro o URL do feed RSS/Atom.');
          return;
        }
        if (localPreviewMode) {
          setMessage('A confirmação do feed aparece quando o painel estiver ligado à API.');
          return;
        }
        const subscription = rssSubscriptions[0];
        if (!subscription) {
          setMessage('Guarda primeiro a subscrição para poderes enviar um teste para o Discord.');
          return;
        }
        const result = await api.testRssDelivery(subscription.id, {
          feedUrl,
          targetChannelId: String(detailConfig.targetChannelId ?? subscription.targetChannelId),
          messageTemplate: String(detailConfig.messageTemplate ?? subscription.messageTemplate),
          mention: String(detailConfig.mention ?? subscription.mention),
          intervalSeconds: Number(detailConfig.intervalSeconds ?? subscription.intervalSeconds),
          enabled: Boolean(detailEnabled),
        });
        setMessage(
          result.delivered
            ? 'Mensagem de teste enviada para o canal Discord configurado. O cursor do feed não foi alterado.'
            : 'O teste não foi entregue.',
        );
        return;
      }
      if (route.key === 'social.twitch') {
        const login = String(detailConfig.sourceLogin ?? '').trim();
        if (!login) {
          setMessage('Indica primeiro o nome do canal Twitch.');
          return;
        }
        if (localPreviewMode) {
          setMessage('A validação do canal Twitch aparece quando o painel estiver ligado à API.');
          return;
        }
        const subscription = twitchSubscriptions[0];
        if (!subscription) {
          setMessage('Guarda primeiro a subscrição para poderes enviar um teste para o Discord.');
          return;
        }
        const result = await api.testTwitchDelivery(subscription.id, {
          sourceLogin: login,
          targetChannelId: String(detailConfig.targetChannelId ?? subscription.targetChannelId),
          messageTemplate: String(detailConfig.messageTemplate ?? subscription.messageTemplate),
          mention: String(detailConfig.mention ?? subscription.mention),
          enabled: Boolean(detailEnabled),
        });
        setMessage(
          result.delivered
            ? 'Mensagem de teste enviada para o canal Discord configurado. Nenhum evento EventSub foi consumido.'
            : 'O teste não foi entregue.',
        );
        return;
      }
      if (route.key === 'social.tiktok') {
        const username = String(detailConfig.username ?? detailConfig.sourceLabel ?? '').trim();
        if (!username) {
          setMessage('Indica primeiro o nome da conta TikTok.');
          return;
        }
        if (localPreviewMode) {
          setMessage('O teste TikTok aparece quando o painel estiver ligado à API.');
          return;
        }
        const subscription = externalSubscriptions.tiktok?.[0];
        if (!subscription) {
          setMessage('Guarda primeiro a subscrição para poderes enviar um teste para o Discord.');
          return;
        }
        const result = await api.testTikTokDelivery(subscription.id, {
          username,
          targetChannelId: String(detailConfig.targetChannelId ?? subscription.targetChannelId),
          messageTemplate: String(detailConfig.messageTemplate ?? subscription.messageTemplate),
          mention: String(detailConfig.mention ?? subscription.mention),
          intervalSeconds: Number(detailConfig.intervalSeconds ?? subscription.intervalSeconds),
          enabled: Boolean(detailEnabled),
        });
        setMessage(
          result.delivered
            ? 'Mensagem de teste TikTok enviada para o Discord. O cursor de monitorização não foi alterado.'
            : 'O teste TikTok não foi entregue.',
        );
        return;
      }
      const result = await api.testFeature(route.key, detailConfig);
      const errors = result.result.issues.filter((issue) => issue.severity === 'error');
      const decision = result.decision;
      const decisionText = decision ? ` · ${decision.reason}` : '';
      setMessage(
        errors.length
          ? errors.map((issue) => issue.message).join(' ')
          : result.result.effects.length
            ? `Simulação: ${result.result.effects.join(' · ')}${decisionText}`
            : 'Simulação concluída — nenhuma ação real foi aplicada.',
      );
    } catch {
      setMessage(
        route.key === 'social.rss' || route.key === 'social.podcasts'
          ? 'Não foi possível ler este feed. Confirma o URL e tenta novamente.'
          : route.key === 'social.twitch'
            ? 'Não foi possível validar o canal Twitch. Confirma o nome e as credenciais do servidor.'
            : 'A simulação está disponível quando a API estiver ligada.',
      );
    }
  }
  async function saveRankCard() {
    setStatus('saving');
    try {
      const result = localPreviewMode ? { config: rankConfig } : await api.saveRankCard(rankConfig);
      setRankConfig(result.config);
      setSavedRankConfig(result.config);
      setStatus('ready');
      setMessage(
        localPreviewMode
          ? 'Pré-visualização guardada neste navegador.'
          : 'XP card publicado no servidor.',
      );
    } catch (cause) {
      setStatus('error');
      setMessage(cause instanceof Error ? cause.message : 'Não foi possível publicar.');
    }
  }
  async function applyQuickSetupStep(
    step: QuickSetupStepKey,
    config: FeatureConfig,
    enabled = true,
  ): Promise<boolean> {
    setStatus('saving');
    try {
      const writes: Array<{ key: string; config: FeatureConfig; enabled: boolean }> = [];
      if (step === 'welcome') writes.push({ key: 'support.welcome', config, enabled });
      if (step === 'roles') writes.push({ key: 'community.role_panels', config, enabled });
      if (step === 'moderation') writes.push({ key: 'management.moderation', config, enabled });
      if (step === 'protection') {
        const profile = String(config.profile ?? 'balanced');
        const profiles: Record<string, { antispam: FeatureConfig; antiRaid: FeatureConfig }> = {
          monitor: {
            antispam: {
              ...quickSetupDefaults.antiSpam,
              floodCount: 8,
              windowSeconds: 10,
              duplicateLimit: 4,
              maxLinks: 8,
              capsPercent: 90,
              capsMinLetters: 12,
              deleteMessage: false,
              timeoutSeconds: 0,
              mentionLimit: 8,
              ignoredChannels: [],
              ignoredRoles: [],
              alertOnly: true,
              logChannel: config.logChannel ?? '',
            },
            antiRaid: {
              ...quickSetupDefaults.antiRaid,
              joinThreshold: 12,
              windowSeconds: 20,
              incidentMinutes: 10,
              verification: 'high',
              pauseInvites: true,
              alertOnly: true,
              alertChannel: config.logChannel ?? '',
            },
          },
          balanced: {
            antispam: {
              ...quickSetupDefaults.antiSpam,
              floodCount: 6,
              windowSeconds: 10,
              duplicateLimit: 3,
              maxLinks: 5,
              capsPercent: 80,
              capsMinLetters: 8,
              deleteMessage: false,
              timeoutSeconds: 60,
              mentionLimit: 5,
              ignoredChannels: [],
              ignoredRoles: [],
              alertOnly: false,
              logChannel: config.logChannel ?? '',
            },
            antiRaid: {
              ...quickSetupDefaults.antiRaid,
              joinThreshold: 10,
              windowSeconds: 20,
              incidentMinutes: 10,
              verification: 'high',
              pauseInvites: true,
              alertOnly: true,
              alertChannel: config.logChannel ?? '',
            },
          },
          strict: {
            antispam: {
              ...quickSetupDefaults.antiSpam,
              floodCount: 5,
              windowSeconds: 10,
              duplicateLimit: 2,
              maxLinks: 3,
              capsPercent: 75,
              capsMinLetters: 8,
              deleteMessage: true,
              timeoutSeconds: 300,
              mentionLimit: 4,
              ignoredChannels: [],
              ignoredRoles: [],
              alertOnly: false,
              logChannel: config.logChannel ?? '',
            },
            antiRaid: {
              ...quickSetupDefaults.antiRaid,
              joinThreshold: 8,
              windowSeconds: 20,
              incidentMinutes: 10,
              verification: 'high',
              pauseInvites: true,
              alertOnly: false,
              alertChannel: config.logChannel ?? '',
            },
          },
        };
        const selected = profiles[profile] ?? profiles.balanced;
        writes.push({ key: 'protection.antispam', config: selected.antispam, enabled });
        writes.push({ key: 'protection.anti_raid', config: selected.antiRaid, enabled });
      }
      // Welcome and role-panel publication is handled atomically by the
      // Quick Setup endpoint. Protection/moderation still use the regular
      // feature endpoint because their profile expands into multiple policies
      // and must preserve the existing projections.
      if (!localPreviewMode && (step === 'protection' || step === 'moderation'))
        for (const write of writes) await api.saveFeature(write.key, write.enabled, write.config);
      const previous = quickSetup ?? defaultQuickSetupState(me?.guildId ?? 'demo');
      const next = localPreviewMode
        ? {
            ...previous,
            revision: previous.revision + 1,
            status: 'in_progress' as const,
            steps: previous.steps.map((item) =>
              item.key === step ? { ...item, status: 'applied' as const } : item,
            ),
          }
        : await api.saveQuickSetupStep(step, {
            status: 'applied',
            config,
            enabled,
            expectedRevision: previous.revision,
          });
      if (!localPreviewMode && next.draft && step === 'protection') {
        const normalizedConfig = next.draft as FeatureConfig;
        const channelId = String(normalizedConfig.logChannel ?? '').trim();
        if (channelId) {
          const antispam = writes.find((write) => write.key === 'protection.antispam');
          const antiRaid = writes.find((write) => write.key === 'protection.anti_raid');
          if (antispam)
            await api.saveFeature(antispam.key, antispam.enabled, {
              ...antispam.config,
              logChannel: channelId,
            });
          if (antiRaid)
            await api.saveFeature(antiRaid.key, antiRaid.enabled, {
              ...antiRaid.config,
              alertChannel: channelId,
            });
        }
      }
      const normalized = next.steps.every((item) => item.status !== 'pending')
        ? { ...next, status: 'completed' as const, currentStep: null }
        : next;
      setQuickSetup(normalized);
      if (localPreviewMode)
        localStorage.setItem(`vh_quick_setup_${me?.guildId ?? 'demo'}`, JSON.stringify(normalized));
      setFeatures((items) =>
        items.map((item) =>
          writes.some((write) => write.key === item.key) ? { ...item, enabled } : item,
        ),
      );
      setStatus('ready');
      setMessage(
        `${quickSetupSteps.find((item) => item.key === step)?.label ?? 'Etapa'} aplicada.`,
      );
      return true;
    } catch (cause) {
      setStatus('error');
      setMessage(cause instanceof Error ? cause.message : 'Não foi possível aplicar esta etapa.');
      return false;
    }
  }
  async function skipQuickSetupStep(step: QuickSetupStepKey): Promise<boolean> {
    try {
      const previous = quickSetup ?? defaultQuickSetupState(me?.guildId ?? 'demo');
      const next = localPreviewMode
        ? {
            ...previous,
            revision: previous.revision + 1,
            status: 'in_progress' as const,
            steps: previous.steps.map((item) =>
              item.key === step ? { ...item, status: 'skipped' as const } : item,
            ),
          }
        : await api.saveQuickSetupStep(step, {
            status: 'skipped',
            expectedRevision: previous.revision,
          });
      setQuickSetup(next);
      if (localPreviewMode)
        localStorage.setItem(`vh_quick_setup_${me?.guildId ?? 'demo'}`, JSON.stringify(next));
      return true;
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : 'Não foi possível saltar esta etapa.');
      return false;
    }
  }
  async function dismissQuickSetup() {
    try {
      const next = localPreviewMode
        ? {
            ...(quickSetup ?? defaultQuickSetupState(me?.guildId ?? 'demo')),
            status: 'dismissed' as const,
          }
        : await api.dismissQuickSetup();
      setQuickSetup(next);
      if (localPreviewMode)
        localStorage.setItem(`vh_quick_setup_${me?.guildId ?? 'demo'}`, JSON.stringify(next));
    } catch {
      setMessage('A configuração rápida continua disponível na barra lateral.');
    }
  }
  if (status === 'loading')
    return (
      <div className="center" role="status" aria-live="polite" aria-busy="true">
        <div className="loader" />
        <p>A preparar o teu espaço de trabalho…</p>
      </div>
    );
  if ((status === 'auth' || status === 'error') && !me)
    return (
      <AuthScreen
        error={status === 'auth' ? authError : message}
        loading={authLoading}
        onLogin={() => void startLogin()}
      />
    );
  const title =
    route.page === 'detail'
      ? (currentFeature?.label ?? 'Configuração')
      : (pages.find((item) => item.id === route.page)?.label ?? 'Painel');
  const subtitle =
    route.page === 'overview'
      ? 'O essencial para deixares o servidor pronto.'
      : route.page === 'quick-setup'
        ? 'Prepara o essencial por etapas curtas, com revisão antes de publicar.'
        : route.page === 'features'
          ? 'Escolhe um tópico para abrir a configuração completa.'
          : route.page === 'activity'
            ? 'Vê o que aconteceu e mantém o controlo.'
            : route.page === 'rank-card'
              ? 'Cria uma carta de nível com a identidade do teu servidor.'
              : 'Configuração por servidor, com opções simples e avançadas.';
  return (
    <div className="shell panel-shell">
      <aside className="sidebar panel-sidebar">
        <div className="logo panel-logo">
          <span>✦</span>
          <div>
            <strong>VOZEN</strong>
            <small>HELPER PANEL</small>
          </div>
        </div>
        <div className="workspace panel-workspace">
          <small>SERVIDOR ATUAL</small>
          <select
            aria-label="Servidor atual"
            value={currentGuild?.id ?? ''}
            onChange={(event) => void switchGuild(event.target.value)}
          >
            {guilds.map((guild) => (
              <option value={guild.id} key={guild.id}>
                {guild.name}
              </option>
            ))}
          </select>
          <p>As alterações ficam isoladas neste servidor.</p>
        </div>
        <nav className="panel-nav" aria-label="Navegação principal">
          {pages.map((item) => (
            <button
              key={item.id}
              type="button"
              className={
                route.page === item.id || (item.id === 'features' && route.page === 'detail')
                  ? 'nav active'
                  : 'nav'
              }
              aria-current={
                route.page === item.id || (item.id === 'features' && route.page === 'detail')
                  ? 'page'
                  : undefined
              }
              onClick={() => navigate(item.id === 'overview' ? '#/' : `#/${item.id}`)}
            >
              <span>{item.icon}</span>
              <div>
                <b>{item.label}</b>
                <small>{item.hint}</small>
              </div>
            </button>
          ))}
        </nav>
        <div className="runtime">
          <i /> {localPreviewMode ? 'Pré-visualização local' : 'Sincronizado com Rust'}
        </div>
      </aside>
      <main className="main panel-main" aria-labelledby="route-heading">
        <header className="panel-header">
          <div>
            <small className="eyebrow">{currentGuild?.name ?? 'WORKSPACE'} · HELPER</small>
            <h1 id="route-heading" data-route-heading tabIndex={-1}>
              {title}
            </h1>
            <p className="subtitle">{subtitle}</p>
          </div>
          <div className="header-state">
            <span className="status-dot" />{' '}
            {dirty
              ? 'Rascunho por publicar'
              : localPreviewMode
                ? 'Modo de demonstração'
                : 'Tudo sincronizado'}
          </div>
        </header>
        {message && (
          <div className="toast panel-toast" role="status">
            {message}
            <button type="button" aria-label="Fechar" onClick={() => setMessage('')}>
              ×
            </button>
          </div>
        )}
        {guildContext && !localPreviewMode && guildContext.stale && (
          <div className="toast panel-toast" role="status">
            O contexto do Discord precisa de ser atualizado antes de publicar alterações.{' '}
            {guildContext.bot?.reason === 'discord_bot_member_unavailable'
              ? 'Não foi possível confirmar o cargo e as permissões do Helper.'
              : (guildContext.message ??
                'Os seletores continuam disponíveis, mas o preflight está bloqueado.')}
          </div>
        )}
        {route.page === 'overview' && (
          <Overview
            features={features}
            stats={stats}
            quota={quota}
            cases={cases}
            onOpen={navigate}
          />
        )}
        {route.page === 'quick-setup' && (
          <QuickSetup
            state={quickSetup ?? defaultQuickSetupState(currentGuild?.id ?? 'demo')}
            context={guildContext}
            featureDefaults={quickSetupDefaults}
            localCompatibilityDefaults={localPreviewMode}
            onApply={applyQuickSetupStep}
            onSkip={skipQuickSetupStep}
            onDismiss={() => void dismissQuickSetup()}
            onOpen={navigate}
          />
        )}
        {route.page === 'features' && (
          <FeatureCatalogue
            features={filteredFeatures}
            filter={filter}
            setFilter={setFilter}
            search={search}
            setSearch={setSearch}
            onOpen={(key) =>
              navigate(
                key === 'studio.rank_card' ? '#/rank-card' : `#/config/${encodeURIComponent(key)}`,
              )
            }
          />
        )}
        {route.page === 'activity' && <Activity cases={cases} audit={audit} activity={activity} />}
        {route.page === 'rank-card' && (
          <RankCardEditor
            config={rankConfig}
            patch={(next) => setRankConfig((current) => ({ ...current, ...next }))}
            onSave={() => void saveRankCard()}
            onReset={() => setRankConfig(defaultRankCard)}
            saving={status === 'saving'}
          />
        )}
        {route.page === 'detail' &&
          (detailLoading ? (
            <div className="loading-card card">
              <div className="loader" />
              <span>A carregar configuração…</span>
            </div>
          ) : (
            <FeatureDetail
              feature={currentFeature}
              schema={detailSchema}
              context={guildContext}
              config={detailConfig}
              enabled={detailEnabled}
              revision={detailRevision}
              onEnabled={setDetailEnabled}
              onChange={(key, value) =>
                setDetailConfig((current) => ({ ...current, [key]: value }))
              }
              onSave={() => void saveDetail()}
              onRepair={() => void repairDetail()}
              onDiscard={() => {
                setDetailConfig(savedDetailConfig);
                setDetailEnabled(features.find((item) => item.key === route.key)?.enabled ?? false);
              }}
              onTest={() => void testDetail()}
              templates={studioTemplates}
              onTemplatesChange={setStudioTemplates}
              providerHealth={providerHealth}
              saving={status === 'saving'}
              onBack={() => navigate('#/features')}
            />
          ))}
      </main>
    </div>
  );
}

function QuickSetup({
  state,
  context,
  featureDefaults,
  localCompatibilityDefaults,
  onApply,
  onSkip,
  onDismiss,
  onOpen,
}: {
  state: QuickSetupState;
  context: GuildContext | null;
  featureDefaults: QuickSetupFeatureDefaults;
  localCompatibilityDefaults: boolean;
  onApply: (step: QuickSetupStepKey, config: FeatureConfig, enabled?: boolean) => Promise<boolean>;
  onSkip: (step: QuickSetupStepKey) => Promise<boolean>;
  onDismiss: () => void;
  onOpen: (path: string) => void;
}) {
  const [started, setStarted] = useState(
    state.status === 'in_progress' || state.status === 'completed',
  );
  const [index, setIndex] = useState(
    Math.max(
      0,
      quickSetupSteps.findIndex((item) => item.key === state.currentStep),
    ),
  );
  const [applying, setApplying] = useState(false);
  const [draft, setDraft] = useState<Record<QuickSetupStepKey, FeatureConfig>>(() =>
    quickSetupDraft(featureDefaults, localCompatibilityDefaults),
  );
  useEffect(() => {
    setDraft(quickSetupDraft(featureDefaults, localCompatibilityDefaults));
  }, [featureDefaults, localCompatibilityDefaults]);
  useEffect(() => {
    setStarted(state.status === 'in_progress' || state.status === 'completed');
    const next = quickSetupSteps.findIndex((item) => item.key === state.currentStep);
    if (next >= 0) setIndex(next);
  }, [state.status, state.currentStep]);
  const current = quickSetupSteps[index] ?? quickSetupSteps[0];
  const completed =
    state.status === 'completed' || state.steps.every((item) => item.status !== 'pending');
  const patch = (key: string, value: unknown) =>
    setDraft((currentDraft) => ({
      ...currentDraft,
      [current.key]: { ...currentDraft[current.key], [key]: value },
    }));
  const apply = async () => {
    setApplying(true);
    const ok = await onApply(
      current.key,
      draft[current.key],
      current.key !== 'welcome' || draft[current.key].mode !== 'off',
    );
    setApplying(false);
    if (ok && index < quickSetupSteps.length - 1) setIndex((value) => value + 1);
  };
  const skip = async () => {
    setApplying(true);
    const ok = await onSkip(current.key);
    setApplying(false);
    if (ok && index < quickSetupSteps.length - 1) setIndex((value) => value + 1);
  };
  if (!started && !completed)
    return (
      <section className="quick-setup-page">
        <div className="quick-setup-hero card">
          <div className="quick-setup-mark">✧</div>
          <small className="eyebrow">CONFIGURAÇÃO GUIADA · 2–4 MIN</small>
          <h2>Põe o essencial a funcionar.</h2>
          <p>
            Escolhe as bases do teu servidor. O Vozen mostra cada alteração antes de a aplicar e
            guarda o progresso por servidor.
          </p>
          <div className="quick-setup-meta">
            <span>
              Servidor: <b>{context?.name ?? state.guildId}</b>
            </span>
            <span>
              {context?.capabilities.permissionPreflight
                ? 'Permissões verificadas'
                : 'Verificação de permissões pendente'}
            </span>
          </div>
          <div className="actions">
            <button type="button" className="secondary" onClick={onDismiss}>
              Agora não
            </button>
            <button type="button" className="primary" onClick={() => setStarted(true)}>
              Preparar servidor <span>→</span>
            </button>
          </div>
        </div>
      </section>
    );
  if (completed)
    return (
      <section className="quick-setup-page">
        <div className="quick-setup-complete card">
          <span className="success-mark">✓</span>
          <small className="eyebrow">SERVIDOR PREPARADO</small>
          <h2>Está tudo pronto.</h2>
          <p>
            As escolhas do Quick Setup foram guardadas. Podes voltar aqui sempre que quiseres rever
            o essencial.
          </p>
          <div className="setup-summary">
            {state.steps.map((step) => (
              <div key={step.key}>
                <span className={step.status === 'applied' ? 'summary-icon done' : 'summary-icon'}>
                  {step.status === 'applied' ? '✓' : '–'}
                </span>
                <div>
                  <b>{quickSetupSteps.find((item) => item.key === step.key)?.label}</b>
                  <small>
                    {step.status === 'applied' ? 'Aplicado no servidor' : 'Ignorado nesta sessão'}
                  </small>
                </div>
              </div>
            ))}
          </div>
          <div className="premium-panel">
            <small className="eyebrow">QUANDO QUISERES IR MAIS LONGE</small>
            <h3>Funcionalidades Premium para o próximo passo</h3>
            <div className="premium-grid">
              <PremiumCard
                icon="↗"
                title="Níveis e XP"
                text="Recompensas, anúncios de nível e XP card."
              />
              <PremiumCard
                icon="□"
                title="Tickets avançados"
                text="Equipas, transcripts e SLA para suporte."
              />
              <PremiumCard
                icon="⌁"
                title="Automações"
                text="Liga eventos do servidor a ações personalizadas."
              />
            </div>
            <button type="button" className="secondary" onClick={() => onOpen('#/features')}>
              Ver todas as funcionalidades
            </button>
          </div>
        </div>
      </section>
    );
  const currentConfig = draft[current.key];
  const channels = context?.channels ?? [];
  const roles = context?.roles ?? [];
  const resourceName =
    current.key === 'welcome'
      ? '#boas-vindas'
      : current.key === 'roles'
        ? '#escolhe-cargos'
        : '#vozen-alertas';
  return (
    <section className="quick-setup-page">
      <div className="quick-setup-head">
        <div>
          <small className="eyebrow">
            QUICK SETUP · {index + 1} DE {quickSetupSteps.length}
          </small>
          <h2>Configura o essencial do servidor.</h2>
          <p>Aplicamos uma etapa de cada vez. Voltar não desfaz alterações já publicadas.</p>
        </div>
        <button type="button" className="link-button" onClick={onDismiss}>
          Sair por agora
        </button>
      </div>
      <div className="setup-progress" aria-label="Progresso da configuração">
        {quickSetupSteps.map((step, stepIndex) => (
          <button
            key={step.key}
            type="button"
            className={
              stepIndex === index
                ? 'progress-step active'
                : state.steps.find((item) => item.key === step.key)?.status === 'applied'
                  ? 'progress-step done'
                  : 'progress-step'
            }
            onClick={() => stepIndex <= index && setIndex(stepIndex)}
          >
            <span>
              {state.steps.find((item) => item.key === step.key)?.status === 'applied'
                ? '✓'
                : stepIndex + 1}
            </span>
            <b>{step.label}</b>
          </button>
        ))}
      </div>
      <div className="quick-setup-layout">
        <div className="quick-setup-form card">
          <small className="eyebrow">ETAPA {index + 1}</small>
          <h3>{current.label}</h3>
          <p className="setup-description">{current.description}</p>
          {current.key === 'welcome' && (
            <>
              <div className="choice-grid">
                <Choice
                  selected={currentConfig.mode === 'recommended'}
                  title="Mensagem recomendada"
                  text="Uma receção curta, clara e pronta a usar."
                  onClick={() => patch('mode', 'recommended')}
                />
                <Choice
                  selected={currentConfig.mode === 'custom'}
                  title="Personalizar"
                  text="Escreve a tua mensagem e escolhe as opções."
                  onClick={() => patch('mode', 'custom')}
                />
                <Choice
                  selected={currentConfig.mode === 'off'}
                  title="Desativar"
                  text="Não publicar mensagens de entrada."
                  onClick={() => patch('mode', 'off')}
                />
              </div>
              {currentConfig.mode !== 'off' && (
                <>
                  <SelectField
                    label="Canal de entrada"
                    value={String(currentConfig.channel ?? '')}
                    options={channels}
                    placeholder="Escolhe um canal"
                    onChange={(value) => patch('channel', value)}
                  />
                  <label className="field toggle-field">
                    <span>
                      <b>Criar #boas-vindas se não existir</b>
                      <small>O Vozen mostra a criação no resumo antes de confirmar.</small>
                    </span>
                    <input
                      type="checkbox"
                      checked={Boolean(currentConfig.createChannel)}
                      onChange={(event) => patch('createChannel', event.target.checked)}
                    />
                  </label>
                  <label className="field">
                    <span>
                      <b>Mensagem pública</b>
                      <small>
                        Podes usar {`{member}`} e {`{server}`}.
                      </small>
                    </span>
                    <textarea
                      rows={3}
                      value={String(currentConfig.message ?? '')}
                      onChange={(event) => patch('message', event.target.value)}
                    />
                  </label>
                </>
              )}
            </>
          )}
          {current.key === 'roles' && (
            <>
              <div className="template-row">
                <b>Escolhe um ponto de partida</b>
                <div>
                  {[
                    ['notifications', 'Notificações'],
                    ['interests', 'Interesses'],
                    ['languages', 'Idiomas'],
                  ].map(([id, label]) => (
                    <button
                      type="button"
                      key={id}
                      className={currentConfig.template === id ? 'template selected' : 'template'}
                      onClick={() => patch('template', id)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <SelectField
                label="Canal do painel"
                value={String(currentConfig.channel ?? '')}
                options={channels}
                placeholder="Escolhe um canal"
                onChange={(value) => patch('channel', value)}
              />
              <label className="field toggle-field">
                <span>
                  <b>Criar #escolhe-cargos se não existir</b>
                  <small>Os cargos ficam sem permissões administrativas.</small>
                </span>
                <input
                  type="checkbox"
                  checked={Boolean(currentConfig.createChannel)}
                  onChange={(event) => patch('createChannel', event.target.checked)}
                />
              </label>
              <label className="field">
                <span>
                  <b>Nomes dos cargos</b>
                  <small>Separa os nomes por vírgulas.</small>
                </span>
                <input
                  value={String(currentConfig.roleNames ?? '')}
                  onChange={(event) => patch('roleNames', event.target.value)}
                />
              </label>
            </>
          )}
          {current.key === 'moderation' && (
            <>
              <label className="field toggle-field">
                <span>
                  <b>Exigir motivo nas ações</b>
                  <small>Ajuda a equipa a manter uma auditoria clara e consistente.</small>
                </span>
                <input
                  type="checkbox"
                  checked={currentConfig.requireReason !== false}
                  onChange={(event) => patch('requireReason', event.target.checked)}
                />
              </label>
              <label className="field">
                <span>
                  <b>Limite de limpeza por ação</b>
                  <small>Protege contra purgas acidentais e respeita os limites do Discord.</small>
                </span>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={Number(currentConfig.maxPurge ?? 100)}
                  onChange={(event) => patch('maxPurge', Number(event.target.value))}
                />
              </label>
              <div className="notice">
                As regras de auditoria e o canal de registos são configurados em Auditoria e
                permissões, para não duplicar definições.
              </div>
            </>
          )}
          {current.key === 'protection' && (
            <>
              <div className="choice-grid">
                <Choice
                  selected={currentConfig.profile === 'monitor'}
                  title="Monitorizar"
                  text="Avisa a equipa sem castigar membros."
                  onClick={() => patch('profile', 'monitor')}
                />
                <Choice
                  selected={currentConfig.profile === 'balanced'}
                  title="Equilibrado"
                  text="Recomendado para a maioria dos servidores."
                  onClick={() => patch('profile', 'balanced')}
                />
                <Choice
                  selected={currentConfig.profile === 'strict'}
                  title="Reforçado"
                  text="Limites apertados para comunidades maiores."
                  onClick={() => patch('profile', 'strict')}
                />
              </div>
              <SelectField
                label="Canal de alertas"
                value={String(currentConfig.logChannel ?? '')}
                options={channels}
                placeholder="Escolhe um canal"
                onChange={(value) => patch('logChannel', value)}
              />
              <label className="field toggle-field">
                <span>
                  <b>Criar #vozen-alertas se não existir</b>
                  <small>O nome é apenas uma sugestão; revê-o antes de aplicar.</small>
                </span>
                <input
                  type="checkbox"
                  checked={Boolean(currentConfig.createChannel)}
                  onChange={(event) => patch('createChannel', event.target.checked)}
                />
              </label>
              <div className="notice">
                O perfil altera anti-spam e anti-raid com valores transparentes e reversíveis.
              </div>
            </>
          )}
        </div>
        <aside className="quick-setup-aside card">
          <small className="eyebrow">ANTES DE APLICAR</small>
          <h3>Pré-visualização</h3>
          <div className="discord-preview">
            <span className="preview-avatar">✦</span>
            <div>
              <b>
                {current.key === 'roles'
                  ? 'Painel de escolhas'
                  : current.key === 'protection'
                    ? 'Proteção do servidor'
                    : current.key === 'moderation'
                      ? 'Registo de moderação'
                      : 'Bem-vindo ao servidor'}
              </b>
              <p>
                {current.key === 'roles'
                  ? 'Escolhe as opções que combinam contigo.'
                  : current.key === 'protection'
                    ? 'Perfil ' +
                      String(currentConfig.profile ?? 'balanced') +
                      ' · ações reversíveis.'
                    : current.key === 'moderation'
                      ? 'As ações da equipa ficam registadas.'
                      : String(currentConfig.message ?? 'A tua comunidade começa aqui.')}
              </p>
            </div>
          </div>
          {Boolean(currentConfig.createChannel) && current.key !== 'protection' && (
            <div className="resource-preview">
              <span>+</span>
              <div>
                <b>Criar {resourceName}</b>
                <small>Será confirmado antes da publicação.</small>
              </div>
            </div>
          )}
          {roles.length > 0 && current.key === 'roles' && (
            <small className="muted-note">{roles.length} cargos disponíveis para reutilizar.</small>
          )}
          <div className="sticky-actions">
            <button
              type="button"
              className="secondary"
              onClick={() => void skip()}
              disabled={applying}
            >
              Saltar
            </button>
            <button
              type="button"
              className="primary"
              onClick={() => void apply()}
              disabled={applying}
            >
              {applying ? 'A aplicar…' : 'Confirmar e aplicar'}
            </button>
          </div>
        </aside>
      </div>
    </section>
  );
}

function Choice({
  selected,
  title,
  text,
  onClick,
}: {
  selected: boolean;
  title: string;
  text: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={selected ? 'setup-choice selected' : 'setup-choice'}
      onClick={onClick}
    >
      <span className="choice-dot" />
      <div>
        <b>{title}</b>
        <small>{text}</small>
      </div>
    </button>
  );
}
function SelectField({
  label,
  value,
  options,
  placeholder,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<{ id: string; name: string }>;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="field">
      <span>
        <b>{label}</b>
        <small>
          {options.length
            ? 'Seleciona um recurso existente.'
            : 'A leitura do Discord ainda não está disponível.'}
        </small>
      </span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">{placeholder}</option>
        {options.map((option) => (
          <option value={option.id} key={option.id}>
            #{option.name}
          </option>
        ))}
      </select>
    </label>
  );
}
function PremiumCard({ icon, title, text }: { icon: string; title: string; text: string }) {
  return (
    <article className="premium-card">
      <span>{icon}</span>
      <b>{title}</b>
      <p>{text}</p>
      <small>Premium</small>
    </article>
  );
}

function AuthScreen({
  error,
  loading,
  onLogin,
}: {
  error: string;
  loading: boolean;
  onLogin: () => void;
}) {
  const visibleError = /unauthenticated|API 401/i.test(error) ? '' : error;
  return (
    <main className="auth-shell" aria-labelledby="auth-title">
      <div className="auth-brand">
        <span>✦</span>
        <div>
          <strong>VOZEN</strong>
          <small>HELPER PANEL</small>
        </div>
      </div>
      <section className="auth-card card">
        <div className="auth-icon">✦</div>
        <small className="eyebrow">ACESSO SEGURO</small>
        <h1 id="auth-title">Entra no teu painel</h1>
        <p>Usa a tua conta Discord para gerir o Helper e configurar os teus servidores.</p>
        <button
          type="button"
          className="primary auth-button"
          onClick={onLogin}
          disabled={loading}
          aria-busy={loading}
        >
          {loading ? 'A ligar ao Discord…' : 'Continuar com Discord'}
        </button>
        {visibleError && (
          <p className="auth-error" role="alert">
            {visibleError}
          </p>
        )}
        <small className="auth-note">
          O acesso é protegido e só mostra servidores onde tens permissão de gestão.
        </small>
      </section>
    </main>
  );
}

function Overview({
  features,
  stats,
  quota,
  cases,
  onOpen,
}: {
  features: Feature[];
  stats: { totalCases: number };
  quota: { plan: string; limits: Record<string, number>; usage: Record<string, number> };
  cases: CaseRecord[];
  onOpen: (path: string) => void;
}) {
  const enabled = features.filter((feature) => feature.enabled).length;
  return (
    <>
      <section className="welcome card">
        <div>
          <small className="eyebrow">CENTRO DE COMANDO</small>
          <h2>O teu servidor, sob controlo.</h2>
          <p>
            Vê o que precisa de atenção e configura o Helper por etapas simples. Cada alteração fica
            ligada ao teu servidor.
          </p>
          <button type="button" className="primary" onClick={() => onOpen('#/features')}>
            Configurar o Helper
          </button>
        </div>
        <div className="setup-steps">
          <button type="button" onClick={() => onOpen('#/config/protection.antispam')}>
            <span>1</span>
            <div>
              <b>Proteger o servidor</b>
              <small>{enabled} funcionalidades ativas</small>
            </div>
            <em>›</em>
          </button>
          <button type="button" onClick={() => onOpen('#/config/support.welcome')}>
            <span>2</span>
            <div>
              <b>Receber novos membros</b>
              <small>Mensagem e cargo inicial</small>
            </div>
            <em>›</em>
          </button>
          <button type="button" onClick={() => onOpen('#/config/community.levels')}>
            <span>3</span>
            <div>
              <b>Dar vida à comunidade</b>
              <small>Níveis, XP e recompensas</small>
            </div>
            <em>›</em>
          </button>
        </div>
      </section>
      <div className="metrics">
        <Metric value={String(enabled)} label="funcionalidades ativas" />
        <Metric value={String(stats.totalCases)} label="casos de moderação" />
        <Metric value={String(cases.length)} label="eventos recentes" />
        <Metric value={quota.plan} label="plano atual" />
      </div>
      <section className="section-heading">
        <div>
          <small className="eyebrow">RECOMENDADO</small>
          <h2>O que queres fazer primeiro?</h2>
        </div>
        <button type="button" className="link-button" onClick={() => onOpen('#/features')}>
          Ver tudo →
        </button>
      </section>
      <div className="quick-grid">
        <Quick
          icon="🛡"
          title="Proteger o servidor"
          text="Anti-spam, anti-raid e proteção de entradas."
          onClick={() => onOpen('#/config/protection.antispam')}
        />
        <Quick
          icon="✦"
          title="Dar vida à comunidade"
          text="Níveis, sugestões, sorteios e starboard."
          onClick={() => onOpen('#/config/community.levels')}
        />
        <Quick
          icon="▣"
          title="Criar identidade"
          text="Escolhe cores, tipografia e um banner seguro."
          onClick={() => onOpen('#/rank-card')}
        />
      </div>
      <section className="quota card">
        <div>
          <small className="eyebrow">LIMITE DO PLANO</small>
          <h3>Usa o Helper com espaço para crescer</h3>
          <p>O plano atual mostra os limites antes de uma ação ficar bloqueada.</p>
        </div>
        <div className="quota-items">
          <Quota
            label="Workflows"
            used={quota.usage.workflows ?? 0}
            limit={quota.limits.workflows ?? 0}
          />
          <Quota
            label="Templates"
            used={quota.usage.templates ?? 0}
            limit={quota.limits.templates ?? 0}
          />
          <Quota
            label="Role panels"
            used={quota.usage.role_panels ?? 0}
            limit={quota.limits.role_panels ?? 0}
          />
        </div>
      </section>
    </>
  );
}
function Metric({ value, label }: { value: string; label: string }) {
  return (
    <div className="metric card">
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}
function Quota({ label, used, limit }: { label: string; used: number; limit: number }) {
  const percent = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  return (
    <div className="quota-item">
      <div>
        <span>{label}</span>
        <b>
          {used} / {limit || '—'}
        </b>
      </div>
      <i>
        <em style={{ width: `${percent}%` }} />
      </i>
    </div>
  );
}
function Quick({
  icon,
  title,
  text,
  onClick,
}: {
  icon: string;
  title: string;
  text: string;
  onClick: () => void;
}) {
  return (
    <button type="button" className="quick card" onClick={onClick}>
      <span className="quick-icon">{icon}</span>
      <div>
        <h3>{title}</h3>
        <p>{text}</p>
      </div>
      <b>→</b>
    </button>
  );
}

function FeatureCatalogue({
  features,
  filter,
  setFilter,
  search,
  setSearch,
  onOpen,
}: {
  features: Feature[];
  filter: Category;
  setFilter: (value: Category) => void;
  search: string;
  setSearch: (value: string) => void;
  onOpen: (key: string) => void;
}) {
  const uniqueFeatures = Array.from(new Map(features.map((item) => [item.key, item])).values());
  const maturityCounts = uniqueFeatures.reduce(
    (counts, feature) => {
      const maturity = feature.maturity ?? (feature.available ? 'operational' : 'planned');
      counts[maturity] = (counts[maturity] ?? 0) + 1;
      return counts;
    },
    {} as Record<string, number>,
  );
  const operationalCount = maturityCounts.operational ?? 0;
  const betaCount = maturityCounts.beta ?? 0;
  const requirementCount = maturityCounts.blocked ?? 0;
  // Every adapter-backed topic has a real configuration page, including
  // integrations that are blocked until credentials or an approval exist.
  // Keep “configuráveis” aligned with the API contract (52 topics), while the
  // card itself still prevents publication and explains the blocked
  // dependency.  Excluding blocked entries here made the panel report 45 and
  // suggested that seven topics were missing rather than waiting on a
  // legitimate external requirement.
  const configurableCount = uniqueFeatures.filter(
    (feature) => feature.configurable !== false,
  ).length;
  return (
    <section>
      <div className="catalog-toolbar">
        <div>
          <small className="eyebrow">CATÁLOGO DO HELPER</small>
          <h2>Escolhe o que o teu servidor precisa</h2>
          <p>
            Abre um tópico para veres opções essenciais, definições avançadas e uma simulação
            segura.
          </p>
        </div>
        <input
          className="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Pesquisar funcionalidade…"
          aria-label="Pesquisar funcionalidade"
          autoComplete="off"
        />
      </div>
      <div className="feature-summary" aria-label="Estado do catálogo">
        <span className="summary-item">
          <b>{uniqueFeatures.length}</b> módulos no catálogo
        </span>
        <span className="summary-item summary-configurable">
          <b>{configurableCount}</b> configuráveis
        </span>
        <span className="summary-item summary-ready">
          <b>{operationalCount}</b> operacionais
        </span>
        <span className="summary-item summary-beta">
          <b>{betaCount}</b> em beta
        </span>
        {requirementCount > 0 && (
          <span className="summary-item summary-requirements">
            <b>{requirementCount}</b> aguardam credenciais ou aprovação
          </span>
        )}
      </div>
      <div className="filters">
        {categories.map((category) => (
          <button
            key={category.id}
            type="button"
            className={filter === category.id ? 'filter active' : 'filter'}
            aria-pressed={filter === category.id}
            onClick={() => setFilter(category.id)}
          >
            {category.label}
          </button>
        ))}
      </div>
      <div className="feature-grid">
        {uniqueFeatures.map((feature) => {
          const maturity = feature.maturity ?? (feature.available ? 'operational' : 'planned');
          const configurable = feature.configurable ?? feature.available;
          // A blocked feature may expose a contract so the user can inspect
          // its requirements, but it must never look publishable until its
          // external dependency/approval is ready.
          const canConfigure = configurable && maturity !== 'blocked';
          const healthStatus = feature.health?.status;
          const dependencies = feature.health?.dependencies ?? [];
          const docsUrl = docsUrlForFeature(feature.key);
          const label =
            healthStatus === 'misconfigured'
              ? 'Verificar configuração'
              : healthStatus === 'degraded'
                ? 'Degradada'
                : healthStatus === 'dependency_down'
                  ? 'Dependência em falta'
                  : maturity === 'operational'
                    ? feature.enabled
                      ? 'Ativa'
                      : 'Disponível'
                    : maturity === 'beta'
                      ? 'Beta'
                      : maturity === 'blocked'
                        ? 'Bloqueada'
                        : maturity === 'degraded'
                          ? 'Com problemas'
                          : 'Planeada';
          return (
            <article className="feature card" key={feature.key}>
              <div className="feature-top">
                <span className={`feature-icon ${feature.category}`}>
                  {feature.category === 'protection'
                    ? '◈'
                    : feature.category === 'community'
                      ? '✦'
                      : '▤'}
                </span>
                <span
                  className={
                    feature.enabled && maturity === 'operational'
                      ? 'pill on'
                      : maturity === 'blocked'
                        ? 'pill muted'
                        : 'pill'
                  }
                >
                  {label}
                </span>
              </div>
              <h3>{feature.label}</h3>
              <p>{feature.description}</p>
              {maturity === 'blocked' && feature.issues?.[0]?.message && (
                <p className="tip feature-requirement">{feature.issues[0].message}</p>
              )}
              {maturity === 'blocked' && dependencies.length > 0 && (
                <details className="feature-dependencies">
                  <summary>Requisitos para ativar</summary>
                  <ul>
                    {dependencies.slice(0, 4).map((dependency) => (
                      <li key={dependency}>{dependency}</li>
                    ))}
                  </ul>
                </details>
              )}
              <button
                type="button"
                className="secondary full"
                disabled={!canConfigure && maturity !== 'blocked'}
                onClick={() => onOpen(feature.key)}
              >
                {feature.key === 'studio.rank_card'
                  ? 'Personalizar'
                  : canConfigure
                    ? 'Configurar'
                    : maturity === 'blocked'
                      ? 'Ver requisitos'
                      : 'Ver plano'}
              </button>
              {docsUrl && (
                <a
                  className="link-button feature-doc-link"
                  href={docsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Learn how this works
                </a>
              )}
            </article>
          );
        })}
      </div>
      {!features.length && (
        <div className="empty card">Não encontrámos funcionalidades com esse filtro.</div>
      )}
    </section>
  );
}

function FeatureDetail({
  feature,
  schema,
  context,
  config,
  enabled,
  revision,
  onEnabled,
  onChange,
  onSave,
  onRepair,
  onDiscard,
  onTest,
  templates,
  onTemplatesChange,
  providerHealth,
  saving,
  onBack,
}: {
  feature?: Feature;
  schema: FeatureSchema | null;
  context: GuildContext | null;
  config: FeatureConfig;
  enabled: boolean;
  revision: number;
  onEnabled: (value: boolean) => void;
  onChange: (key: string, value: unknown) => void;
  onSave: () => void;
  onRepair: () => void;
  onDiscard: () => void;
  onTest: () => void;
  templates: StudioTemplate[];
  onTemplatesChange: (templates: StudioTemplate[]) => void;
  providerHealth: ProviderSubscriptionHealth | null;
  saving: boolean;
  onBack: () => void;
}) {
  const templateOptions: [string, string][] = [
    ['', 'No template'],
    ...templates.map(
      (template) => [template.id, `${template.name} (v${template.version})`] as [string, string],
    ),
  ];
  const sections: SectionSpec[] =
    schema?.sections.map((section) => ({
      ...section,
      fields: section.fields.map((field) => ({
        ...field,
        kind: field.kind as FieldSpec['kind'],
        options: field.key === 'templateId' ? templateOptions : field.options,
      })),
    })) ?? (localPreviewMode ? spec(feature?.key ?? '') : []);
  // Keep blocked providers discoverable, but do not expose a save/enable
  // form that can only fail at publication time. Their detail page is a
  // requirements view until the backend reports a non-blocked maturity.
  const configurable = (feature?.configurable ?? true) && feature?.maturity !== 'blocked';
  const docsUrl = docsUrlForFeature(feature?.key);
  if (!configurable)
    return (
      <section className="detail-page">
        <button type="button" className="back-link" onClick={onBack}>
          ← Voltar às funcionalidades
        </button>
        <div className="detail-intro card">
          <div>
            <small className="eyebrow">
              {feature?.maturity === 'blocked' ? 'REQUISITOS EXTERNOS' : 'ROADMAP'}
            </small>
            <h2>{feature?.label ?? 'Funcionalidade'}</h2>
            <p>{feature?.description ?? 'Esta área está no plano do Vozen Helper.'}</p>
            <p className="tip">
              {feature?.issues?.[0]?.message ??
                'Ainda não existe um adaptador operacional para este servidor. Não há ativação disponível até a integração, permissões e rollback estarem prontos.'}
            </p>
            {feature?.health?.dependencies && feature.health.dependencies.length > 0 && (
              <div className="requirement-list">
                <strong>O que falta</strong>
                <ul>
                  {feature.health.dependencies.map((dependency) => (
                    <li key={dependency}>{dependency}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
          {docsUrl && (
            <a className="link-button" href={docsUrl} target="_blank" rel="noopener noreferrer">
              Read the documentation
            </a>
          )}
        </div>
      </section>
    );
  if (!schema && !localPreviewMode)
    return (
      <section className="detail-page">
        <button type="button" className="back-link" onClick={onBack}>
          ← Voltar às funcionalidades
        </button>
        <div className="detail-intro card">
          <div>
            <small className="eyebrow">ADAPTER INDISPONÍVEL</small>
            <h2>{feature?.label ?? 'Funcionalidade'}</h2>
            <p>
              O painel não recebeu o contrato desta funcionalidade. Atualiza a página ou verifica o
              estado da API antes de publicar alterações.
            </p>
          </div>
          {docsUrl && (
            <a className="link-button" href={docsUrl} target="_blank" rel="noopener noreferrer">
              Read the documentation
            </a>
          )}
        </div>
      </section>
    );
  return (
    <section className="detail-page">
      <button type="button" className="back-link" onClick={onBack}>
        ← Voltar às funcionalidades
      </button>
      <div className="detail-intro card">
        <div>
          <small className="eyebrow">
            CONFIGURAÇÃO ·{' '}
            {feature?.category === 'protection'
              ? 'PROTEÇÃO'
              : feature?.category === 'community'
                ? 'COMUNIDADE'
                : 'GESTÃO'}
          </small>
          <h2>{feature?.label ?? 'Funcionalidade'}</h2>
          <p>{feature?.description ?? 'Ajusta esta funcionalidade ao teu servidor.'}</p>
        </div>
        <label className="switch-row">
          <span>
            <b>{enabled ? 'Ativa' : 'Desativada'}</b>
            <small>O Helper aplica esta configuração no servidor.</small>
          </span>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => onEnabled(event.target.checked)}
          />
        </label>
        {docsUrl && (
          <a className="link-button" href={docsUrl} target="_blank" rel="noopener noreferrer">
            Learn how this works
          </a>
        )}
      </div>
      <div className="detail-layout">
        <div className="detail-sections">
          {feature?.key === 'management.templates' && (
            <TemplateManager
              templates={templates}
              onChange={onTemplatesChange}
              localPreviewMode={localPreviewMode}
            />
          )}
          {feature?.key === 'management.custom_commands' && (
            <CustomCommandManager localPreviewMode={localPreviewMode} />
          )}
          {feature?.key === 'management.workflows' && (
            <WorkflowManager enabled={enabled} localPreviewMode={localPreviewMode} />
          )}
          {feature?.key === 'community.leaderboard' && (
            <LeaderboardPreview enabled={enabled} localPreviewMode={localPreviewMode} />
          )}
          {feature?.key === 'utility.reminders' && (
            <RemindersManager enabled={enabled} localPreviewMode={localPreviewMode} />
          )}
          {feature?.key === 'community.role_panels' && (
            <RolePanelManager context={context} localPreviewMode={localPreviewMode} />
          )}
          {feature?.key === 'social.tiktok' && <TikTokConnection />}
          {sections.map((section) => (
            <ConfigSection
              key={section.title}
              section={section}
              config={config}
              context={context}
              onChange={onChange}
            />
          ))}
        </div>
        <aside className="detail-aside card">
          <div>
            <small className="eyebrow">ANTES DE PUBLICAR</small>
            <h3>Confere sem risco</h3>
            <p>
              Usa a simulação para veres o que aconteceria. Ela nunca apaga mensagens nem castiga
              membros.
            </p>
          </div>
          <button type="button" className="secondary full" onClick={onTest}>
            {feature?.key === 'social.youtube' ||
            feature?.key === 'social.twitch' ||
            feature?.key === 'social.rss' ||
            feature?.key === 'social.podcasts' ||
            feature?.key === 'social.tiktok'
              ? 'Enviar teste para o Discord'
              : 'Simular configuração'}
          </button>
          {providerHealth && <ProviderHealthPanel health={providerHealth} />}
          {!localPreviewMode &&
            feature?.health?.status &&
            feature.health.status !== 'ready' &&
            revision > 0 && (
              <button type="button" className="secondary full" onClick={onRepair} disabled={saving}>
                Reparar publicação
              </button>
            )}
          <div className="tip">
            <b>Precisas de ajuda?</b>
            <a
              className="link-button"
              href={docsTroubleshootingUrl('missing-permissions')}
              target="_blank"
              rel="noopener noreferrer"
            >
              Why is this permission needed?
            </a>
            <a
              className="link-button"
              href={docsTroubleshootingUrl('restore-configuration')}
              target="_blank"
              rel="noopener noreferrer"
            >
              Rollback instructions
            </a>
            <span>Os campos avançados estão fechados para manter o primeiro passo simples.</span>
          </div>
        </aside>
      </div>
      <div className="sticky-actions">
        <button type="button" className="secondary" onClick={onDiscard} disabled={saving}>
          Descartar
        </button>
        <button type="button" className="primary" onClick={onSave} disabled={saving}>
          {saving ? 'A guardar…' : 'Guardar alterações'}
        </button>
      </div>
    </section>
  );
}

function TikTokConnection() {
  const [status, setStatus] = useState<Awaited<ReturnType<typeof api.tiktokOAuthStatus>> | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    api
      .tiktokOAuthStatus()
      .then((value) => {
        if (!cancelled) setStatus(value);
      })
      .catch(() => {
        if (!cancelled) setError('Não foi possível verificar a ligação ao TikTok.');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const connect = async () => {
    setBusy(true);
    setError('');
    try {
      const result = await api.startTikTokOAuth();
      window.location.assign(result.authorization_url);
    } catch {
      setError('Não foi possível iniciar a autorização do TikTok.');
      setBusy(false);
    }
  };

  const disconnect = async () => {
    setBusy(true);
    setError('');
    try {
      await api.disconnectTikTokOAuth();
      setStatus({ connected: false });
    } catch {
      setError('Não foi possível remover a ligação ao TikTok.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card config-section">
      <small className="eyebrow">CONTA TIKTOK</small>
      {status?.sandbox && (
        <p className="tip feature-requirement">
          Sandbox de revisão ativo — esta ligação usa uma conta de teste autorizada no TikTok
          Developer Portal.
        </p>
      )}
      <h3>{status?.connected ? 'TikTok ligado' : 'Liga a conta que publica os vídeos'}</h3>
      <p>
        {status?.connected
          ? `A monitorizar ${status.displayName || status.openId}. Os tokens ficam cifrados no servidor.`
          : 'Autoriza apenas o perfil público e a leitura dos teus vídeos. O Helper não publica nem altera conteúdo.'}
      </p>
      {error && <p className="tip feature-requirement">{error}</p>}
      {status?.connected ? (
        <button type="button" className="secondary" onClick={disconnect} disabled={busy}>
          {busy ? 'A desligar…' : 'Desligar TikTok'}
        </button>
      ) : (
        <button
          type="button"
          className="primary"
          onClick={connect}
          disabled={busy || status === null}
        >
          {busy ? 'A abrir TikTok…' : 'Ligar TikTok'}
        </button>
      )}
    </section>
  );
}

function ProviderHealthPanel({ health }: { health: ProviderSubscriptionHealth }) {
  const labels: Record<ProviderSubscriptionHealth['status'], string> = {
    ready: 'Pronto',
    degraded: 'Degradado',
    dependency_down: 'Dependencia indisponivel',
  };
  const provider =
    health.provider === 'rss' ? 'RSS' : health.provider === 'youtube' ? 'YouTube' : 'Twitch';
  const source =
    health.provider === 'youtube'
      ? health.latestVideo?.title
      : health.provider === 'rss'
        ? health.feed?.latestTitle
        : health.channel?.displayName;
  return (
    <div className={`provider-health ${health.status}`} role="status">
      <div className="provider-health-heading">
        <span className="eyebrow">SAUDE · {provider}</span>
        <strong>{labels[health.status]}</strong>
      </div>
      <p>
        {health.message ??
          (health.status === 'ready'
            ? 'A fonte respondeu e esta subscricao pode ser testada.'
            : 'Verifica as credenciais e a fonte configurada.')}
      </p>
      {source && <small>Ultima fonte: {source}</small>}
      {health.failureCount > 0 && <small>Falhas consecutivas: {health.failureCount}</small>}
      {health.lastError && (
        <small className="provider-health-error">Ultimo erro: {health.lastError}</small>
      )}
      <a
        className="link-button"
        href={docsProviderStatusUrl()}
        target="_blank"
        rel="noopener noreferrer"
      >
        Provider status
      </a>
    </div>
  );
}

function TemplateManager({
  templates,
  onChange,
  localPreviewMode,
}: {
  templates: StudioTemplate[];
  onChange: (templates: StudioTemplate[]) => void;
  localPreviewMode: boolean;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [content, setContent] = useState('');
  const [modules, setModules] = useState<string[]>(['core', 'security', 'support']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const moduleOptions = [
    ['core', 'Core'],
    ['security', 'Protection'],
    ['support', 'Support'],
    ['events', 'Events'],
    ['community', 'Community'],
    ['automate', 'Automation'],
    ['insights', 'Insights'],
    ['studio', 'Studio'],
  ] as const;
  async function createTemplate() {
    if (localPreviewMode || !name.trim() || busy) return;
    setBusy(true);
    setError('');
    try {
      const result = await api.createStudioTemplate({
        name: name.trim(),
        description: description.trim(),
        modules,
        config: { content: content.trim() },
      });
      onChange([...templates, result.template]);
      setName('');
      setDescription('');
      setContent('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not save the template.');
    } finally {
      setBusy(false);
    }
  }
  async function removeTemplate(id: string) {
    if (localPreviewMode || busy) return;
    setBusy(true);
    setError('');
    try {
      await api.deleteStudioTemplate(id);
      onChange(templates.filter((template) => template.id !== id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not delete the template.');
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="config-section card">
      <div className="section-heading">
        <div>
          <small className="eyebrow">REAL SERVER TEMPLATES</small>
          <h3>Save a reusable server setup</h3>
          <p>
            {localPreviewMode
              ? 'Connect the panel to a Helper API to create templates for a real guild.'
              : 'Templates are stored for this guild only. Secrets and tokens are never exported.'}
          </p>
        </div>
      </div>
      <div className="field-grid">
        <label className="field">
          <span>
            <b>Template name</b>
            <small>Use a clear name your team will recognise.</small>
          </span>
          <input value={name} maxLength={80} onChange={(event) => setName(event.target.value)} />
        </label>
        <label className="field">
          <span>
            <b>Description</b>
            <small>Optional context for the next administrator.</small>
          </span>
          <input
            value={description}
            maxLength={500}
            onChange={(event) => setDescription(event.target.value)}
          />
        </label>
        <label className="field">
          <span>
            <b>Default message</b>
            <small>
              Optional content used by welcome, goodbye and guided-channel templates. Supports{' '}
              {'{member}'} and {'{server}'}.
            </small>
          </span>
          <textarea
            value={content}
            maxLength={2000}
            rows={3}
            onChange={(event) => setContent(event.target.value)}
          />
        </label>
      </div>
      <div className="template-module-grid" aria-label="Template modules">
        {moduleOptions.map(([value, label]) => (
          <label className="toggle-field" key={value}>
            <span>
              <b>{label}</b>
            </span>
            <input
              type="checkbox"
              checked={modules.includes(value)}
              onChange={(event) =>
                setModules((current) =>
                  event.target.checked
                    ? [...new Set([...current, value])]
                    : current.filter((item) => item !== value),
                )
              }
            />
          </label>
        ))}
      </div>
      <button
        type="button"
        className="secondary"
        onClick={() => void createTemplate()}
        disabled={localPreviewMode || busy || !name.trim()}
      >
        {busy ? 'Saving…' : 'Save template'}
      </button>
      {error && (
        <p className="tip" role="alert">
          {error}
        </p>
      )}
      {templates.length > 0 && (
        <div className="template-list">
          {templates.map((template) => (
            <div className="template-row" key={template.id}>
              <div>
                <b>{template.name}</b>
                <small>
                  {template.description || 'No description'} · v{template.version}
                </small>
              </div>
              <button
                type="button"
                className="ghost"
                onClick={() => void removeTemplate(template.id)}
                disabled={localPreviewMode || busy}
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function CustomCommandManager({ localPreviewMode }: { localPreviewMode: boolean }) {
  const [commands, setCommands] = useState<CustomCommand[]>([]);
  const [name, setName] = useState('');
  const [content, setContent] = useState('');
  const [editingName, setEditingName] = useState<string | null>(null);
  const [limit, setLimit] = useState(100);
  const [maxResponseLength, setMaxResponseLength] = useState(1000);
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(!localPreviewMode);
  const [error, setError] = useState('');

  useEffect(() => {
    if (localPreviewMode) return;
    let cancelled = false;
    void api
      .customCommands()
      .then((result) => {
        if (cancelled) return;
        setCommands(result.commands);
        setLimit(result.limit);
        setMaxResponseLength(result.maxResponseLength);
        setEnabled(result.enabled);
      })
      .catch((cause) => {
        if (!cancelled)
          setError(cause instanceof Error ? cause.message : 'Could not load custom commands.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [localPreviewMode]);

  function resetForm() {
    setName('');
    setContent('');
    setEditingName(null);
  }

  function beginEdit(command: CustomCommand) {
    setEditingName(command.name);
    setName(command.name);
    setContent(command.content);
    setError('');
  }

  async function saveCommand() {
    const normalizedName = name.trim().toLowerCase();
    if (localPreviewMode || busy || !normalizedName || !content.trim()) return;
    setBusy(true);
    setError('');
    try {
      const result = editingName
        ? await api.updateCustomCommand(editingName, content.trim())
        : await api.createCustomCommand(normalizedName, content.trim());
      setCommands((current) =>
        editingName
          ? current.map((command) => (command.name === editingName ? result.command : command))
          : [...current, result.command].sort((a, b) => a.name.localeCompare(b.name)),
      );
      resetForm();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not save the custom command.');
    } finally {
      setBusy(false);
    }
  }

  async function removeCommand(commandName: string) {
    if (localPreviewMode || busy) return;
    setBusy(true);
    setError('');
    try {
      await api.deleteCustomCommand(commandName);
      setCommands((current) => current.filter((command) => command.name !== commandName));
      if (editingName === commandName) resetForm();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not delete the custom command.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="config-section card">
      <div className="section-heading">
        <div>
          <small className="eyebrow">RESPOSTAS DO SERVIDOR</small>
          <h3>Comandos personalizados</h3>
          <p>
            Cria respostas simples para o teu servidor. O prefixo e os limites ficam nas opções
            acima; aqui geres o conteúdo que o Helper publica de verdade.
          </p>
        </div>
      </div>
      <div className="tip">
        <b>Variáveis disponíveis</b>
        <span>
          {'{user}'}, {'{channel}'}, {'{server}'} e {'{args}'}. Menções globais são neutralizadas
          pelo Helper.
        </span>
      </div>
      {!localPreviewMode && !loading && !enabled && (
        <p className="tip" role="status">
          Ativa esta funcionalidade e guarda as alterações acima para gerir comandos.
        </p>
      )}
      {loading && (
        <p className="tip" role="status">
          A carregar comandos deste servidor…
        </p>
      )}
      <div className="field-grid">
        <label className="field">
          <span>
            <b>{editingName ? 'Nome do comando' : 'Novo comando'}</b>
            <small>Usa apenas letras, números, hífen ou underscore. Máximo 32 caracteres.</small>
          </span>
          <input
            value={name}
            maxLength={32}
            disabled={Boolean(editingName) || localPreviewMode || busy || !enabled}
            onChange={(event) => setName(event.target.value)}
            placeholder="regras"
          />
        </label>
        <label className="field">
          <span>
            <b>Resposta</b>
            <small>
              Até {maxResponseLength} caracteres. O prefixo configurado será usado no Discord.
            </small>
          </span>
          <textarea
            value={content}
            maxLength={maxResponseLength}
            rows={3}
            disabled={localPreviewMode || busy || !enabled}
            onChange={(event) => setContent(event.target.value)}
            placeholder="Consulta #regras para conhecer as regras do servidor."
          />
        </label>
      </div>
      <div className="inline-actions">
        <button
          type="button"
          className="secondary"
          onClick={() => void saveCommand()}
          disabled={localPreviewMode || busy || !enabled || !name.trim() || !content.trim()}
        >
          {busy ? 'A guardar…' : editingName ? 'Guardar comando' : 'Adicionar comando'}
        </button>
        {editingName && (
          <button type="button" className="ghost" onClick={resetForm} disabled={busy}>
            Cancelar edição
          </button>
        )}
        <small>
          {commands.length}/{limit} comandos usados
        </small>
      </div>
      {error && (
        <p className="tip" role="alert">
          {error}
        </p>
      )}
      {!localPreviewMode && !loading && commands.length === 0 && (
        <p className="tip">Ainda não existem comandos. Adiciona o primeiro acima.</p>
      )}
      {commands.length > 0 && (
        <div className="template-list" aria-label="Comandos personalizados">
          {commands.map((command) => (
            <div className="template-row" key={command.name}>
              <div>
                <b>{command.name}</b>
                <small>{command.content}</small>
              </div>
              <div className="inline-actions">
                <button
                  type="button"
                  className="ghost"
                  onClick={() => beginEdit(command)}
                  disabled={busy}
                >
                  Editar
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void removeCommand(command.name)}
                  disabled={busy}
                >
                  Apagar
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function LeaderboardPreview({
  enabled,
  localPreviewMode,
}: {
  enabled: boolean;
  localPreviewMode: boolean;
}) {
  const [entries, setEntries] = useState<LeaderboardEntry[]>([]);
  const [maxEntries, setMaxEntries] = useState(10);
  const [isPublic, setIsPublic] = useState(true);
  const [loading, setLoading] = useState(!localPreviewMode);
  const [error, setError] = useState('');

  useEffect(() => {
    if (localPreviewMode) return;
    let cancelled = false;
    void api
      .leaderboard()
      .then((result) => {
        if (cancelled) return;
        setEntries(result.entries);
        setMaxEntries(result.maxEntries);
        setIsPublic(result.public);
      })
      .catch((cause) => {
        if (!cancelled)
          setError(cause instanceof Error ? cause.message : 'Could not load the leaderboard.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [localPreviewMode]);

  return (
    <section className="config-section card">
      <div className="section-heading">
        <div>
          <small className="eyebrow">XP COMMUNITY</small>
          <h3>Leaderboard preview</h3>
          <p>
            Preview the same opt-out-aware ranking that the Helper publishes with{' '}
            <code>/leaderboard</code>.
          </p>
        </div>
        <span className="status-pill">{isPublic ? 'Public' : 'Private'}</span>
      </div>
      {!localPreviewMode && !enabled && (
        <p className="tip" role="status">
          Enable the XP leaderboard and save the settings to publish it in Discord.
        </p>
      )}
      {loading && (
        <p className="tip" role="status">
          Loading the latest XP ranking…
        </p>
      )}
      {error && (
        <p className="tip" role="alert">
          {error}
        </p>
      )}
      {!loading && !error && enabled && entries.length === 0 && (
        <p className="tip">
          No eligible XP data yet. Members can opt out with <code>/leaderboard-privacy</code>.
        </p>
      )}
      {entries.length > 0 && (
        <div className="template-list" aria-label="XP leaderboard preview">
          {entries.map((entry) => (
            <div className="template-row" key={`${entry.userId}-${entry.rank}`}>
              <div>
                <b>
                  #{entry.rank} · {entry.userId}
                </b>
                <small>{entry.xp.toLocaleString()} XP</small>
              </div>
              <span className="status-pill">
                {entry.rank <= maxEntries ? 'Included' : 'Hidden'}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function RemindersManager({
  enabled,
  localPreviewMode,
}: {
  enabled: boolean;
  localPreviewMode: boolean;
}) {
  const [reminders, setReminders] = useState<ReminderRecord[]>([]);
  const [loading, setLoading] = useState(!localPreviewMode);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (localPreviewMode) return;
    let cancelled = false;
    void api
      .reminders()
      .then((result) => {
        if (cancelled) return;
        setReminders(result.reminders);
      })
      .catch((cause) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : 'Could not load reminders.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [localPreviewMode]);

  async function cancel(id: number) {
    if (localPreviewMode || busyAction !== null || !enabled) return;
    setBusyAction(`cancel:${id}`);
    setError('');
    try {
      await api.cancelReminder(id);
      setReminders((current) => current.filter((reminder) => reminder.id !== id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not cancel the reminder.');
    } finally {
      setBusyAction(null);
    }
  }

  async function retry(id: number) {
    if (localPreviewMode || busyAction !== null || !enabled) return;
    setBusyAction(`retry:${id}`);
    setError('');
    try {
      await api.retryReminder(id);
      setReminders((current) =>
        current.map((reminder) =>
          reminder.id === id
            ? {
                ...reminder,
                status: 'pending',
                attempts: 0,
                lastError: null,
                leaseUntil: null,
                executeAt: Date.now(),
              }
            : reminder,
        ),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not retry the reminder.');
    } finally {
      setBusyAction(null);
    }
  }

  const statusCounts = reminders.reduce<Record<string, number>>((counts, reminder) => {
    counts[reminder.status] = (counts[reminder.status] ?? 0) + 1;
    return counts;
  }, {});

  return (
    <section className="config-section card">
      <div className="section-heading">
        <div>
          <small className="eyebrow">SCHEDULED ACTIONS</small>
          <h3>Pending reminders</h3>
          <p>
            See reminders created with <code>/remind</code> and cancel them before they are sent.
          </p>
        </div>
        <span className="status-pill">
          {reminders.length} scheduled
          {statusCounts.dead ? ` · ${statusCounts.dead} failed` : ''}
        </span>
      </div>
      {!localPreviewMode && !enabled && (
        <p className="tip" role="status">
          Enable reminders and save the policy before scheduling new messages.
        </p>
      )}
      {loading && (
        <p className="tip" role="status">
          Loading scheduled reminders…
        </p>
      )}
      {error && (
        <p className="tip" role="alert">
          {error}
        </p>
      )}
      {!loading && reminders.length === 0 && (
        <p className="tip">
          No pending reminders. Members can create one with <code>/remind</code> in Discord.
        </p>
      )}
      {reminders.length > 0 && (
        <div className="template-list" aria-label="Pending reminders">
          {reminders.map((reminder) => (
            <div className="template-row" key={reminder.id}>
              <div>
                <b>
                  #{reminder.id} · {new Date(reminder.executeAt).toLocaleString()}
                </b>
                <small>
                  {reminder.text || 'Reminder'}
                  {reminder.repeat
                    ? ` · repeats ${reminder.repeat}${reminder.remaining == null ? '' : ` (${reminder.remaining} left)`}`
                    : ''}
                  {reminder.timezone ? ` · ${reminder.timezone}` : ''}
                </small>
                <span className={`status-pill reminder-status-${reminder.status}`}>
                  {reminder.status === 'dead' ? 'Failed — retry required' : reminder.status}
                  {reminder.attempts > 0
                    ? ` · ${reminder.attempts} attempt${reminder.attempts === 1 ? '' : 's'}`
                    : ''}
                </span>
                {reminder.lastError ? <small className="tip">{reminder.lastError}</small> : null}
              </div>
              <div className="button-row">
                {reminder.status === 'dead' && (
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => void retry(reminder.id)}
                    disabled={localPreviewMode || !enabled || busyAction !== null}
                  >
                    {busyAction === `retry:${reminder.id}` ? 'Retrying...' : 'Retry now'}
                  </button>
                )}
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void cancel(reminder.id)}
                  disabled={localPreviewMode || !enabled || busyAction !== null}
                >
                  {busyAction === `cancel:${reminder.id}` ? 'Cancelling...' : 'Cancel'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function isSafeWorkflowReaction(value: string): boolean {
  const characters = Array.from(value);
  return (
    characters.length > 0 &&
    characters.length <= 16 &&
    characters.every((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint > 0x7f &&
        !/\s/u.test(character) &&
        character !== '<' &&
        character !== '>' &&
        character !== ':'
      );
    })
  );
}

function WorkflowManager({
  enabled,
  localPreviewMode,
}: {
  enabled: boolean;
  localPreviewMode: boolean;
}) {
  const [workflows, setWorkflows] = useState<WorkflowRecord[]>([]);
  const [limit, setLimit] = useState(10);
  const [maxReplyLength, setMaxReplyLength] = useState(1000);
  const [name, setName] = useState('');
  const [condition, setCondition] = useState('');
  const [action, setAction] = useState<'reply' | 'react'>('reply');
  const [payload, setPayload] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(!localPreviewMode);
  const [error, setError] = useState('');

  useEffect(() => {
    if (localPreviewMode) return;
    let cancelled = false;
    void api
      .workflows()
      .then((result) => {
        if (cancelled) return;
        setWorkflows(result.workflows);
        setLimit(result.maxWorkflows);
        setMaxReplyLength(result.maxReplyLength);
      })
      .catch((cause) => {
        if (!cancelled)
          setError(cause instanceof Error ? cause.message : 'Could not load workflows.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [localPreviewMode]);

  async function create() {
    const trimmedName = name.trim();
    const trimmedCondition = condition.trim();
    const trimmedPayload = payload.trim();
    if (localPreviewMode || busy || !enabled || !trimmedName || !trimmedPayload) return;
    if (action === 'reply' && trimmedPayload.length > maxReplyLength) {
      setError(`Reply must be ${maxReplyLength} characters or fewer.`);
      return;
    }
    if (action === 'react' && !isSafeWorkflowReaction(trimmedPayload)) {
      setError(
        'Reactions use one Unicode emoji (maximum 16 characters); custom emojis are not supported.',
      );
      return;
    }
    setBusy(true);
    setError('');
    try {
      const result = await api.createWorkflow({
        name: trimmedName,
        trigger: 'message',
        condition: trimmedCondition || undefined,
        action,
        payload: trimmedPayload,
      });
      setWorkflows((current) => [
        {
          id: result.id,
          name: trimmedName,
          trigger: 'message',
          condition: trimmedCondition,
          action,
          payload: trimmedPayload,
          enabled: true,
        },
        ...current,
      ]);
      setName('');
      setCondition('');
      setPayload('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create the workflow.');
    } finally {
      setBusy(false);
    }
  }

  async function toggle(workflow: WorkflowRecord) {
    if (localPreviewMode || busy || !enabled) return;
    setBusy(true);
    setError('');
    try {
      await api.updateWorkflow(workflow.id, !workflow.enabled);
      setWorkflows((current) =>
        current.map((item) =>
          item.id === workflow.id ? { ...item, enabled: !item.enabled } : item,
        ),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not update the workflow.');
    } finally {
      setBusy(false);
    }
  }

  async function remove(workflow: WorkflowRecord) {
    if (localPreviewMode || busy || !enabled) return;
    setBusy(true);
    setError('');
    try {
      await api.deleteWorkflow(workflow.id);
      setWorkflows((current) => current.filter((item) => item.id !== workflow.id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not delete the workflow.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="config-section card">
      <div className="section-heading">
        <div>
          <small className="eyebrow">AUTOMAÇÕES REAIS</small>
          <h3>Workflow builder</h3>
          <p>
            Cria regras seguras de mensagem: quando o texto contém uma condição, o Helper responde
            ou adiciona uma reação.
          </p>
        </div>
      </div>
      {!localPreviewMode && !enabled && (
        <p className="tip" role="status">
          Ativa esta funcionalidade e guarda as alterações acima para gerir automações.
        </p>
      )}
      {loading && (
        <p className="tip" role="status">
          A carregar automações deste servidor…
        </p>
      )}
      <div className="field-grid">
        <label className="field">
          <span>
            <b>Nome</b>
            <small>Um nome curto para encontrares a regra.</small>
          </span>
          <input
            value={name}
            maxLength={50}
            disabled={localPreviewMode || busy || !enabled}
            onChange={(event) => setName(event.target.value)}
            placeholder="welcome-reply"
          />
        </label>
        <label className="field">
          <span>
            <b>Quando a mensagem contém</b>
            <small>Texto simples, sem código executável.</small>
          </span>
          <input
            value={condition}
            maxLength={200}
            disabled={localPreviewMode || busy || !enabled}
            onChange={(event) => setCondition(event.target.value)}
            placeholder="regras"
          />
        </label>
        <label className="field">
          <span>
            <b>Ação</b>
            <small>As ações são limitadas para evitar loops e spam.</small>
          </span>
          <select
            value={action}
            disabled={localPreviewMode || busy || !enabled}
            onChange={(event) => setAction(event.target.value as 'reply' | 'react')}
          >
            <option value="reply">Responder à mensagem</option>
            <option value="react">Adicionar reação</option>
          </select>
        </label>
        <label className="field">
          <span>
            <b>{action === 'reply' ? 'Resposta' : 'Emoji/reação'}</b>
            <small>
              {action === 'reply'
                ? `Até ${maxReplyLength} caracteres.`
                : 'Emoji Unicode, até 16 caracteres; emojis personalizados ficam bloqueados por segurança.'}
            </small>
          </span>
          <textarea
            value={payload}
            maxLength={action === 'reply' ? maxReplyLength : 16}
            rows={2}
            disabled={localPreviewMode || busy || !enabled}
            onChange={(event) => setPayload(event.target.value)}
            placeholder={action === 'reply' ? 'Consulta #regras para conhecer as regras.' : '✅'}
          />
        </label>
      </div>
      <div className="inline-actions">
        <button
          type="button"
          className="secondary"
          onClick={() => void create()}
          disabled={localPreviewMode || busy || !enabled || !name.trim() || !payload.trim()}
        >
          {busy ? 'A guardar…' : 'Adicionar automação'}
        </button>
        <small>
          {workflows.length}/{limit} automações usadas
        </small>
      </div>
      {error && (
        <p className="tip" role="alert">
          {error}
        </p>
      )}
      {!localPreviewMode && !loading && workflows.length === 0 && (
        <p className="tip">Ainda não existem automações. Adiciona a primeira acima.</p>
      )}
      {workflows.length > 0 && (
        <div className="template-list" aria-label="Workflows do servidor">
          {workflows.map((workflow) => (
            <div className="template-row" key={workflow.id}>
              <div>
                <b>{workflow.name}</b>
                <small>
                  Quando contém “{workflow.condition || 'qualquer texto'}” ·{' '}
                  {workflow.action === 'react'
                    ? `reage com ${workflow.payload}`
                    : `responde: ${workflow.payload}`}
                </small>
              </div>
              <div className="inline-actions">
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void toggle(workflow)}
                  disabled={busy || localPreviewMode || !enabled}
                >
                  {workflow.enabled ? 'Desativar' : 'Ativar'}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void remove(workflow)}
                  disabled={busy || localPreviewMode || !enabled}
                >
                  Apagar
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function RolePanelManager({
  context,
  localPreviewMode,
}: {
  context: GuildContext | null;
  localPreviewMode: boolean;
}) {
  const [panels, setPanels] = useState<RolePanelRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(!localPreviewMode);
  const [error, setError] = useState('');

  useEffect(() => {
    if (localPreviewMode) return;
    let cancelled = false;
    void api
      .rolePanels()
      .then((result) => {
        if (!cancelled) setPanels(result.panels);
      })
      .catch((cause) => {
        if (!cancelled)
          setError(cause instanceof Error ? cause.message : 'Could not load role panels.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [localPreviewMode]);

  const channelName = (id?: string) => context?.channels.find((channel) => channel.id === id)?.name;
  const roleNames = (ids?: string[]) =>
    (ids ?? []).map((id) => context?.roles.find((role) => role.id === id)?.name ?? id).join(', ');

  async function remove(messageId: string) {
    if (localPreviewMode || busy) return;
    setBusy(true);
    setError('');
    try {
      await api.deleteRolePanel(messageId);
      setPanels((current) => current.filter((panel) => panel.message_id !== messageId));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not delete the role panel.');
    } finally {
      setBusy(false);
    }
  }

  async function repair(messageId: string) {
    if (localPreviewMode || busy) return;
    setBusy(true);
    setError('');
    try {
      const result = await api.repairRolePanel(messageId);
      setPanels((current) =>
        current.map((panel) =>
          panel.message_id === messageId ? { ...panel, message_id: result.messageId } : panel,
        ),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not repair the role panel.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="config-section card">
      <div className="section-heading">
        <div>
          <small className="eyebrow">REAL DISCORD PANELS</small>
          <h3>Role panel manager</h3>
          <p>
            Guardar a configuração publica um painel real. Aqui podes confirmar onde está, reparar
            uma mensagem apagada ou removê-la sem apagar os cargos.
          </p>
        </div>
      </div>
      {loading && (
        <p className="tip" role="status">
          A carregar painéis deste servidor…
        </p>
      )}
      {!localPreviewMode && !loading && panels.length === 0 && (
        <p className="tip">
          Ainda não existe um painel publicado. Escolhe um canal e cargos acima e guarda.
        </p>
      )}
      {panels.length > 0 && (
        <div className="template-list" aria-label="Role panels">
          {panels.map((panel) => (
            <div className="template-row" key={panel.message_id}>
              <div>
                <b>{panel.title || 'Role panel'}</b>
                <small>
                  #{channelName(panel.channel_id) ?? panel.channel_id ?? 'unknown channel'} ·{' '}
                  {roleNames(panel.role_ids) || 'no roles'} ·{' '}
                  {panel.selection_mode === 'unique' ? 'one choice' : 'multiple choices'}
                </small>
              </div>
              <div className="inline-actions">
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void repair(panel.message_id)}
                  disabled={busy}
                >
                  Repair
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void remove(panel.message_id)}
                  disabled={busy}
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      {error && (
        <p className="tip" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

function ConfigSection({
  section,
  config,
  context,
  onChange,
}: {
  section: SectionSpec;
  config: FeatureConfig;
  context: GuildContext | null;
  onChange: (key: string, value: unknown) => void;
}) {
  const advanced = section.fields.filter((field) => field.advanced);
  const basic = section.fields.filter((field) => !field.advanced);
  return (
    <section className="config-section card">
      <div className="section-heading">
        <div>
          <small className="eyebrow">CONFIGURAÇÃO</small>
          <h3>{section.title}</h3>
          <p>{section.description}</p>
        </div>
      </div>
      <div className="field-grid">
        {basic.map((field) => (
          <FieldControl
            field={field}
            key={field.key}
            value={config[field.key]}
            context={context}
            onChange={onChange}
          />
        ))}
      </div>
      {advanced.length > 0 && (
        <details className="advanced">
          <summary>
            Opções avançadas <span>{advanced.length} definições</span>
          </summary>
          <div className="field-grid">
            {advanced.map((field) => (
              <FieldControl
                field={field}
                key={field.key}
                value={config[field.key]}
                context={context}
                onChange={onChange}
              />
            ))}
          </div>
        </details>
      )}
    </section>
  );
}
function FieldControl({
  field,
  value,
  context,
  onChange,
}: {
  field: FieldSpec;
  value: unknown;
  context: GuildContext | null;
  onChange: (key: string, value: unknown) => void;
}) {
  const normalized =
    value ??
    (field.kind === 'toggle'
      ? false
      : field.kind === 'tags' || field.kind === 'channels' || field.kind === 'roles'
        ? []
        : '');
  const resourceOptions =
    field.kind === 'category'
      ? (context?.channels ?? []).filter((option) => option.type === 'category')
      : field.kind === 'channel' || field.kind === 'channels'
        ? (context?.channels ?? []).filter((option) => option.type !== 'category')
        : (context?.roles ?? []);
  const multiple = field.kind === 'channels' || field.kind === 'roles';
  if (
    field.kind === 'channel' ||
    field.kind === 'category' ||
    field.kind === 'channels' ||
    field.kind === 'role' ||
    field.kind === 'roles'
  )
    return (
      <label className="field">
        <span>
          <b>{field.label}</b>
          <small>
            {field.help ??
              (resourceOptions.length
                ? 'Seleciona um recurso existente.'
                : 'A leitura do Discord ainda não está disponível.')}
          </small>
        </span>
        <select
          value={
            multiple
              ? Array.isArray(normalized)
                ? normalized.map(String)
                : []
              : String(normalized)
          }
          multiple={multiple}
          size={multiple ? Math.min(5, Math.max(2, resourceOptions.length)) : undefined}
          onChange={(event) => {
            const selected = Array.from(event.currentTarget.selectedOptions).map(
              (option) => option.value,
            );
            onChange(field.key, multiple ? selected : (selected[0] ?? ''));
          }}
          disabled={
            (!context?.capabilities.channelSelectors &&
              (field.kind === 'channel' ||
                field.kind === 'category' ||
                field.kind === 'channels')) ||
            (!context?.capabilities.roleSelectors &&
              (field.kind === 'role' || field.kind === 'roles'))
          }
        >
          {!multiple && <option value="">Escolhe um recurso</option>}
          {resourceOptions.map((option) => (
            <option value={option.id} key={option.id}>
              {field.kind === 'role' || field.kind === 'roles'
                ? `@${option.name}`
                : field.kind === 'category'
                  ? `▾ ${option.name}`
                  : `#${option.name}`}
            </option>
          ))}
        </select>
      </label>
    );
  if (field.kind === 'toggle')
    return (
      <label className="field toggle-field">
        <span>
          <b>{field.label}</b>
          {field.help && <small>{field.help}</small>}
        </span>
        <input
          type="checkbox"
          checked={Boolean(normalized)}
          onChange={(event) => onChange(field.key, event.target.checked)}
        />
      </label>
    );
  if (field.kind === 'textarea')
    return (
      <label className="field">
        <span>
          <b>{field.label}</b>
          {field.help && <small>{field.help}</small>}
        </span>
        <textarea
          value={String(normalized)}
          onChange={(event) => onChange(field.key, event.target.value)}
          rows={3}
        />
      </label>
    );
  if (field.kind === 'tags')
    return (
      <label className="field">
        <span>
          <b>{field.label}</b>
          <small>{field.help ?? 'Separa vários valores por vírgulas.'}</small>
        </span>
        <input
          value={Array.isArray(normalized) ? normalized.join(', ') : String(normalized)}
          onChange={(event) =>
            onChange(
              field.key,
              event.target.value
                .split(',')
                .map((item) => item.trim())
                .filter(Boolean),
            )
          }
        />
      </label>
    );
  if (field.kind === 'select')
    return (
      <label className="field">
        <span>
          <b>{field.label}</b>
          {field.help && <small>{field.help}</small>}
        </span>
        <select
          value={String(normalized)}
          onChange={(event) => onChange(field.key, event.target.value)}
        >
          {field.options?.map((entry) => {
            const [option, label] = Array.isArray(entry) ? entry : [entry, entry];
            return (
              <option value={option} key={option}>
                {label}
              </option>
            );
          })}
        </select>
      </label>
    );
  return (
    <label className="field">
      <span>
        <b>{field.label}</b>
        {field.help && <small>{field.help}</small>}
      </span>
      <input
        type={field.kind}
        min={field.min}
        max={field.max}
        maxLength={field.maxLength}
        step={field.step ?? 1}
        value={field.kind === 'number' ? Number(normalized) : String(normalized)}
        onChange={(event) =>
          onChange(
            field.key,
            field.kind === 'number' ? Number(event.target.value) : event.target.value,
          )
        }
      />
    </label>
  );
}

function Activity({
  cases,
  audit,
  activity,
}: {
  cases: CaseRecord[];
  audit: AuditRecord[];
  activity: ActivityRecord[];
}) {
  return (
    <section className="activity">
      <div className="section-heading">
        <div>
          <small className="eyebrow">TRANSPARÊNCIA</small>
          <h2>Atividade recente</h2>
          <p>Cada ação mostra o que aconteceu sem esconder detalhes importantes.</p>
        </div>
      </div>
      <div className="table card">
        <div className="table-head">
          <span>Ação</span>
          <span>Alvo / ator</span>
          <span>Estado</span>
          <span>Data</span>
        </div>
        {cases.map((item) => (
          <div className="table-row" key={`case-${item.id}`}>
            <span>
              <b className="tag danger">{item.kind ?? item.type ?? 'moderação'}</b>
            </span>
            <span>{item.target_id ?? item.targetId ?? '—'}</span>
            <span>{item.reason || 'Sem motivo indicado'}</span>
            <span>{formatDate(item.created_at ?? item.createdAt)}</span>
          </div>
        ))}
        {audit.map((item, index) => (
          <div className="table-row" key={`audit-${index}`}>
            <span>
              <b className="tag">{item.action}</b>
            </span>
            <span>{item.actor_id ?? item.actorId ?? '—'}</span>
            <span>{item.outcome}</span>
            <span>{formatDate(item.created_at)}</span>
          </div>
        ))}
        {activity.map((item) => (
          <div className="table-row" key={`activity-${item.id}`}>
            <span>
              <b className="tag">{item.kind.replaceAll('_', ' ')}</b>
            </span>
            <span>{item.user_tag ?? item.user_id}</span>
            <span>Metadata only · {item.detail}</span>
            <span>{formatDate(item.created_at)}</span>
          </div>
        ))}
        {!cases.length && !audit.length && !activity.length && (
          <div className="empty">Ainda não há atividade para mostrar.</div>
        )}
      </div>
    </section>
  );
}
function formatDate(value?: number | string) {
  if (!value) return '—';
  const date =
    typeof value === 'number'
      ? new Date(value < 2_000_000_000 ? value * 1000 : value)
      : new Date(value);
  return Number.isNaN(date.valueOf())
    ? '—'
    : date.toLocaleString('pt-PT', { dateStyle: 'short', timeStyle: 'short' });
}

function RankCardEditor({
  config,
  patch,
  onSave,
  onReset,
  saving,
}: {
  config: RankCardConfig;
  patch: (next: Partial<RankCardConfig>) => void;
  onSave: () => void;
  onReset: () => void;
  saving: boolean;
}) {
  return (
    <section className="editor-grid panel-editor-grid">
      <div className="card preview-panel panel-preview-panel">
        <div className="card-title">
          <div>
            <small className="eyebrow">PRÉ-VISUALIZAÇÃO AO VIVO</small>
            <h2>Assim aparece no Discord</h2>
          </div>
          <span className="live-dot">● ao vivo</span>
        </div>
        <RankPreview config={config} />
      </div>
      <div className="card controls panel-controls">
        <div className="card-title">
          <div>
            <small className="eyebrow">EDITOR SEGURO</small>
            <h2>Identidade do XP card</h2>
            <p>Usa apenas banners curados pelo Vozen ou uma cor sólida.</p>
          </div>
        </div>
        <label>
          Fonte
          <select value={config.font} onChange={(event) => patch({ font: event.target.value })}>
            <option value="system">System</option>
            <option value="inter">Inter</option>
            <option value="roboto">Roboto</option>
            <option value="poppins">Poppins</option>
            <option value="space_grotesk">Space Grotesk</option>
            <option value="lexend">Lexend</option>
          </select>
        </label>
        <ColorField
          label="Cor principal"
          value={config.primary_color}
          swatches={swatches}
          onChange={(value) => patch({ primary_color: value, avatar_ring_color: value })}
        />
        <ColorField
          label="Cor do texto"
          value={config.text_color}
          swatches={swatches}
          onChange={(value) => patch({ text_color: value })}
        />
        <label>
          Opacidade do overlay <output>{Math.round(config.overlay_opacity * 100)}%</output>
          <input
            type="range"
            min="0"
            max="0.85"
            step="0.01"
            value={config.overlay_opacity}
            onChange={(event) => patch({ overlay_opacity: Number(event.target.value) })}
          />
        </label>
        <BackgroundPicker config={config} patch={patch} />
        <div className="actions rank-actions">
          <button type="button" className="secondary" onClick={onReset}>
            Restaurar
          </button>
          <button type="button" className="primary" onClick={onSave} disabled={saving}>
            {saving ? 'A guardar…' : 'Guardar alterações'}
          </button>
        </div>
      </div>
    </section>
  );
}
function BackgroundPicker({
  config,
  patch,
}: {
  config: RankCardConfig;
  patch: (next: Partial<RankCardConfig>) => void;
}) {
  const preset = config.background_preset;
  return (
    <div className="background-picker">
      <div className="field-label">
        <span>Fundo do XP card</span>
        <small>{preset ? 'Banner curado' : 'Cor sólida'}</small>
      </div>
      <div className="background-modes">
        <button
          type="button"
          className={!preset ? 'mode selected' : 'mode'}
          onClick={() =>
            patch({ background_preset: null, background_url: null, background_data: null })
          }
        >
          Cor sólida
        </button>
        <button
          type="button"
          className={preset ? 'mode selected' : 'mode'}
          onClick={() =>
            patch({
              background_preset: preset ?? presetOptions[0][0],
              background_url: null,
              background_data: null,
            })
          }
        >
          Banners
        </button>
      </div>
      {preset ? (
        <div className="banner-grid">
          {presetOptions.map(([id, label, path]) => (
            <button
              type="button"
              className={preset === id ? 'banner-option selected' : 'banner-option'}
              key={id}
              onClick={() =>
                patch({ background_preset: id, background_url: null, background_data: null })
              }
            >
              <img src={path} alt="" />
              <span>{label}</span>
            </button>
          ))}
        </div>
      ) : (
        <ColorField
          label="Escolhe uma cor de fundo"
          value={config.background_color}
          swatches={['#101725', '#172033', '#1F2937', '#312E46', '#3B2434', '#243A36']}
          onChange={(value) => patch({ background_color: value })}
        />
      )}
    </div>
  );
}
function ColorField({
  label,
  value,
  swatches: colors,
  onChange,
}: {
  label: string;
  value: string;
  swatches: string[];
  onChange: (value: string) => void;
}) {
  return (
    <div className="color-field">
      <div className="field-label">
        <span>{label}</span>
        <input
          type="color"
          value={value}
          onChange={(event) => onChange(event.target.value.toUpperCase())}
        />
      </div>
      <div className="swatches">
        {colors.map((color) => (
          <button
            type="button"
            aria-label={`${label}: ${color}`}
            title={color}
            key={color}
            className={color.toLowerCase() === value.toLowerCase() ? 'swatch selected' : 'swatch'}
            style={{ '--swatch-color': color } as CSSProperties}
            onClick={() => onChange(color)}
          />
        ))}
      </div>
    </div>
  );
}
function RankPreview({ config }: { config: RankCardConfig }) {
  const background = presetOptions.find(([id]) => id === config.background_preset)?.[2];
  const backgroundImage = background
    ? `linear-gradient(rgba(0,0,0,${config.overlay_opacity}), rgba(0,0,0,${config.overlay_opacity})), url(${JSON.stringify(background)})`
    : undefined;
  return (
    <div
      className="rank-preview"
      style={{
        backgroundColor: config.background_color,
        backgroundImage,
        fontFamily: config.font === 'system' ? 'system-ui' : config.font.replace('_', ' '),
      }}
    >
      <div
        className="rank-avatar"
        style={{ borderColor: config.avatar_ring_color, borderWidth: config.avatar_ring_width }}
      >
        <span>✦</span>
      </div>
      <div className="rank-content">
        <div className="rank-top">
          <strong style={{ color: config.text_color }}>Lunara</strong>
          <div>
            <b style={{ color: config.primary_color }}>Rank #17</b>
            <b style={{ color: config.text_color }}>Level 8</b>
          </div>
        </div>
        <p style={{ color: config.primary_color }}>lunara#4821</p>
        <div className="xp-meta">
          <span style={{ color: config.text_color }}>429 / 1337 XP</span>
          <span style={{ color: config.text_color }}>32%</span>
        </div>
        <div className="xp-track">
          <i style={{ background: config.primary_color, width: '32%' }} />
        </div>
      </div>
    </div>
  );
}

export default App;
