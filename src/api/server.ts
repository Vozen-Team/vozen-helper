import Fastify, { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import type Database from 'better-sqlite3';
import { fetchDiscordUser, type DiscordUser } from './discordAuth.js';
import { sessionTokenDigest, signSessionToken, verifySessionTokenClaims } from './session.js';
import { getRecentCases, countCases } from '../store/cases.js';
import { getRecentActivity, countActivity } from '../store/activity.js';
import { getStatsTotals } from '../community/store.js';
import { deleteSetting, getSetting, setSetting } from '../store/settings.js';
import { getEffectiveFlags, FLAG_KEYS, flagSettingKey, clearFlagCache } from '../store/flags.js';
import {
  getEffectiveTexts,
  TEXT_DEFS,
  TEXT_SETTING_KEYS,
  textSettingKey,
  clearTextCache,
} from '../store/textSettings.js';
import {
  getChannelSettingsView,
  CHANNEL_SETTING_KEYS,
  clearChannelCache,
} from '../store/channelSettings.js';
import { fetchGuildChannels, validateChannelValue, type GuildChannel } from './channels.js';
import { modConfig } from '../config.js';

// Servidor HTTP da API do painel. Trata-se como superfície HOSTIL: CORS trancado ao
// origin do site, sessão por cookie assinado + httpOnly, verificação de identidade
// feita no servidor. Ouve só em 127.0.0.1 (o túnel é quem a expõe).

/** Nome do cookie de sessão. */
const COOKIE = 'vh_session';
/** Validade da sessão (8 horas). */
const SESSION_MAX_AGE = 60 * 60 * 8;
const MAX_REVOKED_SESSIONS = 1_000;

/** Nº máximo de casos devolvidos numa listagem (teto anti-abuso). */
const MAX_CASES = 200;

/** Nº máximo de eventos de atividade por listagem. */
const MAX_ACTIVITY = 200;
/** Allowlist de tipos filtráveis no endpoint de atividade. */
const ACTIVITY_TYPES = new Set(['join', 'leave', 'ban', 'unban', 'kick']);

// Configuração editável pelo painel web. As chaves são deliberadamente fechadas:
// o painel nunca pode escrever definições arbitrárias na tabela de settings.
const WEB_CONFIG_KEYS = [
  'quarantine',
  'giveaways',
  'workflows',
  'polls-events',
  'self-roles',
  'audit',
  'permissions',
  'privacy',
  'templates',
] as const;
type WebConfigKey = (typeof WEB_CONFIG_KEYS)[number];
const WEB_CONFIG_KEY_SET = new Set<string>(WEB_CONFIG_KEYS);
const WEB_CONFIG_MAX_VALUE_BYTES = 64 * 1024;

const WEB_CONFIG_DEFAULTS: Record<WebConfigKey, unknown> = {
  quarantine: { enabled: false, durationMinutes: 30, action: 'restrict' },
  giveaways: { giveaways: [] },
  workflows: [],
  'polls-events': { polls: [], events: [] },
  'self-roles': { panels: [] },
  audit: { enabled: true, logChannelId: '', retentionDays: 90 },
  permissions: { reviewRequired: true, allowedRoleIds: [] },
  privacy: { retentionDays: 90, allowExports: true },
  templates: [],
};

function webConfigStorageKey(key: WebConfigKey): string {
  return `web.${key}`;
}

function readWebConfig(db: Database.Database, guildId: string): Record<WebConfigKey, unknown> {
  const config = {} as Record<WebConfigKey, unknown>;
  for (const key of WEB_CONFIG_KEYS) {
    const raw = getSetting(db, guildId, webConfigStorageKey(key));
    if (raw === null) {
      config[key] = WEB_CONFIG_DEFAULTS[key];
      continue;
    }
    try {
      config[key] = JSON.parse(raw) as unknown;
    } catch {
      // Configuração antiga/corrompida não deve quebrar o painel inteiro.
      config[key] = WEB_CONFIG_DEFAULTS[key];
    }
  }
  return config;
}

function jsonSize(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

export interface ServerOptions {
  /** Application ID Discord esperada no token OAuth do painel. */
  clientId: string;
  /** Única conta autorizada. */
  allowedUserId: string;
  /** ÚNICO servidor cujos dados a API serve. */
  guildId: string;
  /** Token do bot (para listar canais). */
  botToken: string;
  /** Segredo de assinatura do cookie. */
  sessionSecret: string;
  /** Origin autorizado no CORS. */
  allowedOrigin: string;
  /** Handle de leitura da SQLite do bot. */
  db: Database.Database;
  /** Verificador de token (injetável nos testes; default = Discord real). */
  verifyUser?: (token: string, clientId: string) => Promise<DiscordUser | null>;
  /** Lista de canais (injetável nos testes; default = REST do Discord). */
  listChannels?: () => Promise<GuildChannel[]>;
  /** Relógio injetável para validar a expiração no servidor. */
  now?: () => number;
}

class RevokedSessionStore {
  private readonly byDigest = new Map<string, number>();

  private prune(now: number): void {
    for (const [digest, expiresAt] of this.byDigest) {
      if (expiresAt <= now) this.byDigest.delete(digest);
    }
  }

  revoke(token: string, expiresAt: number, now: number): void {
    this.prune(now);
    const digest = sessionTokenDigest(token);
    if (!this.byDigest.has(digest) && this.byDigest.size >= MAX_REVOKED_SESSIONS) {
      let oldestDigest: string | undefined;
      let oldestExpiry = Number.POSITIVE_INFINITY;
      for (const [existingDigest, existingExpiry] of this.byDigest) {
        if (existingExpiry < oldestExpiry) {
          oldestDigest = existingDigest;
          oldestExpiry = existingExpiry;
        }
      }
      if (oldestDigest) this.byDigest.delete(oldestDigest);
    }
    this.byDigest.set(digest, expiresAt);
  }

  has(token: string, now: number): boolean {
    this.prune(now);
    return this.byDigest.has(sessionTokenDigest(token));
  }
}

/** Constrói (sem arrancar) a instância Fastify com as rotas da Fase 1. */
export function buildServer(opts: ServerOptions): FastifyInstance {
  const verify =
    opts.verifyUser ?? ((token: string, clientId: string) => fetchDiscordUser(token, clientId));
  const listChannels = opts.listChannels ?? (() => fetchGuildChannels(opts.botToken, opts.guildId));
  const now = opts.now ?? Date.now;
  // Cache curto da lista de canais (evita bater na REST do Discord a cada pedido).
  let chanCache: { at: number; list: GuildChannel[] } | null = null;
  async function channels(now: number): Promise<GuildChannel[]> {
    if (chanCache && now - chanCache.at < 30_000) return chanCache.list;
    const list = await listChannels();
    chanCache = { at: now, list };
    return list;
  }

  const app = Fastify({ logger: false });

  // Cookie assinado (o segredo assina/verifica) + CORS com credenciais só p/ o site.
  void app.register(cookie, { secret: opts.sessionSecret });
  void app.register(cors, {
    origin: opts.allowedOrigin,
    credentials: true,
    // PATCH é obrigatório aqui: o painel grava com PATCH (/api/flags e
    // /api/channel-settings). O default do @fastify/cors é só GET,HEAD,POST — sem
    // isto o browser bloqueia a escrita antes de a enviar (surge como "CORS error").
    methods: ['GET', 'HEAD', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });
  // Rate-limit global: superfície exposta à internet. 120 pedidos/min por IP.
  void app.register(rateLimit, { max: 120, timeWindow: '1 minute' });

  // Healthcheck público (usado pelo túnel).
  app.get('/health', async () => ({ ok: true }));

  // Troca do token Discord por uma sessão. Verificação SEMPRE no servidor.
  app.post('/api/session', async (req: FastifyRequest, reply: FastifyReply) => {
    const body = (req.body ?? {}) as { token?: unknown };
    const token = typeof body.token === 'string' ? body.token : '';
    if (!token) return reply.code(400).send({ error: 'missing_token' });

    let user: DiscordUser | null;
    try {
      user = await verify(token, opts.clientId);
    } catch {
      return reply.code(502).send({ error: 'discord_unreachable' });
    }

    if (!user) return reply.code(401).send({ error: 'invalid_token' });
    if (user.id !== opts.allowedUserId) return reply.code(403).send({ error: 'blocked' });

    const sessionToken = signSessionToken(user.id, opts.sessionSecret, now(), SESSION_MAX_AGE);
    reply.setCookie(COOKIE, sessionToken, {
      signed: true,
      httpOnly: true,
      secure: true,
      sameSite: 'none', // site (github.io) e API (túnel) são cross-site
      path: '/',
      maxAge: SESSION_MAX_AGE,
    });
    // O token no corpo é o mecanismo principal (o painel envia-o no header Authorization);
    // o cookie fica como fallback para navegadores que aceitam cookies de terceiros.
    return {
      ok: true,
      user: { id: user.id, name: user.global_name || user.username },
      token: sessionToken,
    };
  });

  // Tokens revogados por logout. Em memória: perde-se num restart da API, mas os
  // tokens expiram sozinhos em 8h e o painel é de UMA conta — risco residual aceite.
  const revoked = new RevokedSessionStore();

  function revokeIfValid(token: string, at: number): void {
    const claims = verifySessionTokenClaims(token, opts.sessionSecret, at);
    if (claims?.userId === opts.allowedUserId) {
      revoked.revoke(token, claims.expiresAt, at);
    }
  }

  // Termina a sessão: limpa o cookie e revoga o Bearer token (se enviado).
  app.post('/api/logout', async (req: FastifyRequest, reply: FastifyReply) => {
    const bearer =
      req.headers.authorization?.startsWith('Bearer ') &&
      req.headers.authorization.slice(7).trim().length > 0;
    const originCount = req.raw.rawHeaders.filter(
      (value, index) => index % 2 === 0 && value.toLowerCase() === 'origin',
    ).length;
    if (!bearer && (originCount !== 1 || req.headers.origin !== opts.allowedOrigin)) {
      return reply.code(403).send({ error: 'csrf_origin_invalid' });
    }
    const at = now();
    const auth = req.headers.authorization;
    if (auth?.startsWith('Bearer ')) revokeIfValid(auth.slice(7), at);
    const cookieToken = req.cookies[COOKIE];
    if (cookieToken) {
      const unsigned = req.unsignCookie(cookieToken);
      if (unsigned.valid) revokeIfValid(unsigned.value, at);
    }
    reply.clearCookie(COOKIE, { path: '/' });
    return { ok: true };
  });

  // Guarda de sessão: aceita (1) token no header Authorization (principal, robusto
  // cross-site) OU (2) o cookie assinado (fallback). Ambos têm de ser da conta certa.
  const guard = async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const at = now();
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) {
      const raw = auth.slice(7);
      if (!revoked.has(raw, at)) {
        const claims = verifySessionTokenClaims(raw, opts.sessionSecret, at);
        if (claims?.userId === opts.allowedUserId) return;
      }
    }
    const raw = req.cookies[COOKIE];
    if (raw) {
      const un = req.unsignCookie(raw);
      if (un.valid && !revoked.has(un.value, at)) {
        const claims = verifySessionTokenClaims(un.value, opts.sessionSecret, at);
        if (claims?.userId === opts.allowedUserId) return;
      }
    }
    await reply.code(401).send({ error: 'unauthenticated' });
  };

  // Sessão atual + smoke test de leitura da DB (prova o handle partilhado).
  app.get('/api/me', { preHandler: guard }, async () => {
    const row = opts.db.prepare('SELECT 1 AS ok').get() as { ok: number } | undefined;
    return { id: opts.allowedUserId, dbOk: row?.ok === 1 };
  });

  // Casos de moderação mais recentes do servidor.
  app.get('/api/cases', { preHandler: guard }, async (req: FastifyRequest) => {
    const q = (req.query ?? {}) as { limit?: unknown };
    const raw = typeof q.limit === 'string' ? Number.parseInt(q.limit, 10) : 50;
    const limit = Math.min(Math.max(Number.isFinite(raw) ? raw : 50, 1), MAX_CASES);
    return { cases: getRecentCases(opts.db, opts.guildId, limit) };
  });

  // Estatísticas agregadas do servidor + total de casos (para o dashboard).
  app.get('/api/stats', { preHandler: guard }, async () => {
    const totals = getStatsTotals(opts.db, opts.guildId);
    return { ...totals, totalCases: countCases(opts.db, opts.guildId) };
  });

  // Registo de atividade (dashboard: joins com convite, leaves, …). Filtro por tipo opcional.
  app.get('/api/activity', { preHandler: guard }, async (req: FastifyRequest) => {
    const q = (req.query ?? {}) as { limit?: unknown; type?: unknown };
    const raw = typeof q.limit === 'string' ? Number.parseInt(q.limit, 10) : 50;
    const limit = Math.min(Math.max(Number.isFinite(raw) ? raw : 50, 1), MAX_ACTIVITY);
    const type = typeof q.type === 'string' && ACTIVITY_TYPES.has(q.type) ? q.type : undefined;
    return {
      activity: getRecentActivity(opts.db, opts.guildId, limit, type),
      total: countActivity(opts.db, opts.guildId),
    };
  });

  // Estado efetivo dos toggles de subsistemas (override na DB ou default do modConfig).
  app.get('/api/flags', { preHandler: guard }, async () => {
    return { flags: getEffectiveFlags(opts.db, opts.guildId, modConfig) };
  });

  // Liga/desliga um subsistema. ESCRITA — allowlist de chaves + validação estrita.
  app.patch(
    '/api/flags',
    { preHandler: guard },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const body = (req.body ?? {}) as { key?: unknown; enabled?: unknown };
      const key = typeof body.key === 'string' ? body.key : '';
      const enabled = body.enabled;
      if (!FLAG_KEYS.has(key)) return reply.code(400).send({ error: 'invalid_key' });
      if (typeof enabled !== 'boolean') return reply.code(400).send({ error: 'invalid_value' });

      setSetting(
        opts.db,
        opts.guildId,
        flagSettingKey(key),
        enabled ? 'true' : 'false',
        Date.now(),
      );
      clearFlagCache(); // este processo reflete já; o bot apanha via TTL
      // Auditoria (fica no api.log).
      console.log(
        `[api] flag ${key}=${enabled} por ${opts.allowedUserId} @ ${new Date().toISOString()}`,
      );
      return { ok: true, flags: getEffectiveFlags(opts.db, opts.guildId, modConfig) };
    },
  );

  // Textos editáveis (ex.: mensagem da DM de boas-vindas). Override na DB ou default.
  app.get('/api/text-settings', { preHandler: guard }, async () => {
    return { texts: getEffectiveTexts(opts.db, opts.guildId, modConfig) };
  });

  // Edita um texto. ESCRITA — allowlist de chaves + limite de tamanho por chave.
  app.patch(
    '/api/text-settings',
    { preHandler: guard },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const body = (req.body ?? {}) as { key?: unknown; value?: unknown };
      const key = typeof body.key === 'string' ? body.key : '';
      const value = typeof body.value === 'string' ? body.value : null;
      if (!TEXT_SETTING_KEYS.has(key)) return reply.code(400).send({ error: 'invalid_key' });
      if (value === null || value.trim().length === 0)
        return reply.code(400).send({ error: 'empty' });
      const def = TEXT_DEFS.find((t) => t.key === key);
      if (def && value.length > def.maxLen) return reply.code(400).send({ error: 'too_long' });

      setSetting(opts.db, opts.guildId, textSettingKey(key), value, Date.now());
      clearTextCache(); // este processo reflete já; o bot apanha via TTL
      console.log(
        `[api] text ${key} (${value.length} chars) por ${opts.allowedUserId} @ ${new Date().toISOString()}`,
      );
      return { ok: true, texts: getEffectiveTexts(opts.db, opts.guildId, modConfig) };
    },
  );

  // Lista de canais do servidor (para os dropdowns do painel).
  app.get(
    '/api/channels',
    { preHandler: guard },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      try {
        return { channels: await channels(Date.now()) };
      } catch {
        return reply.code(502).send({ error: 'discord_unreachable' });
      }
    },
  );

  // Estado atual das definições de canal.
  app.get('/api/channel-settings', { preHandler: guard }, async () => {
    return { settings: getChannelSettingsView(opts.db, opts.guildId, modConfig) };
  });

  // Altera uma definição de canal. ESCRITA — allowlist + validação contra os canais reais.
  app.patch(
    '/api/channel-settings',
    { preHandler: guard },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const body = (req.body ?? {}) as { key?: unknown; value?: unknown };
      const key = typeof body.key === 'string' ? body.key : '';
      const value = typeof body.value === 'string' ? body.value : '';
      if (!CHANNEL_SETTING_KEYS.has(key)) return reply.code(400).send({ error: 'invalid_key' });

      let validIds: Set<string>;
      try {
        validIds = new Set((await channels(Date.now())).map((c) => c.id));
      } catch {
        return reply.code(502).send({ error: 'discord_unreachable' });
      }
      if (!validateChannelValue(key, value, validIds)) {
        return reply.code(400).send({ error: 'invalid_value' });
      }

      setSetting(opts.db, opts.guildId, key, value, Date.now());
      clearChannelCache();
      console.log(
        `[api] channel ${key}=${value} por ${opts.allowedUserId} @ ${new Date().toISOString()}`,
      );
      return { ok: true, settings: getChannelSettingsView(opts.db, opts.guildId, modConfig) };
    },
  );

  // Configurações avançadas do site. São JSON versionados por funcionalidade,
  // com allowlist e limites de tamanho. Assim o painel pode evoluir sem criar
  // uma tabela nova para cada cartão e o bot pode consumi-las numa fase seguinte.
  app.get('/api/web-config', { preHandler: guard }, async () => ({
    config: readWebConfig(opts.db, opts.guildId),
  }));

  app.patch(
    '/api/web-config',
    { preHandler: guard },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const body = (req.body ?? {}) as { key?: unknown; value?: unknown };
      const key = typeof body.key === 'string' ? body.key : '';
      if (!WEB_CONFIG_KEY_SET.has(key)) return reply.code(400).send({ error: 'invalid_key' });
      const value = body.value;
      if (value === undefined || typeof value === 'function') {
        return reply.code(400).send({ error: 'invalid_value' });
      }
      let serialized: string;
      try {
        serialized = JSON.stringify(value);
      } catch {
        return reply.code(400).send({ error: 'invalid_value' });
      }
      if (Buffer.byteLength(serialized, 'utf8') > WEB_CONFIG_MAX_VALUE_BYTES) {
        return reply.code(413).send({ error: 'value_too_large' });
      }
      setSetting(
        opts.db,
        opts.guildId,
        webConfigStorageKey(key as WebConfigKey),
        serialized,
        now(),
      );
      console.log(
        `[api] web config ${key} updated by ${opts.allowedUserId} @ ${new Date().toISOString()}`,
      );
      return { ok: true, config: readWebConfig(opts.db, opts.guildId) };
    },
  );

  // Exportação/importação servem para backups e para clonar uma configuração
  // entre servidores. O ficheiro nunca contém tokens, mensagens ou dados de membros.
  app.get('/api/web-config/export', { preHandler: guard }, async () => ({
    version: 1,
    exportedAt: new Date(now()).toISOString(),
    config: readWebConfig(opts.db, opts.guildId),
  }));

  app.post(
    '/api/web-config/import',
    { preHandler: guard },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const body = (req.body ?? {}) as { config?: unknown };
      const incoming = body.config;
      if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
        return reply.code(400).send({ error: 'invalid_config' });
      }
      const entries = Object.entries(incoming as Record<string, unknown>);
      if (entries.some(([key]) => !WEB_CONFIG_KEY_SET.has(key))) {
        return reply.code(400).send({ error: 'invalid_key' });
      }
      const totalBytes = entries.reduce((total, [, value]) => total + jsonSize(value), 0);
      if (totalBytes > WEB_CONFIG_MAX_VALUE_BYTES * WEB_CONFIG_KEYS.length) {
        return reply.code(413).send({ error: 'config_too_large' });
      }
      for (const [, value] of entries) {
        if (jsonSize(value) > WEB_CONFIG_MAX_VALUE_BYTES) {
          return reply.code(413).send({ error: 'value_too_large' });
        }
      }
      const save = opts.db.transaction(() => {
        for (const [key, value] of entries) {
          setSetting(
            opts.db,
            opts.guildId,
            webConfigStorageKey(key as WebConfigKey),
            JSON.stringify(value),
            now(),
          );
        }
      });
      save();
      console.log(
        `[api] web config imported by ${opts.allowedUserId} @ ${new Date().toISOString()}`,
      );
      return { ok: true, config: readWebConfig(opts.db, opts.guildId) };
    },
  );

  app.post('/api/web-config/delete', { preHandler: guard }, async (_req: FastifyRequest) => {
    for (const key of WEB_CONFIG_KEYS)
      deleteSetting(opts.db, opts.guildId, webConfigStorageKey(key));
    console.log(`[api] web config deleted by ${opts.allowedUserId} @ ${new Date().toISOString()}`);
    return { ok: true, config: readWebConfig(opts.db, opts.guildId) };
  });

  return app;
}
