import { describe, it, expect, beforeEach } from 'vitest';
import type Database from 'better-sqlite3';
import type { FastifyInstance } from 'fastify';
import { initDb } from '../src/store/db.js';
import { buildServer } from '../src/api/server.js';
import { fetchDiscordUser, type DiscordUser, type FetchLike } from '../src/api/discordAuth.js';
import { loadApiEnv, ApiConfigError } from '../src/api/config.js';
import { insertCase } from '../src/store/cases.js';
import { logActivity } from '../src/store/activity.js';
import { incrStat } from '../src/community/store.js';
import { signSessionToken, verifySessionToken } from '../src/api/session.js';

// Fase 1/2 — API + auth + leitura. A verificação de identidade é feita no servidor;
// só a conta autorizada obtém sessão e lê dados do servidor.

// Synthetic identities and origin for isolated API fixtures.
const ALLOWED = '100000000000000001';
const GUILD = '100000000000000002';
const SECRET = 'x'.repeat(40);
const ORIGIN = 'https://admin.example.com';

const FAKE_CHANNELS = [
  { id: '900000000000000001', name: 'geral', type: 0 },
  { id: '900000000000000002', name: 'logs', type: 0 },
  { id: '900000000000000003', name: 'sugestoes', type: 0 },
];

function makeApp(db: Database.Database, user: DiscordUser | null | 'throw') {
  return buildServer({
    allowedUserId: ALLOWED,
    guildId: GUILD,
    botToken: 'bot-token',
    sessionSecret: SECRET,
    allowedOrigin: ORIGIN,
    db,
    verifyUser: async () => {
      if (user === 'throw') throw new Error('rede');
      return user;
    },
    listChannels: async () => FAKE_CHANNELS,
  });
}

/** Faz login e devolve o valor do cookie de sessão (para as rotas protegidas). */
async function login(app: FastifyInstance): Promise<string> {
  const res = await app.inject({ method: 'POST', url: '/api/session', payload: { token: 'abc' } });
  const c = res.cookies.find((x) => x.name === 'vh_session');
  if (!c) throw new Error('login sem cookie');
  return c.value;
}

/** Faz login e devolve o token de sessão (header Authorization). */
async function loginToken(app: FastifyInstance): Promise<string> {
  const res = await app.inject({ method: 'POST', url: '/api/session', payload: { token: 'abc' } });
  const body = res.json() as { token?: string };
  if (!body.token) throw new Error('login sem token');
  return body.token;
}

let db: Database.Database;
beforeEach(() => {
  db = initDb(':memory:');
});

describe('POST /api/session', () => {
  it('cria sessão para a conta permitida (200 + cookie)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'diogo' });
    const res = await app.inject({ method: 'POST', url: '/api/session', payload: { token: 'abc' } });
    expect(res.statusCode).toBe(200);
    expect(res.cookies.find((c) => c.name === 'vh_session')).toBeTruthy();
  });

  it('bloqueia outra conta (403)', async () => {
    const app = makeApp(db, { id: '999999999999999999', username: 'outro' });
    const res = await app.inject({ method: 'POST', url: '/api/session', payload: { token: 'abc' } });
    expect(res.statusCode).toBe(403);
    expect(res.cookies.find((c) => c.name === 'vh_session')).toBeUndefined();
  });

  it('token inválido → 401', async () => {
    const app = makeApp(db, null);
    const res = await app.inject({ method: 'POST', url: '/api/session', payload: { token: 'abc' } });
    expect(res.statusCode).toBe(401);
  });

  it('sem token → 400', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({ method: 'POST', url: '/api/session', payload: {} });
    expect(res.statusCode).toBe(400);
  });

  it('Discord inacessível → 502', async () => {
    const app = makeApp(db, 'throw');
    const res = await app.inject({ method: 'POST', url: '/api/session', payload: { token: 'abc' } });
    expect(res.statusCode).toBe(502);
  });
});

describe('GET /api/me (protegida)', () => {
  it('sem cookie → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({ method: 'GET', url: '/api/me' });
    expect(res.statusCode).toBe(401);
  });

  it('com cookie válido → 200 e lê a DB', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const login = await app.inject({ method: 'POST', url: '/api/session', payload: { token: 'abc' } });
    const c = login.cookies.find((x) => x.name === 'vh_session');
    if (!c) throw new Error('sessão sem cookie');
    const res = await app.inject({
      method: 'GET',
      url: '/api/me',
      cookies: { vh_session: c.value },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ id: ALLOWED, dbOk: true });
  });

  it('cookie forjado (não assinado) → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({
      method: 'GET',
      url: '/api/me',
      cookies: { vh_session: ALLOWED }, // valor sem assinatura válida
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('GET /api/cases (protegida)', () => {
  it('sem cookie → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({ method: 'GET', url: '/api/cases' });
    expect(res.statusCode).toBe(401);
  });

  it('devolve os casos do servidor, do mais recente ao mais antigo', async () => {
    insertCase(db, { guildId: GUILD, type: 'warn', targetId: 'u1', moderatorId: 'm', reason: 'a', createdAt: 1 });
    insertCase(db, { guildId: GUILD, type: 'ban', targetId: 'u2', moderatorId: 'm', reason: 'b', createdAt: 2 });
    insertCase(db, { guildId: 'outro-guild', type: 'kick', targetId: 'u3', moderatorId: 'm', createdAt: 3 });
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const cookie = await login(app);
    const res = await app.inject({ method: 'GET', url: '/api/cases', cookies: { vh_session: cookie } });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { cases: { id: number; type: string }[] };
    expect(body.cases).toHaveLength(2); // exclui o outro guild
    expect(body.cases[0].type).toBe('ban'); // mais recente primeiro
  });

  it('respeita o teto do limite (máx. 200)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const cookie = await login(app);
    const res = await app.inject({
      method: 'GET',
      url: '/api/cases?limit=99999',
      cookies: { vh_session: cookie },
    });
    expect(res.statusCode).toBe(200); // não rebenta; o teto aplica-se internamente
  });
});

describe('GET /api/activity (protegida)', () => {
  it('sem sessão → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({ method: 'GET', url: '/api/activity' });
    expect(res.statusCode).toBe(401);
  });

  it('devolve a atividade do servidor (recente primeiro, exclui outro guild) + total', async () => {
    logActivity(db, { guildId: GUILD, type: 'join', userId: 'u1', userTag: 'A#1', detail: { inviteCode: 'abc' }, createdAt: 1 });
    logActivity(db, { guildId: GUILD, type: 'leave', userId: 'u2', userTag: 'B#2', createdAt: 2 });
    logActivity(db, { guildId: 'outro-guild', type: 'join', userId: 'u3', createdAt: 3 });
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const cookie = await login(app);
    const res = await app.inject({ method: 'GET', url: '/api/activity', cookies: { vh_session: cookie } });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { activity: { type: string; detail: Record<string, unknown> }[]; total: number };
    expect(body.activity).toHaveLength(2); // exclui o outro guild
    expect(body.activity[0].type).toBe('leave'); // mais recente primeiro
    expect(body.activity[1].detail.inviteCode).toBe('abc'); // detail parseado
    expect(body.total).toBe(2);
  });

  it('filtra por tipo', async () => {
    logActivity(db, { guildId: GUILD, type: 'join', userId: 'u1', createdAt: 1 });
    logActivity(db, { guildId: GUILD, type: 'leave', userId: 'u2', createdAt: 2 });
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const cookie = await login(app);
    const res = await app.inject({ method: 'GET', url: '/api/activity?type=join', cookies: { vh_session: cookie } });
    const body = res.json() as { activity: { type: string }[] };
    expect(body.activity).toHaveLength(1);
    expect(body.activity[0].type).toBe('join');
  });
});

describe('GET /api/stats (protegida)', () => {
  it('agrega mensagens/joins/leaves + total de casos', async () => {
    incrStat(db, GUILD, '2026-07-14', 'messages');
    incrStat(db, GUILD, '2026-07-14', 'messages');
    incrStat(db, GUILD, '2026-07-14', 'joins');
    insertCase(db, { guildId: GUILD, type: 'warn', targetId: 'u1', moderatorId: 'm', createdAt: 1 });
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const cookie = await login(app);
    const res = await app.inject({ method: 'GET', url: '/api/stats', cookies: { vh_session: cookie } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ messages: 2, joins: 1, leaves: 0, totalCases: 1 });
  });

  it('sem cookie → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({ method: 'GET', url: '/api/stats' });
    expect(res.statusCode).toBe(401);
  });
});

describe('auth por token (header Authorization)', () => {
  it('/api/session devolve um token', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const t = await loginToken(app);
    expect(t.split('.')).toHaveLength(3);
  });

  it('/api/me aceita Bearer válido (sem cookie)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'GET',
      url: '/api/me',
      headers: { authorization: 'Bearer ' + token },
    });
    expect(res.statusCode).toBe(200);
  });

  it('/api/cases aceita Bearer válido', async () => {
    insertCase(db, { guildId: GUILD, type: 'warn', targetId: 'u', moderatorId: 'm', createdAt: 1 });
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'GET',
      url: '/api/cases',
      headers: { authorization: 'Bearer ' + token },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { cases: unknown[] }).cases).toHaveLength(1);
  });

  it('logout revoga o Bearer (o mesmo token deixa de servir)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const before = await app.inject({
      method: 'GET', url: '/api/me', headers: { authorization: 'Bearer ' + token },
    });
    expect(before.statusCode).toBe(200);
    await app.inject({
      method: 'POST', url: '/api/logout', headers: { authorization: 'Bearer ' + token },
    });
    const after = await app.inject({
      method: 'GET', url: '/api/me', headers: { authorization: 'Bearer ' + token },
    });
    expect(after.statusCode).toBe(401);
  });

  it('Bearer forjado → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({
      method: 'GET',
      url: '/api/me',
      headers: { authorization: 'Bearer ' + ALLOWED + '.9999999999.assinaturafalsa' },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('signSessionToken / verifySessionToken', () => {
  const S = 'y'.repeat(40);
  it('assina e verifica ida-e-volta', () => {
    const now = 1_000_000_000_000;
    const t = signSessionToken(ALLOWED, S, now, 3600);
    expect(verifySessionToken(t, S, now)).toBe(ALLOWED);
  });
  it('rejeita expirado', () => {
    const now = 1_000_000_000_000;
    const t = signSessionToken(ALLOWED, S, now, 10);
    expect(verifySessionToken(t, S, now + 20_000)).toBeNull();
  });
  it('rejeita segredo errado', () => {
    const now = 1_000_000_000_000;
    const t = signSessionToken(ALLOWED, S, now, 3600);
    expect(verifySessionToken(t, 'z'.repeat(40), now)).toBeNull();
  });
  it('rejeita adulteração', () => {
    const now = 1_000_000_000_000;
    const t = signSessionToken(ALLOWED, S, now, 3600);
    const tampered = '999.' + t.split('.').slice(1).join('.');
    expect(verifySessionToken(tampered, S, now)).toBeNull();
  });
});

describe('flags API (Fase 3/4)', () => {
  it('GET /api/flags devolve os toggles (protegida)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'GET',
      url: '/api/flags',
      headers: { authorization: 'Bearer ' + token },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { flags: unknown[] }).flags.length).toBeGreaterThanOrEqual(10);
  });

  it('PATCH /api/flags liga/desliga um subsistema', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/flags',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'antispam', enabled: false },
    });
    expect(res.statusCode).toBe(200);
    const flags = (res.json() as { flags: { key: string; enabled: boolean }[] }).flags;
    expect(flags.find((f) => f.key === 'antispam')?.enabled).toBe(false);
  });

  it('PATCH rejeita chave fora da allowlist (400)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/flags',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'DROP TABLE settings', enabled: true },
    });
    expect(res.statusCode).toBe(400);
  });

  it('PATCH rejeita valor não-booleano (400)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/flags',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'antispam', enabled: 'sim' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('PATCH sem sessão → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/flags',
      payload: { key: 'antispam', enabled: false },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('text-settings API (mensagem editável)', () => {
  it('GET /api/text-settings devolve os textos (protegida)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'GET',
      url: '/api/text-settings',
      headers: { authorization: 'Bearer ' + token },
    });
    expect(res.statusCode).toBe(200);
    const texts = (res.json() as { texts: { key: string }[] }).texts;
    expect(texts.find((t) => t.key === 'welcomedm.message')).toBeTruthy();
  });

  it('PATCH grava o texto e devolve o efetivo', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/text-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'welcomedm.message', value: 'Olá {user}!' },
    });
    expect(res.statusCode).toBe(200);
    const texts = (res.json() as { texts: { key: string; value: string }[] }).texts;
    expect(texts.find((t) => t.key === 'welcomedm.message')?.value).toBe('Olá {user}!');
  });

  it('PATCH rejeita chave fora da allowlist (400)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/text-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'evil.key', value: 'x' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('PATCH rejeita texto vazio (400)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/text-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'welcomedm.message', value: '   ' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('PATCH rejeita texto gigante (400)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/text-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'welcomedm.message', value: 'a'.repeat(1501) },
    });
    expect(res.statusCode).toBe(400);
  });

  it('PATCH sem sessão → 401', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/text-settings',
      payload: { key: 'welcomedm.message', value: 'x' },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('canais API (Fase canais)', () => {
  it('GET /api/channels lista os canais (protegida)', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'GET',
      url: '/api/channels',
      headers: { authorization: 'Bearer ' + token },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { channels: unknown[] }).channels.length).toBe(3);
  });

  it('GET /api/channel-settings devolve as definições', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'GET',
      url: '/api/channel-settings',
      headers: { authorization: 'Bearer ' + token },
    });
    expect(res.statusCode).toBe(200);
    const s = (res.json() as { settings: { key: string }[] }).settings;
    expect(s.map((x) => x.key)).toContain('chan.log');
    expect(s.map((x) => x.key)).toContain('xp.exclude');
  });

  it('PATCH channel válido grava', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/channel-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'chan.log', value: '900000000000000002' },
    });
    expect(res.statusCode).toBe(200);
    const s = (res.json() as { settings: { key: string; value: string }[] }).settings;
    expect(s.find((x) => x.key === 'chan.log')?.value).toBe('900000000000000002');
  });

  it('PATCH levelup=current é aceite', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/channel-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'chan.levelup', value: 'current' },
    });
    expect(res.statusCode).toBe(200);
  });

  it('PATCH canal inexistente → 400', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/channel-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'chan.log', value: '123nao-existe' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('PATCH chave fora da allowlist → 400', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'd' });
    const token = await loginToken(app);
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/channel-settings',
      headers: { authorization: 'Bearer ' + token },
      payload: { key: 'chan.evil', value: '900000000000000001' },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('CORS — preflight das escritas', () => {
  // O painel grava com PATCH (/api/flags e /api/channel-settings). Sem `methods`
  // explícito o @fastify/cors anuncia só GET,HEAD,POST — o browser bloqueia o PATCH
  // antes de o enviar e o servidor nunca o vê (surge como "CORS error", 0 bytes).
  it('anuncia PATCH em access-control-allow-methods', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'diogo' });
    const res = await app.inject({
      method: 'OPTIONS',
      url: '/api/channel-settings',
      headers: {
        origin: ORIGIN,
        'access-control-request-method': 'PATCH',
        'access-control-request-headers': 'content-type,authorization',
      },
    });
    expect(res.statusCode).toBe(204);
    expect(String(res.headers['access-control-allow-methods'])).toContain('PATCH');
  });
});

describe('GET /health', () => {
  it('200 { ok: true }', async () => {
    const app = makeApp(db, null);
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.json()).toEqual({ ok: true });
  });
});

describe('fetchDiscordUser', () => {
  it('200 → devolve o utilizador', async () => {
    const fake: FetchLike = async () =>
      new Response(JSON.stringify({ id: '1', username: 'a' }), { status: 200 });
    const u = await fetchDiscordUser('tok', fake);
    expect(u?.id).toBe('1');
  });

  it('401 → null', async () => {
    const fake: FetchLike = async () => new Response('no', { status: 401 });
    expect(await fetchDiscordUser('tok', fake)).toBeNull();
  });

  it('token vazio → null (nem chama o fetch)', async () => {
    let called = false;
    const fake: FetchLike = async () => {
      called = true;
      return new Response('', { status: 200 });
    };
    expect(await fetchDiscordUser('', fake)).toBeNull();
    expect(called).toBe(false);
  });
});

describe('loadApiEnv', () => {
  const OK = {
    PANEL_ALLOWED_USER_ID: ALLOWED,
    PANEL_SESSION_SECRET: SECRET,
    GUILD_ID: GUILD,
    DISCORD_TOKEN: 'bot-token',
  };

  it('aceita config válida', () => {
    const cfg = loadApiEnv({ ...OK, PANEL_ALLOWED_ORIGIN: ORIGIN });
    expect(cfg.allowedUserId).toBe(ALLOWED);
    expect(cfg.guildId).toBe(GUILD);
    expect(cfg.port).toBe(8788);
    expect(cfg.allowedOrigin).toBe(ORIGIN);
    // Preserve coverage of the unchanged runtime default separately from test data.
    expect(loadApiEnv(OK).allowedOrigin).toBe('https://rexy40407.github.io');
  });

  it('falha se faltar o segredo', () => {
    expect(() => loadApiEnv({ PANEL_ALLOWED_USER_ID: ALLOWED, GUILD_ID: GUILD })).toThrow(
      ApiConfigError,
    );
  });

  it('falha se faltar o GUILD_ID', () => {
    expect(() =>
      loadApiEnv({ PANEL_ALLOWED_USER_ID: ALLOWED, PANEL_SESSION_SECRET: SECRET }),
    ).toThrow(ApiConfigError);
  });

  it('falha com segredo curto', () => {
    expect(() => loadApiEnv({ ...OK, PANEL_SESSION_SECRET: 'curto' })).toThrow(ApiConfigError);
  });

  it('falha com id inválido', () => {
    expect(() => loadApiEnv({ ...OK, PANEL_ALLOWED_USER_ID: 'nope' })).toThrow(ApiConfigError);
  });
});

describe('logout origin boundary', () => {
  it('rejects external, absent, duplicate and malformed origins without clearing the session', async () => {
    for (const origin of [
      undefined,
      'https://attacker.invalid',
      'null',
      '',
      ORIGIN + '.attacker.invalid',
      ORIGIN + ', https://attacker.invalid',
      [ORIGIN, ORIGIN],
    ]) {
      const app = makeApp(db, { id: ALLOWED, username: 'owner' });
      const cookie = await login(app);
      const headers: Record<string, string | string[]> = {};
      if (origin !== undefined) headers.origin = origin;
      const response = await app.inject({
        method: 'POST',
        url: '/api/logout',
        headers,
        cookies: { vh_session: cookie },
      });
      expect(response.statusCode).toBe(403);
      expect(response.headers['set-cookie']).toBeUndefined();
      const stillValid = await app.inject({
        method: 'GET',
        url: '/api/me',
        cookies: { vh_session: cookie },
      });
      expect(stillValid.statusCode).toBe(200);
      await app.close();
    }
  });

  it('clears cookies only for the configured origin and keeps explicit Bearer clients working', async () => {
    const app = makeApp(db, { id: ALLOWED, username: 'owner' });
    const cookie = await login(app);
    const logout = await app.inject({
      method: 'POST',
      url: '/api/logout',
      headers: { origin: ORIGIN },
      cookies: { vh_session: cookie },
    });
    expect(logout.statusCode).toBe(200);
    expect(logout.cookies.some((value) => value.name === 'vh_session' && value.value === '')).toBe(
      true,
    );
    await app.close();
    for (const origin of [undefined, 'https://attacker.invalid']) {
      const bearerApp = makeApp(db, { id: ALLOWED, username: 'owner' });
      const token = await loginToken(bearerApp);
      const valid = await bearerApp.inject({
        method: 'GET',
        url: '/api/me',
        headers: { authorization: 'Bearer ' + token },
      });
      expect(valid.statusCode).toBe(200);
      const response = await bearerApp.inject({
        method: 'POST',
        url: '/api/logout',
        headers: { authorization: 'Bearer ' + token, ...(origin ? { origin } : {}) },
      });
      expect(response.statusCode).toBe(200);
      const revoked = await bearerApp.inject({
        method: 'GET',
        url: '/api/me',
        headers: { authorization: 'Bearer ' + token },
      });
      expect(revoked.statusCode).toBe(401);
      await bearerApp.close();
    }
  });
});
