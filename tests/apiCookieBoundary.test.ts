import { beforeEach, describe, expect, it } from 'vitest';
import { initDb } from '../src/store/db.js';
import { buildServer } from '../src/api/server.js';
import { signSessionToken } from '../src/api/session.js';
import { getSetting, setSetting } from '../src/store/settings.js';

const USER = '100000000000000001';
const GUILD = '100000000000000002';
const ORIGIN = 'https://admin.example.com';
const SECRET = 'synthetic-session-secret-with-at-least-32-characters';
let now: number;

beforeEach(() => {
  now = 1_800_000_000_000;
});

async function fixture() {
  const db = initDb(':memory:');
  const options = {
    clientId: '100000000000000003',
    allowedUserId: USER,
    guildId: GUILD,
    botToken: 'synthetic-bot-token',
    sessionSecret: SECRET,
    allowedOrigin: ORIGIN,
    db,
    verifyUser: async () => ({ id: USER, username: 'synthetic-owner' }),
    listChannels: async () => [],
    now: () => now,
  };
  const app = buildServer(options);
  const login = await app.inject({
    method: 'POST',
    url: '/api/session',
    payload: { token: 'synthetic-oauth-token' },
  });
  expect(login.statusCode).toBe(200);
  const cookie = login.cookies.find((value) => value.name === 'vh_session')!.value;
  const token = login.json<{ token: string }>().token;
  return { app, db, cookie, token };
}

describe('logout requires an authenticated Bearer exception', () => {
  it('bad, expired, revoked or other-owner Bearers cannot bypass cookie Origin checks', async () => {
    for (const kind of ['invalid', 'expired', 'revoked', 'other-owner']) {
      const { app, db, token, cookie: initialCookie } = await fixture();
      let cookie = initialCookie;
      try {
        let badToken = 'invalid-token';
        if (kind === 'expired') {
          badToken = signSessionToken(USER, SECRET, now - 10_000, 1);
        } else if (kind === 'other-owner') {
          badToken = signSessionToken('100000000000000099', SECRET, now);
        } else if (kind === 'revoked') {
          expect(
            (
              await app.inject({
                method: 'POST',
                url: '/api/logout',
                headers: { authorization: `Bearer ${token}` },
              })
            ).statusCode,
          ).toBe(200);
          // O formato existente identifica sessões por segundo; criar outra no segundo seguinte.
          now += 1_000;
          const login = await app.inject({
            method: 'POST',
            url: '/api/session',
            payload: { token: 'synthetic-oauth-token' },
          });
          cookie = login.cookies.find((value) => value.name === 'vh_session')!.value;
          badToken = token;
        }
        for (const origin of [undefined, 'https://attacker.invalid']) {
          const rejected = await app.inject({
            method: 'POST',
            url: '/api/logout',
            headers: {
              authorization: `Bearer ${badToken}`,
              ...(origin === undefined ? {} : { origin }),
            },
            cookies: { vh_session: cookie },
          });
          expect(rejected.statusCode).toBe(403);
          expect(rejected.headers['set-cookie']).toBeUndefined();
          expect(
            (
              await app.inject({
                url: '/api/me',
                cookies: { vh_session: cookie },
              })
            ).statusCode,
          ).toBe(200);
        }
        const trusted = await app.inject({
          method: 'POST',
          url: '/api/logout',
          headers: { authorization: `Bearer ${badToken}`, origin: ORIGIN },
          cookies: { vh_session: cookie },
        });
        expect(trusted.statusCode).toBe(200);
        expect(
          (
            await app.inject({
              url: '/api/me',
              cookies: { vh_session: cookie },
            })
          ).statusCode,
        ).toBe(401);
      } finally {
        await app.close();
        db.close();
      }
    }
  });

  it('allows a valid owner Bearer without Origin or a cookie', async () => {
    const { app, db, token } = await fixture();
    try {
      expect(
        (
          await app.inject({
            method: 'POST',
            url: '/api/logout',
            headers: { authorization: `Bearer ${token}` },
          })
        ).statusCode,
      ).toBe(200);
      expect(
        (
          await app.inject({
            url: '/api/me',
            headers: { authorization: `Bearer ${token}` },
          })
        ).statusCode,
      ).toBe(401);
    } finally {
      await app.close();
      db.close();
    }
  });
});

describe('cookie lifetime and termination', () => {
  it('expires exactly at eight hours, including a retained cookie', async () => {
    const { app, db, cookie } = await fixture();
    try {
      now += 8 * 3600 * 1000 - 1;
      expect(
        (await app.inject({ url: '/api/me', cookies: { vh_session: cookie } })).statusCode,
      ).toBe(200);
      now += 1;
      expect(
        (await app.inject({ url: '/api/me', cookies: { vh_session: cookie } })).statusCode,
      ).toBe(401);
    } finally {
      await app.close();
      db.close();
    }
  });

  it('revokes the retained cookie and its matching Bearer on cookie logout', async () => {
    const { app, db, cookie, token } = await fixture();
    try {
      const logout = await app.inject({
        method: 'POST',
        url: '/api/logout',
        headers: { origin: ORIGIN },
        cookies: { vh_session: cookie },
      });
      expect(logout.statusCode).toBe(200);
      expect(
        (await app.inject({ url: '/api/me', cookies: { vh_session: cookie } })).statusCode,
      ).toBe(401);
      expect(
        (await app.inject({ url: '/api/me', headers: { authorization: `Bearer ${token}` } }))
          .statusCode,
      ).toBe(401);
    } finally {
      await app.close();
      db.close();
    }
  });

  it('rejects the historical signed plain-user-ID cookie', async () => {
    const { app, db } = await fixture();
    try {
      const historicalCookie = app.signCookie(USER);
      expect(
        (await app.inject({ url: '/api/me', cookies: { vh_session: historicalCookie } }))
          .statusCode,
      ).toBe(401);
    } finally {
      await app.close();
      db.close();
    }
  });
});

describe('cookie mutation origin boundary', () => {
  it('rejects wrong, absent and duplicate origins before changing flags', async () => {
    for (const origin of ['https://attacker.invalid', undefined, [ORIGIN, ORIGIN]]) {
      const { app, db, cookie } = await fixture();
      try {
        setSetting(db, GUILD, 'flag.antispam', 'true', now);
        const headers: Record<string, string | string[]> = {};
        if (origin !== undefined) headers.origin = origin;
        const result = await app.inject({
          method: 'PATCH',
          url: '/api/flags',
          headers,
          cookies: { vh_session: cookie },
          payload: { key: 'antispam', enabled: false },
        });
        expect(result.statusCode).toBe(403);
        expect(result.json()).toEqual({ error: 'csrf_origin_invalid' });
        expect(getSetting(db, GUILD, 'flag.antispam')).toBe('true');
      } finally {
        await app.close();
        db.close();
      }
    }
  });

  it('keeps same-origin cookies and valid Bearer clients usable', async () => {
    const { app, db, cookie, token } = await fixture();
    try {
      for (const headers of [
        { origin: ORIGIN },
        { authorization: `Bearer ${token}` },
        { authorization: `Bearer ${token}`, origin: 'https://attacker.invalid' },
      ]) {
        const result = await app.inject({
          method: 'PATCH',
          url: '/api/flags',
          headers,
          cookies: { vh_session: cookie },
          payload: { key: 'antispam', enabled: false },
        });
        expect(result.statusCode).toBe(200);
      }
      const invalidBearer = await app.inject({
        method: 'PATCH',
        url: '/api/flags',
        headers: { authorization: 'Bearer invalid', origin: 'https://attacker.invalid' },
        cookies: { vh_session: cookie },
        payload: { key: 'antispam', enabled: false },
      });
      expect(invalidBearer.statusCode).toBe(403);
      const unauthenticated = await app.inject({
        method: 'PATCH',
        url: '/api/flags',
        headers: { origin: ORIGIN },
        payload: { key: 'antispam', enabled: false },
      });
      expect(unauthenticated.statusCode).toBe(401);
    } finally {
      await app.close();
      db.close();
    }
  });
});

describe('legacy web configuration reset', () => {
  it('rejects simple text POSTs with wrong, absent or duplicate Origin without deleting data', async () => {
    for (const origin of ['https://attacker.invalid', undefined, [ORIGIN, ORIGIN]]) {
      const { app, db, cookie } = await fixture();
      try {
        setSetting(db, GUILD, 'web.quarantine', '{"enabled":true}', now);
        const headers: Record<string, string | string[]> = { 'content-type': 'text/plain' };
        if (origin !== undefined) headers.origin = origin;
        const result = await app.inject({
          method: 'POST',
          url: '/api/web-config/delete',
          headers,
          cookies: { vh_session: cookie },
          payload: 'ignored=simple-form-body',
        });
        expect(result.statusCode).toBe(403);
        expect(getSetting(db, GUILD, 'web.quarantine')).toBe('{"enabled":true}');
      } finally {
        await app.close();
        db.close();
      }
    }
  });

  it('allows an intentional same-origin cookie reset or explicit Bearer reset', async () => {
    const { app, db, cookie, token } = await fixture();
    try {
      for (const headers of [{ origin: ORIGIN }, { authorization: `Bearer ${token}` }]) {
        setSetting(db, GUILD, 'web.quarantine', '{"enabled":true}', now);
        const result = await app.inject({
          method: 'POST',
          url: '/api/web-config/delete',
          headers,
          cookies: { vh_session: cookie },
        });
        expect(result.statusCode).toBe(200);
        expect(getSetting(db, GUILD, 'web.quarantine')).toBeNull();
      }
    } finally {
      await app.close();
      db.close();
    }
  });
});
