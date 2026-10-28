import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

// Token de sessão assinado (HMAC-SHA256), enviado no header `Authorization: Bearer`.
// Usa-se em vez de cookie de terceiros porque o painel (github.io) e a API (túnel)
// são cross-site — e navegadores como o Brave/Safari bloqueiam cookies de terceiros.
// Formato: `<userId>.<expEpochSec>.<assinatura base64url>`.

/** Cria um token assinado válido por `ttlSec` a partir de `now` (ms). */
export function signSessionToken(
  userId: string,
  secret: string,
  now: number,
  ttlSec = 8 * 3600,
): string {
  const exp = Math.floor(now / 1000) + ttlSec;
  const payload = `${userId}.${exp}`;
  const sig = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

export interface SessionTokenClaims {
  userId: string;
  expiresAt: number;
}

export function verifySessionTokenClaims(
  token: string,
  secret: string,
  now: number,
): SessionTokenClaims | null {
  const parts = (token ?? '').split('.');
  if (parts.length !== 3) return null;
  const [userId, expStr, sig] = parts;

  const payload = `${userId}.${expStr}`;
  const expected = createHmac('sha256', secret).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

  const exp = Number.parseInt(expStr, 10);
  const expiresAt = exp * 1000;
  if (!Number.isFinite(exp) || expiresAt <= now) return null;
  return { userId, expiresAt };
}

/** Devolve o `userId` se o token for válido e não expirou; senão `null`. */
export function verifySessionToken(token: string, secret: string, now: number): string | null {
  return verifySessionTokenClaims(token, secret, now)?.userId ?? null;
}

/** Digest para indexar sessões revogadas sem reter o token original. */
export function sessionTokenDigest(token: string): string {
  return createHash('sha256').update(token).digest('base64url');
}
