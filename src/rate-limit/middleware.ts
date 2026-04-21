import { RateLimiterPostgres } from 'rate-limiter-flexible';
import type pg from 'pg';
import type { Request, Response, NextFunction } from 'express';
import { logger } from '../logger.js';

// cb нужен чтобы RateLimiterPostgres не делал `throw err` в Promise.catch
// при неудаче CREATE TABLE (bad DB URL, DNS flap) — иначе unhandled rejection крашит процесс.
function onInit(err?: Error) {
  if (err) logger.error({ err }, 'rate-limit init failed');
}

export function createMagicLinkLimiter(pool: pg.Pool) {
  return new RateLimiterPostgres({
    storeClient: pool,
    tableName: 'rate_limit_log',
    keyPrefix: 'magic',
    points: 5,
    duration: 3600,
  }, onInit);
}

export function createInviteLimiter(pool: pg.Pool) {
  return new RateLimiterPostgres({
    storeClient: pool,
    tableName: 'rate_limit_log',
    keyPrefix: 'invite',
    points: 100,
    duration: 3600,
  }, onInit);
}

export function limitByEmail(limiter: RateLimiterPostgres) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const email = String(req.body?.email ?? '').toLowerCase();
    if (!email) return next();
    try {
      await limiter.consume(email);
      next();
    } catch {
      res.status(429).json({ error: 'rate_limited' });
    }
  };
}

export function limitByIp(limiter: RateLimiterPostgres) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip ?? 'unknown';
    try {
      await limiter.consume(key);
      next();
    } catch {
      res.status(429).json({ error: 'rate_limited' });
    }
  };
}
