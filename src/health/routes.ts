import { Router } from 'express';
import type pg from 'pg';

export function createHealthRouter(deps: { pool: pg.Pool }): Router {
  const router = Router();

  router.get('/health', (_req, res) => res.json({ status: 'ok' }));

  router.get('/ready', async (_req, res) => {
    try {
      await deps.pool.query('SELECT 1');
      res.json({ status: 'ready' });
    } catch {
      res.status(503).json({ status: 'unready' });
    }
  });

  return router;
}
