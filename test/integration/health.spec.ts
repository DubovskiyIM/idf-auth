import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import express from 'express';
import { createTestDb, destroyTestDb, TestDB } from '../setup.js';
import { createHealthRouter } from '../../src/health/routes.js';

describe('health', () => {
  let handle: TestDB;
  let app: express.Express;

  beforeAll(async () => {
    handle = await createTestDb();
    app = express();
    app.use(createHealthRouter({ pool: handle.pool }));
  });

  afterAll(async () => {
    // Третий тест мог уже закрыть pool — destroyTestDb делает pool.end() повторно,
    // что бросает "Called end on pool more than once". Оборачиваем в try/catch.
    try {
      await destroyTestDb(handle);
    } catch {
      // pool уже закрыт — останавливаем только контейнер.
      try {
        await handle.container.stop();
      } catch {
        // контейнер уже остановлен
      }
    }
  });

  it('GET /health returns 200 always', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('GET /ready returns 200 when DB reachable', async () => {
    const res = await request(app).get('/ready');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ready' });
  });

  it('GET /ready returns 503 when DB unreachable', async () => {
    await handle.pool.end();
    const res = await request(app).get('/ready');
    expect(res.status).toBe(503);
  });
});
