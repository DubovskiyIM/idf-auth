import { loadEnv } from './env.js';
import { createServer } from './http/server.js';
import { logger } from './logger.js';

const env = loadEnv();
const { app } = await createServer(env);

app.listen(env.PORT, () => {
  logger.info({ port: env.PORT, env: env.NODE_ENV }, 'auth plane started');
});
