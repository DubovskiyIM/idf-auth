import type { ErrorRequestHandler } from 'express';
import { logger } from '../logger.js';

export const errorMiddleware: ErrorRequestHandler = (err, req, res, _next) => {
  logger.error({ err, path: req.path, method: req.method }, 'unhandled error');
  if (res.headersSent) return;
  res.status(500).json({ error: 'internal' });
};
