import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { env } from './config/env.js';
import { apiLimiter } from './middleware/rateLimiter.js';
import { authRouter } from './routes/auth.routes.js';
import { secretsRouter } from './routes/secrets.routes.js';

const app = express();

// 1. Strip server fingerprinting & enforce Helmet HTTP security headers
app.disable('x-powered-by');
app.use(helmet());

// 2. Strict Origin CORS (Never use '*' when credentials: true is enabled)
app.use(
  cors({
    origin: env.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// 3. 10kb JSON Body Cap (Anti-DoS) & Cookie Parser (for HttpOnly Refresh Cookie)
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// 4. Global Rate Limiting Shield
app.use('/api', apiLimiter);

// 5. Health Check Endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'pocketvault-api' });
});

// 6. Mount Security Routers
app.use('/api/auth', authRouter);
app.use('/api/secrets', secretsRouter);

// 7. Sanitized Global Error Handler (Prevents Stack Trace Leakage)
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('❌ Unhandled Server Error:', err.message);
  res.status(500).json({
    error: 'Internal server error',
    ...(env.NODE_ENV === 'development' && { debug: err.message }),
  });
});

app.listen(env.PORT, '127.0.0.1', () => {
  console.log(`🔒 PocketVault Hardened API listening on http://127.0.0.1:${env.PORT}`);
});