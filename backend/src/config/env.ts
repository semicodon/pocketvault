import dotenv from 'dotenv';
import path from 'node:path';
import { z } from 'zod';

dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

const envSchema = z.object({

  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(4000),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  FRONTEND_URL: z.string().url('FRONTEND_URL must be a valid URL'),
  ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'ENCRYPTION_KEY must be a 64-character hex string (32 bytes)'),
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ FAIL-FAST SECURITY ERROR: Invalid .env configuration:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
