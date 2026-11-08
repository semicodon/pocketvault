import rateLimit from 'express-rate-limit'

const MAX_AUTH_MINS = 15
const MAX_STRICT_MINS = 15
const MAX_AUTH_LIMITER = 100
const MAX_STRICT_LIMITER = 5

// Tier 1: General API shield (100 requests ('max') per 15 minutes per IP ('windowMs'))
export const apiLimiter = rateLimit({
  windowMs: MAX_AUTH_MINS * 60 * 1000, // 15 minutes
  max: MAX_AUTH_LIMITER, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests from this IP. Please try again in 15 minutes.',
  },
})

// Tier 2: Strict security bunker for Auth & Step-Up Decryption (5 attempts per 15 minutes)
export const strictSecurityLimiter = rateLimit({
  windowMs: MAX_STRICT_MINS * 60 * 1000, // 15 minutes
  max: MAX_STRICT_LIMITER, // limit each IP to 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many security verification attempts. Temporarily locked for 15 minutes.',
  },
})