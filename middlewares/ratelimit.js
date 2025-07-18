import rateLimit from 'express-rate-limit';

export const limit = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: 'Too many requests. Try again later.'
});
