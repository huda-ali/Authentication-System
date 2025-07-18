import express from 'express';
import authController from '../controllers/authcontroller.js';
import authMiddleware from '../middlewares/auth.js';
import { loginValidator } from '../validators/loginValidator.js';
import { limit } from '../middlewares/ratelimit.js';

const router = express.Router();

router.post('/register', limit, authController.register);
router.post('/login', limit, loginValidator, authController.login);
router.get('/profile', authMiddleware, authController.profile);

export default router;
