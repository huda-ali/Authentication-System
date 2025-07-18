import express from 'express';
import authController from '../controllers/authcontroller.js';
import authMiddleware from '../middlewares/auth.js';
import { loginValidator } from '../validators/loginValidator.js';
import { limit } from '../middlewares/ratelimit.js';
import { registerValidator } from '../validators/registerValidator.js';

const router = express.Router();

router.post('/register', limit, registerValidator, authController.register);
router.post('/login', limit, loginValidator, authController.login);
router.get('/profile', authMiddleware, authController.profile);
router.post('/refresh', limit, authController.refresh);
router.get('/admin', authMiddleware, authController.admin);
export default router;
