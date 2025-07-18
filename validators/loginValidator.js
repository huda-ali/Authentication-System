import { check } from 'express-validator';

export const loginValidator = [
  check('email').isEmail().withMessage('Enter a valid email'),
  check('password').notEmpty().withMessage('Password is required')
];
