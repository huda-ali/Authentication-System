import { check } from 'express-validator';

export const registerValidator = [
  check('name').notEmpty().withMessage('Name is required'),
  check('email').isEmail().withMessage('Enter a valid email'),
  check('password').notEmpty().withMessage('Password is required')
];
