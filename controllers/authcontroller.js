import User from '../models/user.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { validationResult } from 'express-validator';
import { StatusCodes } from 'http-status-codes';

const register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(StatusCodes.BAD_REQUEST).json({ errors: errors.array() });

  const { name, email, password } = req.body;
  const userExists = await User.findOne({ email });
  if (userExists) return res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Email already in use' });

  const hashedPassword = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashedPassword });

  res.status(StatusCodes.CREATED).json({ msg: 'User registered' });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Invalid credentials' });

  const isMatch = bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(StatusCodes.UNAUTHORIZED).json({ msg: 'Invalid credentials' });

  const accessToken = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  const refreshToken = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie('refreshToken', refreshToken, { httpOnly: true, expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) });
  res.status(StatusCodes.OK).json({ accessToken });
};

const refresh = async (req, res) => {
  const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
    const [key, value] = cookie.trim().split('=');
    acc[key] = value;
    return acc;
  }, {});
  const refreshToken = cookies.refreshToken;
  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const newAccessToken = jwt.sign(
      { id: decoded.id, role: decoded.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    const newRefreshToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );
    res.cookie('refreshToken', newRefreshToken, { httpOnly: true, expiresIn: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) });
    res.status(StatusCodes.OK).json({ accessToken: newAccessToken });
  } catch {
    res.status(StatusCodes.UNAUTHORIZED).json({ msg: 'Invalid refresh token' });
  }
};

const profile = async (req, res) => {
  res.status(StatusCodes.OK).json({ msg: 'User profile', user: req.user });
};

const admin = async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(StatusCodes.FORBIDDEN).json({ msg: 'Access denied' });
  }
  res.status(StatusCodes.OK).json({ msg: 'Welcome, Admin' });
};

export default { register, login, profile, refresh, admin };
