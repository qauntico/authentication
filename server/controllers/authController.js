import jwt from 'jsonwebtoken';
import User from "../models/user.js"
import config from "../config/config.js"

const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, config.jwtAccessSecret, {
    expiresIn: config.accessTokenExpiry,
  });
  
  const refreshToken = jwt.sign({ userId }, config.jwtRefreshSecret, {
    expiresIn: config.refreshTokenExpiry,
  });
  
  return { accessToken, refreshToken };
};

const authController = {
  register: async (req, res) => {
    try {
      const { email, password } = req.body;
      
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered' });
      }
      
      const user = new User({ email, password });
      await user.save();
      
      const { accessToken, refreshToken } = generateTokens(user._id);
      user.refreshToken = refreshToken;
      await user.save();
      
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: config.cookieMaxAge,
      });
      
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: config.cookieMaxAge,
      });
      
      res.json({ message: 'Registration successful' });
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  },
  
  login: async (req, res) => {
    try {
      const { email, password } = req.body;
      
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      const { accessToken, refreshToken } = generateTokens(user._id);
      user.refreshToken = refreshToken;
      await user.save();
      
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: config.cookieMaxAge,
      });
      
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: config.cookieMaxAge,
      });
      
      res.json({ message: 'Login successful' });
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  },
  
  refresh: async (req, res) => {
    try {
      const refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token not found' });
      }
      
      const decoded = jwt.verify(refreshToken, config.jwtRefreshSecret);
      const user = await User.findById(decoded.userId);
      
      if (!user || user.refreshToken !== refreshToken) {
        return res.status(401).json({ message: 'Invalid refresh token' });
      }
      
      const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);
      user.refreshToken = newRefreshToken;
      await user.save();
      
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: config.cookieMaxAge,
      });
      
      res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: config.cookieMaxAge,
      });
      
      res.json({ message: 'Token refresh successful' });
    } catch (error) {
      res.status(401).json({ message: 'Invalid refresh token' });
    }
  },
  
  logout: async (req, res) => {
    try {
      const refreshToken = req.cookies.refreshToken;
      
      if (refreshToken) {
        const user = await User.findOne({ refreshToken });
        if (user) {
          user.refreshToken = null;
          await user.save();
        }
      }
      
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      res.json({ message: 'Logout successful' });
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  },
};


export default authController;
