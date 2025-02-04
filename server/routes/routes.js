import express from "express";
const router = express.Router();
import authController from '../controllers/authController.js';
import verifyToken from '../middleware/auth.js';

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh', authController.refresh);
router.post('/logout', verifyToken, authController.logout);

export default router;