const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

// Route: /api/auth/register
//router.post('/register', authController.register);

// Route: /api/auth/login  
router.post('/login', authController.login);

router.post('/verify-email', authController.verifyEmail);

router.get('/profile', authMiddleware, authController.getProfile);

module.exports = router;