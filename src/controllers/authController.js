const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// DELETED: exports.register function is gone.

// 1. VERIFY OTP
// (Kept so employees can verify their email after Admin adds them)
exports.verifyEmail = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ success: false, message: 'User not found' });

    // Check the code
    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP code' });
    }

    // Success! Unlock the account
    await user.update({ isVerified: true, otp: null });

    res.status(200).json({ success: true, message: 'Account Verified! You can now log in.' });

  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// 2. LOGIN USER
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // A. Find user
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // B. Check Verified Status 
    if (!user.isVerified) {
        return res.status(403).json({ success: false, message: "Please verify your email first." });
    }

    // C. Check Active Status
    if (user.isActive === false) {
      return res.status(403).json({ success: false, message: "Account is disabled" });
    }

    // D. Compare Passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // E. Update Last Login
    await user.update({ lastLogin: new Date() });

    // F. Generate Token
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || 'secret_key_fallback',
      { expiresIn: '1d' }
    );

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        pharmacyName: user.pharmacyName
      }
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ success: false, message: 'Server Error', error: error.message });
  }
};

// 3. GET PROFILE
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'otp'] } 
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server Error' });
  }
};