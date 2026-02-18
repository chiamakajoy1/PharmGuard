const User = require('../models/user');
const bcrypt = require('bcryptjs');

// 1. ADD EMPLOYEE (Admin Only)
exports.addEmployee = async (req, res) => {
  try {
    const { username, email, password, role, pharmacyName } = req.body;

    // A. Validate Role (Must be 'pharmacist' or 'storekeeper')
    if (role === 'admin') {
      return res.status(400).json({ message: 'Admins cannot create other Admins here.' });
    }

    // B. Check if user exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // C. Hash Password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // D. Create the Employee (Automatically Verified because Admin created them)
    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      role: role, 
      pharmacyName: req.user.pharmacyName, // Assign to Admin's pharmacy
      isVerified: true, // Skip OTP! Admin trusts them.
      otp: null
    });

    res.status(201).json({
      success: true,
      message: `Employee (${role}) created successfully!`,
      user: { id: newUser.id, name: newUser.username, email: newUser.email }
    });

  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};