const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
require("dotenv").config();

const login = async (req, res) => {
  try {
    const { matric, password } = req.body;
    const user = await User.findOne({ matric: matric.toLowerCase() });
    if (!user) return res.status(400).json({ message: "User does not exist" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      {
        id: user._id,
        matric: user.matric,
        voted: user.voted,
        department: user.department,
        level: user.level,
        isVerified: user.isVerified,
        role: user.role,
        isAccredited: user.isAccredited,
      },
      process.env.JWT_SECRET,
    );

    res.status(200).json({ message: "Login Successful", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};

const update = async (req, res) => {
  try {
    const { matric } = req.body;

    async function updateStudentDetails(matric) {
      const formattedMatric = matric.toLowerCase();
      const user = await User.findOne({ matric: formattedMatric });

      if (!user) {
        return { matric: formattedMatric, status: "User does not exist" };
      }

      user.status = "verified";
      user.isAccredited = true;
      user.isVerified = true;
      await user.save();

      return { matric: formattedMatric, status: "Updated" };
    }

    const results = await Promise.all(matric.map(updateStudentDetails));
    const failedUpdates = results.filter(
      (result) => result.status === "User does not exist",
    );

    if (failedUpdates.length) {
      return res.status(400).json({
        message: "Some students were not found",
        failedUpdates,
      });
    }

    res.status(200).json({ message: "All students updated successfully" });
  } catch (err) {
    res.status(500).json({ message: "Internal server error", error: err.message });
  }
};

module.exports = { login, update };
