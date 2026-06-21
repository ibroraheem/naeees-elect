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
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });
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

const verify = async (req, res) => {
  try {
    const { otp } = req.body;
    const token = req.headers.authorization.split(" ")[1];
    if (!token) return res.status(400).json({ message: "No token provided" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded.id });
    if (!user) return res.status(400).json({ message: "User does not exist" });
    if (user.otpExpires < Date.now())
      return res.status(400).json({ message: "OTP has expired" });
    if (user.otp !== otp)
      return res.status(400).json({ message: "Invalid OTP" });
    user.isVerified = true;
    user.status = "verified";
    await user.save();
    const newToken = jwt.sign(
      {
        id: user._id,
        matric: user.matric,
        voted: user.voted,
        department: user.department,
        level: user.level,
        isVerified: user.isVerified,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );
    res
      .status(200)
      .json({ message: "User verified successfully", token: newToken });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};

const resendOTP = async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    if (!token) return res.status(400).json({ message: "No token provided" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded.id });
    if (!user) return res.status(400).json({ message: "User does not exist" });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = Date.now() + 3600000;
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });
    const mailOptions = {
      from: process.env.EMAIL,
      to: user.email,
      subject: "Account Verification",
      html: `<h1>Hi ${user.firstName},</h1><p><strong>Your verification code is ${otp}</strong></p>
            <p>It expires in 1 hour</p>
            <p>Regards,</p>
            <p>NISEC 2023</p>`,
    };
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.log(err);
      } else {
        console.log(info);
        res.status(200).json({ message: "OTP sent successfully" });
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { matric } = req.body;
    const user = await User.findOne({ matric });
    if (!user) return res.status(400).json({ message: "User does not exist" });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = Date.now() + 3600000;
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    const transporter = nodemailer.createTransport({
      service: "gmail",
      secure: true,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });
    const mailOptions = {
      from: process.env.EMAIL,
      to: user.email,
      subject: "Password Reset",
      html: `<h1>Hi ${user.firstName},</h1><p><strong>Your password reset code is ${otp}</strong></p>
            <p>It expires in 1 hour</p>
            <p>Regards,</p>
            <p>NISEC 2023</p>`,
    };
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.log(err);
      } else {
        console.log(info);
      }
    });
    res.status(200).json({ message: "OTP sent successfully", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { otp, password } = req.body;
    const token = req.header.authorization.split(" ")[1];
    if (!token) return res.status(400).json({ message: "No token provided" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded.id });
    if (!user) return res.status(400).json({ message: "User does not exist" });
    if (user.otpExpires < Date.now())
      return res.status(400).json({ message: "OTP has expired" });
    if (user.otp !== otp)
      return res.status(400).json({ message: "Invalid OTP" });
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    user.password = hashedPassword;
    await user.save();
    res.status(200).json({ message: "Password reset successfully" });
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
      res.status(400).json({
        message: "Some students were not found",
        failedUpdates,
      });
    } else {
      res.status(200).json({ message: "All students updated successfully" });
    }
  } catch (err) {
    res
      .status(500)
      .json({ message: "Internal server error", error: err.message });
  }
};

const registerA = async (req, res) => {
  try {
    const {
      firstName,
      email,
      surname,
      matric,
      password,
      level,
      department,
      status,
      otp,
      otpExpires,
      isAccredited,
      isVerified,
    } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = await User.findOne({ matric });
    if (user) return res.status(400).json({ message: "User already exists" });
    const newUser = new User({
      firstName,
      surname,
      matric,
      password: hashedPassword,
      level,
      email,
      department,
      otp,
      otpExpires,
      isAccredited,
      isVerified,
      status,
    });
    await newUser.save();
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
    res.status(200).json({ message: "User registered successfully", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};

const checkABE = async (req, res) => {
  try {
    let student = await User.find({ level: "500", department: "ABE" });
    if (!student) return res.status(404).json({ message: "No student found" });
    res.status(200).json({ student });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  register,
  login,
  verify,
  resendOTP,
  forgotPassword,
  resetPassword,
  update,
  registerA,
  checkABE,
};
