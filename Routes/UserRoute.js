import express from "express";
import bcrypt from "bcrypt";
import { User } from "../Models/User.js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import cookieParser from "cookie-parser"; // Add cookie-parser

dotenv.config();

const router = express.Router();

// Use cookie-parser middleware
router.use(cookieParser());

// Route to handle user signup
router.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to handle user login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: "User is not registered" });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.json({ message: "Password is incorrect" });
    }
    const token = jwt.sign({ username: user.username }, process.env.KEY, {
      expiresIn: "1h",
    });
    res.cookie("token", token, { httpOnly: true, maxAge: 3600000 }); // Corrected maxAge to 1 hour
    return res.json({ status: true, message: "login successful" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to handle forgot password
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: "User not registered" });
    }

    const token = jwt.sign({ id: user._id }, process.env.KEY, {
      expiresIn: "5m",
    });

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Reset Password",
      text: `http://localhost:5173/resetPassword/${token}`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.error("Error sending email:", error);
        return res.json({ message: "Error sending email" });
      } else {
        return res.json({ status: true, message: "Email sent" });
      }
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to handle reset password
router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params; // Correctly extract the token
  const { password } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.KEY);
    const id = decoded.id;
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate({ _id: id }, { password: hashedPassword });
    return res.json({ status: true, message: "Password updated successfully" });
  } catch (err) {
    console.log("Error during password reset:", err); // Log error
    return res.json({ status: false, message: "Invalid or expired token" });
  }
});

// Middleware to verify user
const verifyUser = async (req, res, next) => {
  try {
    console.log("Cookies:", req.cookies); // Log cookies
    const token = req.cookies.token;
    if (!token) {
      return res.json({ status: false, message: "No token" });
    }
    const decode = await jwt.verify(token, process.env.KEY);
    console.log("Decoded token:", decode); // Log decoded token
    req.user = decode; // Attach decoded token to request object
    next();
  } catch (err) {
    console.log("Verification error:", err); // Log error
    return res.json({ status: false, message: "Invalid or expired token" });
  }
};

// Route to verify user
router.get("/verify", verifyUser, (req, res) => {
  return res.json({ status: true, message: "Authorized" });
});

// Route to handle user logout
router.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ status: true });
});

export { router as userRouter };
