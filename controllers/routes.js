import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../model/userModel.js";
import OTP from "../model/otp.js";
import { generateOTP } from "../utils/otpGene.js";
import session from "express-session";

const { sign } = jwt;
const router = express.Router();

// Use for dashboard
router.get("/deshboard", (req, res) => {
  res.render("deshboard");
});

// GET - Register Page
router.get("/register", (req, res) => {
  res.render("register");
});

/**
 * POST - Register User
 */
router.post("/register", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  if (!password || password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters long" });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });
    await user.save();

    // res.status(201).json({ message: "User registered successfully" });
    res.redirect("/api/deshboard");
  } catch (err) {
    res
      .status(500)
      .json({ message: "Registration failed", error: err.message });
  }
});

/**
 * GET - Login Page
 */
router.get("/login", (req, res) => {
  res.render("home");
});

/**
 * POST - Login User
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // res.status(200).json({ message: "Login successful", token });
    res.redirect("/api/deshboard");
  } catch (err) {
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

/// get verify
// router.get("/otp-request", (req, res) => {
//   res.render("forgot");
// });

/// get sign in with otp
router.get("/sign-with-otp", (req, res) => {
  res.render("SignOtp");
});

// get forgot with otp
router.get("/forgot-with-otp", (req, res) => {
  res.render("forgotOtp");
});

/// POST - Request OTP
router.post("/otp-request", async (req, res) => {
  const { email, context } = req.body;
  const code = generateOTP();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // valid for 5 minutes
  req.session.email = req.body.email;
  req.session.context = req.body.context;
  try {
    await OTP.deleteMany({ email, context });
    const otp = new OTP({ email, code, context, expiresAt });
    await otp.save();

    console.log(`OTP for ${email}: ${code} ${context}`);
    res.status(200).redirect("/api/otp-verify");
    // res.status(200).json({ message: "OTP sent" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "OTP generation failed", error: err.message });
  }
});

// get otp verify

router.get("/otp-verify", (req, res) => {
  res.render("otpVer");
});

// POST - Verify OTP and handle context

router.post("/otp-verify", async (req, res) => {
  const email = req.session.email;
  const context = req.session.context;
  const { code } = req.body;

  console.log("Verifying OTP:", { email, code, context });
  try {
    const entry = await OTP.findOne({ email, code, context });
    if (!entry) {
      console.log("No OTP db entry for:", { email, code, context });
      return res.status(400).json({ message: "OTP invalid or expired" });
    }

    if (entry.expiresAt < new Date()) {
      console.log("OTP expired:", entry);
      return res.status(400).json({ message: "OTP expired" });
    }

    await OTP.deleteMany({ email });

    const user = await User.findOne({ email });

    // Registration
    if (context === "register") {
      if (user)
        return res.status(400).json({ message: "Email already registered" });
      return res.status(200).json({ message: "OTP verified for registration" });
    }

    if (!user) return res.status(404).json({ message: "User not found" });

    // Login or Forgot flow
    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    if (context === "login") {
      return res.redirect("/api/deshboard");
    }

    if (context === "forgot") {
      return (
        res
          // .status(200)
          // .json({ message: "OTP verified. Proceed to reset password.", token });
          .redirect("/api/reset-password")
      );
    }

    res.status(400).json({ message: "Unknown OTP context" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "OTP verification failed", error: err.message });
  }
});

/**
 * POST - Reset Password
 */

router.get("/reset-password", async (req, res) => {
  res.render("resetPassword", { success: false });
});

// Post - Reset Password
router.post("/reset-password", async (req, res) => {
  const { password } = req.body;
  const email = req.session.email;
  try {
    const hashedPass = await bcrypt.hash(password, 10);
    const result = await User.updateOne(
      { email },
      { $set: { password: hashedPass } }
    );

    if (result.modifiedCount === 0)
      return res
        .status(404)
        .json({ message: "User not found or password unchanged" });

    // res.status(200).json({ message: "Password reset successful" });
    res.redirect("/api/login");
  } catch (err) {
    res
      .status(500)
      .json({ message: "Password reset failed", error: err.message });
  }
});

export default router;
