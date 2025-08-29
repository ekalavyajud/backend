import express from "express";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Supabase init
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE);

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

//  Auto Schema Migration (Users Table)
async function createSchema() {
  const { error } = await supabase.rpc("exec", {
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        user_type TEXT DEFAULT 'intern',
        council_id TEXT,
        otp TEXT,
        otp_verified BOOLEAN DEFAULT false,
        email_verified BOOLEAN DEFAULT false,
        approved_by_admin BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT now(),
        last_login_at TIMESTAMP,
        login_records JSONB DEFAULT '[]'::jsonb,
        -- personal details
        dob DATE,
        address TEXT,
        gender TEXT,
        nationality TEXT,
        -- sensitive details
        aadhaar TEXT,
        passport TEXT,
        pan_card TEXT
      );
    `,
  });
  if (error) console.error("Schema creation error:", error.message);
}
createSchema();

//  Send Email Helper
async function sendEmail(to, subject, html) {
  await transporter.sendMail({
    from: `"EKALAVYA" <${process.env.GMAIL_USER}>`,
    to,
    subject,
    html,
  });
}

//  Register (OTP sent to email)
app.post("/register", async (req, res) => {
  const { name, email, phone, council_id, user_type, dob, address, gender, nationality, aadhaar, passport, pan_card } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  const { data, error } = await supabase
    .from("users")
    .insert([{ name, email, phone, council_id, user_type, otp, dob, address, gender, nationality, aadhaar, passport, pan_card }]);

  if (error) return res.status(400).json({ error: error.message });

  await sendEmail(
    email,
    "Verify Your Registration",
    `
      <h2>Welcome ${name} 🎉</h2>
      <p>Thank you for registering at our platform. Please verify your email with the OTP below:</p>
      <h3 style="color:#4CAF50;">${otp}</h3>
      <p>Next Steps:</p>
      <ul>
        <li>Verify your email using the OTP above ✅</li>
        <li>Wait for admin approval before logging in 🔑</li>
        <li>Once approved, you can log in and manage your profile ✏️</li>
      </ul><br/>
      <p>@2025 all rights reserved by eLan Technology</p>
    `
  );

  res.json({ message: "Registered successfully. OTP sent to email." });
});

//  Verify OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const { data, error } = await supabase.from("users").select("*").eq("email", email).eq("otp", otp).single();
  if (error || !data) return res.status(400).json({ error: "Invalid OTP" });

  await supabase.from("users").update({ otp_verified: true, email_verified: true }).eq("email", email);
  res.json({ message: "Email verified successfully." });
});

//  Login
app.post("/login", async (req, res) => {
  const { email } = req.body;
  const { data: user, error } = await supabase.from("users").select("*").eq("email", email).single();

  if (error || !user) return res.status(400).json({ error: "User not found" });
  if (!user.email_verified) return res.status(403).json({ error: "Email not verified" });
  if (!user.approved_by_admin) return res.status(403).json({ error: "Not approved by admin" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await supabase.from("users").update({ otp }).eq("email", email);

  await sendEmail(
    email,
    "Login OTP",
    `
      <h2>Hello ${user.name} 👋</h2>
      <p>Your login OTP is:</p>
      <h3 style="color:#FF5722;">${otp}</h3>
      <p>This OTP will expire in 5 minutes.</p>
      <p>Do not share with anyone</p><br/>
      <p>@2025 all rights reserved by eLan Technology</p>

    `
  );

  res.json({ message: "OTP sent for login." });
});

//  Verify Login OTP
app.post("/verify-login", async (req, res) => {
  const { email, otp } = req.body;
  const { data: user, error } = await supabase.from("users").select("*").eq("email", email).eq("otp", otp).single();

  if (error || !user) return res.status(400).json({ error: "Invalid OTP" });

  const token = jwt.sign({ id: user.id, email: user.email, user_type: user.user_type }, process.env.JWT_SECRET, { expiresIn: "1h" });

  await supabase.from("users").update({
    last_login_at: new Date(),
    login_records: [...user.login_records, { action: "login", time: new Date() }]
  }).eq("email", email);

  await sendEmail(
    email,
    "Login Successful",
    `
      <h2>Welcome Back, ${user.name} 🎉</h2>
      <p>You have successfully logged in at ${new Date().toLocaleString()}.</p><br/>
      <p>@2025 all rights reserved by eLan Technology</p>
    `
  );

  res.json({ id: user.id, name: user.name, email: user.email, user_type: user.user_type, token });
});

//  Logout
app.post("/logout", async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase.from("users").select("*").eq("email", email).single();
  if (!user) return res.status(400).json({ error: "User not found" });

  await supabase.from("users").update({
    login_records: [...user.login_records, { action: "logout", time: new Date() }]
  }).eq("email", email);

  await sendEmail(
    email,
    "Logout Notification",
    `
      <h2>Goodbye, ${user.name} 👋</h2>
      <p>You logged out at ${new Date().toLocaleString()}.</p>
      <p>See you soon!</p><br/>
      <p>@2025 all rights reserved by eLan Technology</p>
    `
  );

  res.json({ message: "Logged out successfully." });
});


//  Get All Users
app.get("/users", async (req, res) => {
  try {
    const { data, error } = await supabase.from("users").select("*");

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ users: data });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

//resend otp for registration
// Resend OTP for Registration
app.post("/resend-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: "Email is required" });

  const { data: user, error: fetchError } = await supabase
    .from("users")
    .select("name, otp_verified")
    .eq("email", email)
    .single();

  if (fetchError || !user) {
    return res.status(404).json({ error: "User with this email not found" });
  }

  if (user.otp_verified) {
    return res.status(400).json({ error: "Email already verified" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  const { error: updateError } = await supabase
    .from("users")
    .update({ otp })
    .eq("email", email);

  if (updateError) {
    return res.status(500).json({ error: "Failed to update OTP" });
  }

  try {
    await sendEmail(
      email,
      "Resend OTP - Email Verification",
      `
        <h2>Hello ${user.name} 👋</h2>
        <p>Your new OTP for email verification is:</p>
        <h3 style="color:#2196F3;">${otp}</h3>
        <p>This OTP will expire soon. Use it to verify your registration.</p><br/>
        <p>@2025 all rights reserved by eLan Technology</p>
      `
    );

    return res.json({ message: "OTP resent successfully" });
  } catch (err) {
    return res.status(500).json({ error: "Failed to send OTP email" });
  }
});


app.get("/", (req, res) => {
  res.send("Ekalavya backend is running");
});

// Server
app.listen(5000, () => console.log(" Server running on http://localhost:5000"));
