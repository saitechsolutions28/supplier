require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const axios = require("axios");
const { Pool } = require("pg");

const app = express();

// 1. CORS Configuration (No credentials/cookies needed)
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:3000", "https://achudhaloans.in"],
  })
);

app.use(express.json());

// 2. In-Memory OTP Store (Replaces Express Sessions & Cookies completely)
const otpStore = new Map();

// Automatic cleanup every 15 minutes to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of otpStore.entries()) {
    if (value.expiresAt < now) {
      otpStore.delete(key);
    }
  }
}, 15 * 60 * 1000);

// 3. PostgreSQL Database Connection
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: false,
  },
});

// 4. SMS Provider Credentials & Templates
const SMS_CONFIG = {
  apiKey: "38ac76424a4e4d6ab6daf3d7e0c85d5a",
  senderId: "AHDAET",
  templateId: "1007990358521328635",
  link1: "Dear User Your Achudha Matrimony OTP is",
  link2: "Please use this OTP to verify your account on www.achudhamatrimony.in",
};

// Helper function to send SMS via Edumarc API
async function sendSmsNotification(cleanMobile, generatedOtp) {
  const smsMessage = `${SMS_CONFIG.link1} ${generatedOtp} ${SMS_CONFIG.link2}`;
  try {
    const postData = {
      number: [cleanMobile],
      message: smsMessage,
      senderId: SMS_CONFIG.senderId,
      templateId: SMS_CONFIG.templateId,
      serviceType: "otp",
    };

    const smsResponse = await axios.post(
      "https://smsapi.edumarcsms.com/api/v1/sendsms",
      postData,
      {
        headers: {
          "Content-Type": "application/json",
          apikey: SMS_CONFIG.apiKey,
        },
      }
    );

    console.log("[SMS API SUCCESS]:", smsResponse.data);
  } catch (smsErr) {
    console.error(
      "[SMS API ERROR]:",
      smsErr.response ? smsErr.response.data : smsErr.message
    );
    console.log(`[LOCAL DEBUG] Mobile: ${cleanMobile} | OTP: ${generatedOtp}`);
  }
}

// -------------------------------------------------------------
// Route 1: Registration - Send OTP & Store Temp Data in Memory
// -------------------------------------------------------------
app.post("/send-otp", async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const cleanMobile = mobile.replace(/\D/g, "");

    const checkUser = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR mobile=$2",
      [email, cleanMobile]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({
        message: "Email or mobile number already registered.",
      });
    }

    const saltRounds = 10;
    const hashPassword = await bcrypt.hash(password, saltRounds);
    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();

    // Trigger SMS
    await sendSmsNotification(cleanMobile, generatedOtp);

    // Save payload and OTP in memory map (Expires in 10 mins)
    otpStore.set(`reg_${cleanMobile}`, {
      otp: generatedOtp,
      tempUser: {
        name,
        email,
        mobile: cleanMobile,
        password: hashPassword,
      },
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    res.json({
      message: `OTP sent successfully to ${cleanMobile}`,
    });
  } catch (error) {
    console.error("Send OTP Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 2: Registration - Verify OTP & Insert User into DB
// -------------------------------------------------------------
app.post("/register", async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    if (!mobile || !otp) {
      return res.status(400).json({ message: "Mobile number and OTP are required" });
    }

    const cleanMobile = mobile.replace(/\D/g, "");
    const record = otpStore.get(`reg_${cleanMobile}`);

    if (!record) {
      return res.status(400).json({
        message: "OTP missing or requested mobile number mismatch. Please request a new OTP.",
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(`reg_${cleanMobile}`);
      return res.status(400).json({
        message: "OTP session expired. Please request a new OTP.",
      });
    }

    if (record.otp !== otp.toString().trim()) {
      return res.status(400).json({
        message: "Invalid OTP. Please try again.",
      });
    }

    // Insert user into DB
    const { name, email, password } = record.tempUser;
    await pool.query(
      `INSERT INTO users (name, email, mobile, password) VALUES ($1, $2, $3, $4)`,
      [name, email, cleanMobile, password]
    );

    // Clean memory record
    otpStore.delete(`reg_${cleanMobile}`);

    res.json({
      message: "Registration Successful!",
    });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 3: Standard Password Login API
// -------------------------------------------------------------
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = result.rows[0];
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
      return res.status(400).json({ message: "Wrong Password" });
    }

    res.json({
      message: "Login Successful",
      user: { id: user.id, name: user.name, email: user.email, mobile: user.mobile },
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 4: Live Check Mobile Registration
// -------------------------------------------------------------
app.post("/check-mobile", async (req, res) => {
  try {
    const { mobile } = req.body;
    if (!mobile) {
      return res.status(400).json({ isRegistered: false, message: "Mobile number required" });
    }

    const cleanMobile = mobile.replace(/\D/g, "");
    const result = await pool.query("SELECT id FROM users WHERE mobile=$1", [cleanMobile]);

    if (result.rows.length > 0) {
      return res.json({ isRegistered: true, message: "Mobile number registered" });
    } else {
      return res.json({ isRegistered: false, message: "Mobile number not registered" });
    }
  } catch (error) {
    console.error("Check Mobile Error:", error);
    res.status(500).json({ isRegistered: false, message: "Server Error checking mobile" });
  }
});

// -------------------------------------------------------------
// Route 5: Send OTP for Login
// -------------------------------------------------------------
app.post("/send-otp-login", async (req, res) => {
  try {
    const { mobile } = req.body;

    if (!mobile) {
      return res.status(400).json({ message: "Mobile number is required" });
    }

    const cleanMobile = mobile.replace(/\D/g, "");

    const result = await pool.query("SELECT id FROM users WHERE mobile=$1", [cleanMobile]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Mobile number is not registered." });
    }

    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();

    // Trigger SMS
    await sendSmsNotification(cleanMobile, generatedOtp);

    // Save OTP in memory map (Expires in 10 mins)
    otpStore.set(`login_${cleanMobile}`, {
      otp: generatedOtp,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    res.json({ message: `OTP sent successfully to ${cleanMobile}` });
  } catch (error) {
    console.error("Send Login OTP Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 6: Verify Login OTP
// -------------------------------------------------------------
app.post("/verify-otp-login", async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    if (!mobile || !otp) {
      return res.status(400).json({ message: "Mobile number and OTP are required" });
    }

    const cleanMobile = mobile.replace(/\D/g, "");
    const record = otpStore.get(`login_${cleanMobile}`);

    if (!record) {
      return res.status(400).json({
        message: "OTP session expired. Please request a new OTP.",
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(`login_${cleanMobile}`);
      return res.status(400).json({
        message: "OTP expired. Please request a new OTP.",
      });
    }

    if (record.otp !== otp.toString().trim()) {
      return res.status(400).json({
        message: "Invalid OTP. Please try again.",
      });
    }

    // Clean memory record
    otpStore.delete(`login_${cleanMobile}`);

    // Fetch user details for success response
    const userResult = await pool.query("SELECT id, name, email, mobile FROM users WHERE mobile=$1", [
      cleanMobile,
    ]);

    res.json({
      message: "Login Successful!",
      user: userResult.rows[0],
    });
  } catch (error) {
    console.error("Verify Login OTP Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 7: Clear Session API (Maintained for route compatibility)
// -------------------------------------------------------------
app.post("/clear-session", (req, res) => {
  res.json({ message: "Logged out successfully" });
});

// -------------------------------------------------------------
// Route 8: SMS Status Webhook Listener
// -------------------------------------------------------------
app.post("/combirds/sms-status", (req, res) => {
  const { message_id, status, statusDescription } = req.body;
  console.log(`[SMS WEBHOOK STATUS] ${message_id} -> ${status} (${statusDescription})`);
  res.status(200).send("OK");
});

app.listen(5000, () => {
  console.log("Server Running on port 5000");
});
