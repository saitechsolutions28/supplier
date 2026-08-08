require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("express-session");
const axios = require("axios");
const { Pool } = require("pg");

const app = express();

// 1. CORS Configuration
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:3000", "https://achudhaloans.in"], // Added port 3000 as fallback
    credentials: true,
  })
);

app.use(express.json());

// 2. Express Session Configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || "achudha_matrimony_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set to true for HTTPS in production
      httpOnly: true,
      maxAge: 10 * 60 * 1000, // Session expires in 10 minutes
    },
  })
);

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
// Route 1: Registration - Send OTP & Store Temp Data in Session
// -------------------------------------------------------------
app.post("/send-otp", async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const checkUser = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR mobile=$2",
      [email, mobile]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({
        message: "Email or mobile number already registered.",
      });
    }

    const saltRounds = 10;
    const hashPassword = await bcrypt.hash(password, saltRounds);

    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const cleanMobile = mobile.replace(/\D/g, "");

    await sendSmsNotification(cleanMobile, generatedOtp);

    req.session.tempUser = {
      name,
      email,
      mobile: cleanMobile,
      password: hashPassword,
    };
    req.session.otp = generatedOtp;

    req.session.save((err) => {
      if (err) {
        console.error("Session Save Error:", err);
        return res.status(500).json({ message: "Failed to initialize session." });
      }

      res.json({
       // message: `OTP sent successfully to ${cleanMobile}`,
      });
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
    const { otp } = req.body;

    if (!req.session.otp || !req.session.tempUser) {
      return res.status(400).json({
        message: "OTP session expired or missing. Please request a new OTP.",
      });
    }

    if (req.session.otp !== otp) {
      return res.status(400).json({
        message: "Invalid OTP. Please try again.",
      });
    }

    const { name, email, mobile, password } = req.session.tempUser;

    await pool.query(
      `INSERT INTO users (name, email, mobile, password) VALUES ($1, $2, $3, $4)`,
      [name, email, mobile, password]
    );

    req.session.isAuthenticated = true;
    delete req.session.otp;
    delete req.session.tempUser;

    req.session.save((err) => {
      if (err) console.error("Session Clear Error:", err);

      res.json({
        message: "Registration Successful!",
      });
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

    const result = await pool.query("SELECT * FROM users WHERE email=$1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = result.rows[0];

    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
      return res.status(400).json({ message: "Wrong Password" });
    }

    req.session.isAuthenticated = true;

    res.json({ message: "Login Successful" });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// NEW Route 4: Check if Mobile Number is Registered (Live Check)
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
// NEW Route 5: Send OTP for Login
// -------------------------------------------------------------
app.post("/send-otp-login", async (req, res) => {
  try {
    const { mobile } = req.body;

    if (!mobile) {
      return res.status(400).json({ message: "Mobile number is required" });
    }

    const cleanMobile = mobile.replace(/\D/g, "");

    // Double check registration status
    const result = await pool.query("SELECT * FROM users WHERE mobile=$1", [cleanMobile]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Mobile number is not registered." });
    }

    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();

    // Trigger SMS API
    await sendSmsNotification(cleanMobile, generatedOtp);

    // Save session variables for login OTP
    req.session.loginOtp = generatedOtp;
    req.session.loginMobile = cleanMobile;

    req.session.save((err) => {
      if (err) {
        console.error("Session Save Error:", err);
        return res.status(500).json({ message: "Failed to initialize session." });
      }

      res.json({ message: `OTP sent successfully to ${cleanMobile}` });
    });
  } catch (error) {
    console.error("Send Login OTP Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// NEW Route 6: Verify Login OTP
// -------------------------------------------------------------
app.post("/verify-otp-login", async (req, res) => {
  try {
    const { otp } = req.body;

    if (!req.session.loginOtp) {
      return res.status(400).json({
        message: "OTP session expired. Please request a new OTP.",
      });
    }

    if (req.session.loginOtp !== otp) {
      return res.status(400).json({
        message: "Invalid OTP. Please try again.",
      });
    }

    // Login successful — authenticated status saved
    req.session.isAuthenticated = true;

    // Clear temp login OTP data from session
    delete req.session.loginOtp;
    delete req.session.loginMobile;

    req.session.save((err) => {
      if (err) console.error("Session Clear Error:", err);

      res.json({ message: "Login Successful!" });
    });
  } catch (error) {
    console.error("Verify Login OTP Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 7: Clear/Destroy Session API
// -------------------------------------------------------------
app.post("/clear-session", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Failed to destroy session" });
    }
    res.clearCookie("connect.sid");
    res.json({ message: "Session destroyed successfully" });
  });
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
