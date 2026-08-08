require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("express-session");
const axios = require("axios");
const { Pool } = require("pg");

const app = express();

const isProduction = process.env.NODE_ENV === "production" || process.env.RENDER === "true";

// 1. Crucial for Render / Reverse Proxies (enables secure cookies over HTTPS)
if (isProduction) {
  app.set("trust proxy", 1);
}

// 2. CORS Configuration for Localhost & Production
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://achudhaloans.in",
  "https://www.achudhaloans.in",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (e.g. Postman, mobile apps)
      if (!origin) return callback(null, true);
      
      if (allowedOrigins.indexOf(origin) !== -1 || !isProduction) {
        return callback(null, true);
      } else {
        return callback(null, true); // Fallback to allow requests with credentials
      }
    },
    credentials: true, // Enables passing express-session cookie
  })
);

app.use(express.json());

// 3. Express Session Configuration (Fixed for Cross-Domain Cookies)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "achudha_matrimony_secret_key_123",
    resave: false,
    saveUninitialized: false, // Don't create empty session objects
    cookie: {
      secure: isProduction, // 'true' on Render (HTTPS), 'false' on localhost
      sameSite: isProduction ? "none" : "lax", // 'none' allows cookies across achudhaloans.in and onrender.com
      httpOnly: true,
      maxAge: 10 * 60 * 1000, // 10 minutes session duration
    },
  })
);

// 4. PostgreSQL Database Connection
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});

// 5. SMS Provider Configuration
const SMS_CONFIG = {
  apiKey: "38ac76424a4e4d6ab6daf3d7e0c85d5a",
  senderId: "AHDAET",
  templateId: "1007990358521328635",
  link1: "Dear User Your Achudha Matrimony OTP is",
  link2: "Please use this OTP to verify your account on www.achudhamatrimony.in",
};

// Helper function to trigger SMS API
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
// Route 1: Register - Send OTP & Store Temp User in Session
// -------------------------------------------------------------
app.post("/send-otp", async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const cleanMobile = mobile.replace(/\D/g, "");

    const checkUser = await pool.query(
      "SELECT id FROM users WHERE email=$1 OR mobile=$2",
      [email, cleanMobile]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({
        message: "Email or mobile number already registered.",
      });
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();

    await sendSmsNotification(cleanMobile, generatedOtp);

    req.session.tempUser = {
      name,
      email,
      mobile: cleanMobile,
      password: hashPassword,
    };
    req.session.otp = generatedOtp;

    // Explicit session save before returning HTTP response
    req.session.save((err) => {
      if (err) {
        console.error("Session Save Error:", err);
        return res.status(500).json({ message: "Failed to save session." });
      }
      return res.json({ message: `OTP sent successfully to ${cleanMobile}` });
    });
  } catch (error) {
    console.error("Send OTP Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 2: Register - Verify OTP & Insert User into Database
// -------------------------------------------------------------
app.post("/register", async (req, res) => {
  try {
    const { otp } = req.body;

    if (!req.session.otp || !req.session.tempUser) {
      return res.status(400).json({
        message: "OTP session expired. Please request a new OTP.",
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
      return res.json({ message: "Registration Successful!" });
    });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 3: Combined Live User Check API (Email & Mobile)
// -------------------------------------------------------------
app.post("/check-user", async (req, res) => {
  try {
    const { email, mobile } = req.body;
    let emailExists = false;
    let mobileExists = false;

    if (email) {
      const emailRes = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
      emailExists = emailRes.rows.length > 0;
    }

    if (mobile) {
      const cleanMobile = mobile.replace(/\D/g, "");
      const mobileRes = await pool.query("SELECT id FROM users WHERE mobile=$1", [cleanMobile]);
      mobileExists = mobileRes.rows.length > 0;
    }

    return res.json({ emailExists, mobileExists });
  } catch (error) {
    console.error("Check User Error:", error);
    res.status(500).json({ emailExists: false, mobileExists: false, message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 4: Live Mobile Check API
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
    res.status(500).json({ isRegistered: false, message: "Server Error" });
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

    await sendSmsNotification(cleanMobile, generatedOtp);

    req.session.loginOtp = generatedOtp;
    req.session.loginMobile = cleanMobile;

    req.session.save((err) => {
      if (err) {
        console.error("Session Save Error:", err);
        return res.status(500).json({ message: "Failed to save session." });
      }
      return res.json({ message: `OTP sent successfully to ${cleanMobile}` });
    });
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

    req.session.isAuthenticated = true;
    delete req.session.loginOtp;
    delete req.session.loginMobile;

    req.session.save((err) => {
      if (err) console.error("Session Clear Error:", err);
      return res.json({ message: "Login Successful!" });
    });
  } catch (error) {
    console.error("Verify Login OTP Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 7: Standard Password Login
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

    req.session.isAuthenticated = true;

    req.session.save((err) => {
      if (err) console.error("Session Save Error:", err);
      return res.json({ message: "Login Successful" });
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------------------------------------------------------
// Route 8: Clear/Destroy Session API
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
// Route 9: Webhook Listener for SMS Status
// -------------------------------------------------------------
app.post("/combirds/sms-status", (req, res) => {
  const { message_id, status, statusDescription } = req.body;
  console.log(`[SMS WEBHOOK STATUS] ${message_id} -> ${status} (${statusDescription})`);
  res.status(200).send("OK");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
