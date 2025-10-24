// backend/server.js

import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import jsforce from "jsforce";
import dotenv from "dotenv";
import twilio from "twilio";
import nodemailer from "nodemailer"; // 1. Import nodemailer

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const {
  SF_LOGIN_URL,
  SF_USERNAME,
  SF_PASSWORD,
  SF_CLIENT_ID,
  SF_CLIENT_SECRET,
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
  TWILIO_WHATSAPP_NUMBER,
  // 2. Destructure new email variables
  EMAIL_HOST,
  EMAIL_PORT,
  EMAIL_USER,
  EMAIL_PASS,
} = process.env;

const twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

// 3. Create a Nodemailer transporter
const emailTransporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: false, // true for 465, false for other ports
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
    },
});

const PROFILE_MAP = {
  Vendor: "00eKa000001cisNIAQ",
  Applicant: "00eKa000000OBPOIA4",
  Admin: "00eKa000001cis1IAA",
};

const otpStore = {}; // This will now store OTPs for both phone and email

const adminConnection = new jsforce.Connection({
  loginUrl: SF_LOGIN_URL,
});


// --- SIGN-UP AND LOGIN ENDPOINTS (No changes needed here) ---
app.post("/api/signup", async (req, res) => { /* ... existing code ... */ });
app.post("/api/login", async (req, res) => { /* ... existing code ... */ });


// --- PHONE OTP ENDPOINTS (No changes needed here) ---
app.post("/api/send-otp", async (req, res) => { /* ... existing code ... */ });
app.post("/api/verify-otp", async (req, res) => { /* ... existing code ... */ });


// --- NEW: SEND EMAIL OTP ENDPOINT ---
app.post("/api/send-email-otp", async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, error: "Email address is required." });
    }

    try {
        const userQueryResult = await adminConnection.query(
            `SELECT Id, Username FROM User WHERE Email = '${email}' LIMIT 1`
        );

        if (userQueryResult.totalSize === 0) {
            return res.status(404).json({ success: false, error: "No user found with this email address." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = Date.now() + 5 * 60 * 1000; // 5-minute expiry

        // Use email as the key in otpStore
        otpStore[email] = { otp, expiry };

        // Send the email
        await emailTransporter.sendMail({
            from: `"Your App Name" <${EMAIL_USER}>`,
            to: email,
            subject: "Your One-Time Password (OTP)",
            text: `Your login OTP is: ${otp}`,
            html: `<b>Your login OTP is: ${otp}</b><p>This code will expire in 5 minutes.</p>`,
        });

        console.log(`✅ Successfully sent email OTP to ${email}`);
        res.json({ success: true, message: "OTP sent to your email address." });

    } catch (err) {
        console.error("Error in /api/send-email-otp:", err);
        res.status(500).json({ success: false, error: "Failed to send OTP email." });
    }
});

// --- NEW: VERIFY EMAIL OTP AND LOGIN ENDPOINT ---
app.post("/api/verify-email-otp", async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ success: false, error: "Email and OTP are required." });
    }

    const storedOtpData = otpStore[email];

    if (!storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) {
        if (storedOtpData) delete otpStore[email]; // Clear expired/invalid OTP
        return res.status(400).json({ success: false, error: "Invalid OTP or it has expired." });
    }

    try {
        const userQueryResult = await adminConnection.query(
            `SELECT Id, Username, FirstName, LastName, Email FROM User WHERE Email = '${email}' LIMIT 1`
        );

        if (userQueryResult.totalSize === 0) {
            return res.status(404).json({ success: false, error: "User not found." });
        }

        delete otpStore[email]; // OTP is valid, so remove it
        const userInfo = userQueryResult.records[0];

        res.json({
            success: true,
            message: "Login successful!",
            userId: userInfo.Id,
            username: userInfo.Username,
        });

    } catch (err) {
        console.error("Error in /api/verify-email-otp:", err);
        res.status(500).json({ success: false, error: "An internal server error occurred." });
    }
});


// --- Server startup logic (No changes needed here) ---
const startServer = () => { /* ... existing code ... */ };
const main = async () => { /* ... existing code ... */ };
main();