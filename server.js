// backend/server.js
// This is the complete, final, and corrected server file.
// It includes a modern async startup function to authenticate the server,
// dynamically fetches the Person Account Record Type ID, handles all sign-up
// and login endpoints, and fetches IndividualApplication and Cases from Data Cloud.
// **MODIFIED**: Restored the original, working 'fetch' method for fetching PublicComplaint
// and UserDetails records during login to resolve sObject and Apex signature errors.
// **MODIFIED**: Restored all original console.log statements for detailed debugging.
// **KEPT**: The robust geocoding implementation and proxy helper function.

import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import jsforce from "jsforce";
import dotenv from "dotenv";
import twilio from "twilio";
import nodemailer from "nodemailer";
import fetch from 'node-fetch';
import qs from 'qs'; // for form-urlencoded POST body

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Destructure all required credentials from the .env file
const {
  SF_LOGIN_URL,
  SF_USERNAME,
  SF_PASSWORD,
  SF_CLIENT_ID,
  SF_CLIENT_SECRET,
  OAUTH_REDIRECT_URI,
  SF_COMMUNITY_URL,
  SF_DATA_CLOUD_URL,
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
  EMAIL_HOST,
  EMAIL_PORT,
  EMAIL_USER,
  EMAIL_PASS,
} = process.env;

// --- INITIALIZATIONS ---

const twilioClient = (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;
const emailTransporter = (EMAIL_HOST && EMAIL_USER && EMAIL_PASS) ? nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: false,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
}) : null;

const adminConnection = new jsforce.Connection({ loginUrl: SF_LOGIN_URL });
const otpStore = {};

// --- GLOBAL VARIABLES ---
let adminAccessToken = '';
let personAccountRecordTypeId = null;

const PROFILE_MAP = {
  Vendor: "00eKa0001cisNIAQ",
  Applicant: "00eKa000000OBPOIA4",
  Admin: "00eKa000001cis1IAA",
};

const REVERSE_PROFILE_MAP = Object.fromEntries(Object.entries(PROFILE_MAP).map(([role, id]) => [id, role]));

// --- HELPER FUNCTIONS ---

async function getAdminAccessToken() {
  if (!SF_USERNAME || !SF_PASSWORD || !SF_CLIENT_ID || !SF_CLIENT_SECRET || !SF_LOGIN_URL) {
    const errorMsg = "Missing required Salesforce credentials in .env file.";
    console.error(`❌ FATAL: ${errorMsg}`);
    throw new Error(errorMsg);
  }

  const tokenUrl = `${SF_LOGIN_URL}/services/oauth2/token`;
  console.log("🔑 Authenticating server admin user...");

  try {
    const bodyParams = new URLSearchParams();
    bodyParams.append('grant_type', 'password');
    bodyParams.append('client_id', SF_CLIENT_ID);
    bodyParams.append('client_secret', SF_CLIENT_SECRET);
    bodyParams.append('username', SF_USERNAME);
    bodyParams.append('password', SF_PASSWORD);

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: bodyParams,
    });
    const data = await response.json();
    if (!response.ok) {
      console.error("❌ Salesforce admin authentication failed:", data);
      throw new Error(data.error_description || 'Unknown authentication error');
    }
    adminAccessToken = data.access_token;
    console.log("✅ Successfully obtained server admin credentials.");
    // Print the generated admin access token
    console.log('🔑 Admin Access Token:', data.access_token);
    return data;
  } catch (err) {
    console.error(`[AUTH_FAILURE] Error during server admin authentication: ${err.message}`);
    throw err;
  }
}

async function getDataCloudToken(sfAdminAccessToken) {
    console.log("🔑 Using Admin Access Token to fetch Data Cloud token...");
    const tokenUrl = `${SF_LOGIN_URL}/services/a360/token`;
    const body = qs.stringify({
        grant_type: 'urn:salesforce:grant-type:external:cdp',
        subject_token: sfAdminAccessToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token'
    });
    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Bearer ${sfAdminAccessToken}` },
        body
    });
    if (!response.ok) { throw new Error(`Data Cloud token exchange failed: ${await response.text()}`); }
    const data = await response.json();
    console.log('✅ Received Data Cloud token.');
    console.log('🔑 Data Cloud Access Token:', data.access_token);
    return data.access_token;
}

async function fetchIndividualApplication(dataCloudToken, userEmail) {
    const queryEndpoint = `${SF_DATA_CLOUD_URL}/api/v1/query`;
    const sqlQuery = `SELECT Application_Id__c, Application_Status__c, Application_Type__c, Applied_Date__c, Category__c, Description__c, License_Type__c, InternalOrganization__c FROM Combined_Individual_Application__dlm WHERE Email__c = '${userEmail}' LIMIT 100`;
    const response = await fetch(queryEndpoint, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${dataCloudToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql: sqlQuery })
    });
    if (!response.ok) { throw new Error(`Data Cloud query failed: ${await response.text()}`); }
    const result = await response.json();
    if (result.data && result.data.length > 0) {
        console.log(`✅ ${result.data.length} Individual Application record(s) found.`);
        console.log('📄 Fetched Individual Application Records:', JSON.stringify(result.data, null, 2));
        return result.data;
    } else {
        console.log('🟡 No Individual Application record found for:', userEmail);
        return null;
    }
}

async function fetchCases(dataCloudToken, userEmail) {
    const queryEndpoint = `${SF_DATA_CLOUD_URL}/api/v1/query`;
    const sqlQuery = `SELECT Account_ID__c, Case_ID__c, Case_Number__c, Case_Origin__c, Contact_Email__c, Contact_ID__c, Data_Source__c, DataSource__c, DataSourceObject__c, InternalOrganization__c, Status__c, Subject__c FROM Combined_Cases__dlm WHERE Contact_Email__c = '${userEmail}' LIMIT 100`;
    const response = await fetch(queryEndpoint, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${dataCloudToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql: sqlQuery })
    });
    if (!response.ok) { throw new Error(`Data Cloud case query failed: ${await response.text()}`); }
    const result = await response.json();
    if (result.data && result.data.length > 0) {
        console.log(`✅ ${result.data.length} Case record(s) found.`);
        console.log('📄 Fetched Case Records:', JSON.stringify(result.data, null, 2));
        return result.data;
    } else {
        console.log('🟡 No Case records found for:', userEmail);
        return null;
    }
}

async function proxyAsUserToSalesforce(req, res, method, path, params = {}, body = null) {
    const userAccessToken = req.headers.authorization?.split(' ')[1];
    if (!userAccessToken) {
        if (!res.headersSent) res.status(401).json({ success: false, error: 'Unauthorized: Missing user token.' });
        throw new Error("Missing user access token.");
    }

    const instanceUrl = SF_COMMUNITY_URL;
    if (!instanceUrl) {
        if (!res.headersSent) res.status(503).json({ success: false, error: "Server is missing the SF_COMMUNITY_URL configuration." });
        throw new Error("Salesforce community URL not configured on the server.");
    }

    const url = new URL(`${instanceUrl}${path}`);
    if (params) {
        Object.keys(params).forEach(key => {
            if (params[key] !== undefined && params[key] !== null) {
                url.searchParams.append(key, params[key]);
            }
        });
    }

    const options = {
        method: method,
        headers: {
            'Authorization': `Bearer ${userAccessToken}`,
            'Content-Type': 'application/json',
        },
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const sfResponse = await fetch(url.toString(), options);

    if (!sfResponse.ok) {
        let errorMessage = 'Unknown Salesforce API error';
        try {
            const errorData = await sfResponse.json();
            errorMessage = errorData[0]?.message || errorData.error || JSON.stringify(errorData);
        } catch (e) {
            errorMessage = await sfResponse.text();
        }
        console.error(`Error proxying to Salesforce [${path}]:`, errorMessage);
        if (!res.headersSent) {
            res.status(sfResponse.status).json({ success: false, error: errorMessage });
        }
        throw new Error(errorMessage);
    }

    if (sfResponse.status === 204) {
        return null;
    }

    try {
        return await sfResponse.json();
    } catch (e) {
        console.error(`Failed to parse JSON response from Salesforce [${path}]:`, e);
        if (!res.headersSent) {
            res.status(500).json({ success: false, error: "Failed to parse Salesforce response." });
        }
        throw new Error("Failed to parse Salesforce response.");
    }
}

// --- API ENDPOINTS ---
app.post("/api/signup", async (req, res) => {
  const { fullName, email, role, mobileNumber, password } = req.body;
  if (!fullName || !email || !role || !mobileNumber || !password) {
    return res.status(400).json({ success: false, error: "Missing required fields." });
  }
  const profileId = PROFILE_MAP[role];
  if (!profileId) {
    return res.status(400).json({ success: false, error: "Invalid role specified." });
  }
  if (role !== 'Admin' && !personAccountRecordTypeId) {
    return res.status(500).json({ success: false, error: "Server configuration error." });
  }
  if (!adminConnection.accessToken) {
      return res.status(503).json({ success: false, error: "Server is not yet connected to Salesforce." });
  }

  try {
    const [firstName, ...lastNameParts] = fullName.trim().split(' ');
    const lastName = lastNameParts.join(' ') || firstName;
    const newPersonAccount = {
        FirstName: firstName, LastName: lastName, PersonEmail: email, Phone: mobileNumber,
        RecordTypeId: personAccountRecordTypeId
    };
    const accountResult = await adminConnection.sobject("Account").create(newPersonAccount);
    if (!accountResult.success) {
      throw new Error(`Failed to create person account: ${accountResult.errors.map(e => e.message).join(', ')}`);
    }
    const newAccountRecord = await adminConnection.sobject('Account').retrieve(accountResult.id);
    const contactId = newAccountRecord.PersonContactId;
    if (!contactId) {
      throw new Error('Could not find PersonContactId for the new Person Account.');
    }
    const newUser = {
      FirstName: firstName, LastName: lastName, Email: email, Username: `${email}.portal.citizen`, MobilePhone: mobileNumber,
      Alias: (firstName.charAt(0) + lastName).substring(0, 8).replace(/\s/g, ''),
      TimeZoneSidKey: "America/New_York", LocaleSidKey: "en_US", EmailEncodingKey: "UTF-8", LanguageLocaleKey: "en_US", ProfileId: profileId,
      ContactId: contactId,
    };
    const userResult = await adminConnection.sobject("User").create(newUser);
    if (!userResult.success) { throw new Error(userResult.errors.map(e => e.message).join(', ')); }
    await adminConnection.request({
        method: 'POST', url: `/services/data/v59.0/sobjects/User/${userResult.id}/password`,
        body: JSON.stringify({ NewPassword: password }), headers: { 'Content-Type': 'application/json' }
    });
    res.status(201).json({ success: true, message: "User created successfully! You can now log in." });
  } catch (err) {
    const errorMessage = err.message.includes('DUPLICATE_USERNAME')
        ? 'A user with this email address already exists.' : err.message;
    res.status(500).json({ success: false, error: errorMessage });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password are required." });
  }

  try {
    const result = await adminConnection.query(`SELECT Id, ProfileId, ContactId, Email FROM User WHERE Username = '${username.trim()}' LIMIT 1`);
    if (result.totalSize === 0) {
      return res.status(401).json({ success: false, error: "Invalid username or password." });
    }

    const { ProfileId: profileId, Id: userId, ContactId: contactId, Email: email } = result.records[0];
    const userRole = REVERSE_PROFILE_MAP[profileId] || 'Unknown';

    if (userRole === 'Admin') {
      const tokenUrl = `${SF_LOGIN_URL}/services/oauth2/token`;
      const tokenParams = new URLSearchParams({ grant_type: 'password', client_id: SF_CLIENT_ID, client_secret: SF_CLIENT_SECRET, username: username, password: password });
      const tokenResponse = await fetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: tokenParams });
      const data = await tokenResponse.json();
      if (!tokenResponse.ok) { throw new Error(data.error_description || "Admin authentication failed."); }
      console.log(`✅ [LOGIN SUCCESS - ADMIN] User: ${username} | Session ID (Access Token): ${data.access_token}`);
      res.json({
          success: true, type: "internal", message: "Admin/Internal login successful!", accessToken: data.access_token,
          instanceUrl: data.instance_url, userId: data.id.split('/').pop(), role: userRole
      });

    } else if (userRole === 'Applicant' || userRole === 'Vendor') {
      console.log(`[DEBUG] Applicant login flow started for user: ${username}`);
      const authorizeUrl = `${SF_COMMUNITY_URL}/services/oauth2/authorize`;
      const encodedCredentials = Buffer.from(`${username.trim()}:${password}`).toString('base64');
      const authParams = new URLSearchParams({ response_type: 'code_credentials', client_id: SF_CLIENT_ID, redirect_uri: OAUTH_REDIRECT_URI });
      const authResponse = await fetch(authorizeUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Request-Type': 'Named-User', 'Authorization': `Basic ${encodedCredentials}`}, body: authParams, redirect: 'manual' });
      const redirectLocation = authResponse.headers.get('location');
      if (!redirectLocation || authResponse.status !== 302) { throw new Error((await authResponse.json()).error_description || "Authorization failed."); }
      const authCode = new URL(redirectLocation).searchParams.get('code');
      if (!authCode) { throw new Error("Could not extract authorization code."); }
      const tokenUrl = `${SF_COMMUNITY_URL}/services/oauth2/token`;
      const tokenParams = new URLSearchParams({ grant_type: 'authorization_code', code: authCode, client_id: SF_CLIENT_ID, client_secret: SF_CLIENT_SECRET, redirect_uri: OAUTH_REDIRECT_URI });
      const tokenResponse = await fetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: tokenParams });
      const data = await tokenResponse.json();
      if (!tokenResponse.ok) { throw new Error(data.error_description || "Token exchange failed."); }

      let publicComplaints = null, userDetails = null, individualApplications = null, cases = null;

      // --- FETCH PUBLIC COMPLAINTS (RESTORED ORIGINAL METHOD) ---
      if (contactId) {
          console.log(`[DEBUG] Found ContactId: ${contactId}`);
          try {
              const contactResult = await adminConnection.query(`SELECT AccountId FROM Contact WHERE Id = '${contactId}' LIMIT 1`);
              if (contactResult.totalSize > 0) {
                  const accountId = contactResult.records[0].AccountId;
                  console.log(`[DEBUG] Found AccountId: ${accountId}`);
                  const soqlQuery = `SELECT Name, BusinessAddress, Status, Priority, Subject FROM PublicComplaint WHERE AccountId = '${accountId}' LIMIT 10`;
                  console.log(`[DEBUG] Executing SOQL Query via REST API: ${soqlQuery}`);

                  const queryEndpoint = `${adminConnection.instanceUrl}/services/data/v59.0/query`;
                  const queryUrl = `${queryEndpoint}?q=${encodeURIComponent(soqlQuery)}`;

                  const queryResponse = await fetch(queryUrl, {
                      method: 'GET',
                      headers: { 'Authorization': `Bearer ${adminConnection.accessToken}` }
                  });
                  if (!queryResponse.ok) { throw new Error(`Salesforce REST query failed: ${await queryResponse.text()}`); }
                  const publicComplaintsResult = await queryResponse.json();

                  if (publicComplaintsResult.totalSize > 0) {
                      console.log(`✅ SUCCESS: Found ${publicComplaintsResult.totalSize} Public Complaint(s) for this Account.`);
                      console.log("--- COMPLAINT RECORDS ---", JSON.stringify(publicComplaintsResult.records, null, 2), "-------------------------");
                      publicComplaints = publicComplaintsResult.records;
                  } else {
                      console.log(`🟡 INFO: No PublicComplaint records were found for AccountId: ${accountId}`);
                  }
              }
          } catch (err) {
              console.error('❌ ERROR: An error occurred while fetching PublicComplaints:', err.message);
          }
      }

      // --- FETCH USER DETAILS (RESTORED ORIGINAL METHOD) ---
      try {
          // This query fetches the contact details (Name, Email, Phone) and the user's regional settings.
          const userDetailsQuery = `SELECT Contact.FirstName, Contact.LastName, Contact.Email, Contact.Phone, Contact.MailingStreet, Contact.MailingCity, Contact.MailingState, Contact.MailingPostalCode, Contact.MailingCountry, TimeZoneSidKey, LocaleSidKey, LanguageLocaleKey FROM User WHERE userName = '${username}'`;
          console.log(`[DEBUG] Executing User Details SOQL Query: ${userDetailsQuery.trim().replace(/\s+/g, ' ')}`);

          const queryEndpoint = `${adminConnection.instanceUrl}/services/data/v59.0/query`;
          const queryUrl = `${queryEndpoint}?q=${encodeURIComponent(userDetailsQuery)}`;

          const queryResponse = await fetch(queryUrl, {
              method: 'GET',
              headers: { 'Authorization': `Bearer ${adminConnection.accessToken}` }
          });
          if (!queryResponse.ok) { throw new Error(`Salesforce User Details REST query failed: ${await queryResponse.text()}`); }
          const userDetailsResult = await queryResponse.json();

          if (userDetailsResult.totalSize > 0) {
              console.log(`✅ SUCCESS: Found User Details for ${username}.`);
              userDetails = userDetailsResult.records[0];
              // **CRITICAL LOGGING**: Print the exact data being sent to the client
              console.log("--- USER DETAILS RECORD (Check Contact fields here) ---", JSON.stringify(userDetails, null, 2), "---------------------------");
          }
      } catch (err) {
          console.error('❌ ERROR: An error occurred while fetching User Details:', err.message);
      }

      // --- FETCH DATA CLOUD RECORDS ---
      try {
        if (email && SF_DATA_CLOUD_URL) {
          const dataCloudToken = await getDataCloudToken(adminConnection.accessToken);
          individualApplications = await fetchIndividualApplication(dataCloudToken, email);
          cases = await fetchCases(dataCloudToken, email);
          console.log("📄 Cases data prepared for login response:", JSON.stringify(cases, null, 2));
        }
      } catch (dataCloudError) {
          console.error("❌ Error during post-login Data Cloud fetch:", dataCloudError.message);
      }

      console.log(`✅ [LOGIN SUCCESS - COMMUNITY] User: ${username} | Session ID (Access Token): ${data.access_token}`);
      res.json({
        success: true, type: "community", message: "Community login successful!", accessToken: data.access_token,
        instanceUrl: SF_LOGIN_URL, userId, individualApplications, cases, publicComplaints, userDetails, role: userRole,
      });

    } else {
      res.status(403).json({ success: false, error: "User's profile is not authorized." });
    }
  } catch (err) {
    console.error(`[LOGIN FAILURE] User: "${username}" | Error: ${err.name} - ${err.message}`);
    res.status(401).json({ success: false, error: "Invalid username or password." });
  }
});

// OTP Endpoints (Unchanged)
app.post("/api/send-otp", async (req, res) => {
    const { mobileNumber } = req.body;
    if (!mobileNumber || !twilioClient) { return res.status(400).json({ success: false, error: "Mobile number is required and Twilio must be configured." }); }
    const lastTenDigits = mobileNumber.replace(/\D/g, '').slice(-10);
    try {
        const userQueryResult = await adminConnection.query(`SELECT Id FROM User WHERE MobilePhone LIKE '%${lastTenDigits}' LIMIT 1`);
        if (userQueryResult.totalSize === 0) { return res.status(404).json({ success: false, error: "No user found with this mobile number." }); }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[mobileNumber] = { otp, expiry: Date.now() + 5 * 60 * 1000 };
        await twilioClient.messages.create({ body: `Your login OTP is: ${otp}`, from: TWILIO_PHONE_NUMBER, to: mobileNumber });
        res.json({ success: true, message: "OTP sent successfully." });
    } catch (err) { console.error("Error in /api/send-otp:", err); res.status(500).json({ success: false, error: "Failed to send OTP." }); }
});
app.post("/api/verify-otp", async (req, res) => {
    const { mobileNumber, otp } = req.body;
    const storedOtpData = otpStore[mobileNumber];
    if (!mobileNumber || !otp || !storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) { return res.status(400).json({ success: false, error: "Invalid or expired OTP." }); }
    try {
        const lastTenDigits = mobileNumber.replace(/\D/g, '').slice(-10);
        const userQueryResult = await adminConnection.query(`SELECT Id FROM User WHERE MobilePhone LIKE '%${lastTenDigits}' LIMIT 1`);
        if (userQueryResult.totalSize === 0) { return res.status(404).json({ success: false, error: "User not found." }); }
        delete otpStore[mobileNumber];
        res.json({ success: true, message: "Login successful!", userId: userQueryResult.records[0].Id });
    } catch (err) { console.error("Error in /api/verify-otp:", err); res.status(500).json({ success: false, error: "An internal server error occurred." }); }
});
app.post("/api/send-email-otp", async (req, res) => {
    const { email } = req.body;
    if (!email || !emailTransporter) { return res.status(400).json({ success: false, error: "Email is required and the email service must be configured." }); }
    try {
        const userQueryResult = await adminConnection.query(`SELECT Id FROM User WHERE Email = '${email}' LIMIT 1`);
        if (userQueryResult.totalSize === 0) { return res.status(404).json({ success: false, error: "No user found with this email address." }); }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, expiry: Date.now() + 5 * 60 * 1000 };
        await emailTransporter.sendMail({ from: `"Your App Name" <${process.env.EMAIL_USER}>`, to: email, subject: "Your One-Time Password (OTP)", text: `Your login OTP is: ${otp}`, html: `<b>Your login OTP is: ${otp}</b><p>This code will expire in 5 minutes.</p>`});
        res.json({ success: true, message: "OTP sent to your email address." });
    } catch (err) { console.error("Error in /api/send-email-otp:", err); res.status(500).json({ success: false, error: "Failed to send OTP email." }); }
});
app.post("/api/verify-email-otp", async (req, res) => {
    const { email, otp } = req.body;
    const storedOtpData = otpStore[email];
    if (!email || !otp || !storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) { return res.status(400).json({ success: false, error: "Invalid or expired OTP." }); }
    try {
        const userQueryResult = await adminConnection.query(`SELECT Id FROM User WHERE Email = '${email}' LIMIT 1`);
        if (userQueryResult.totalSize === 0) { return res.status(404).json({ success: false, error: "User not found." }); }
        delete otpStore[email];
        res.json({ success: true, message: "Login successful!", userId: userQueryResult.records[0].Id });
    } catch (err) { console.error("Error in /api/verify-email-otp:", err); res.status(500).json({ success: false, error: "An internal server error occurred." }); }
});

// --- VENUE BOOKING ENDPOINTS ---
app.get("/api/venues", async (req, res) => {
    console.log("🔄 Received request for /api/venues with params:", req.query);
    try {
        // Extract all potential query parameters from the request
        const params = {
            search: req.query.search,
            type: req.query.type,
            minCapacity: req.query.minCapacity,
            maxCapacity: req.query.maxCapacity,
            minPrice: req.query.minPrice,
            maxPrice: req.query.maxPrice,
            sortBy: req.query.sortBy,
            sortOrder: req.query.sortOrder,
            page: req.query.page,
            limit: req.query.limit
        };

        // Pass the extracted params to the proxy function
        const data = await proxyAsUserToSalesforce(
            req,
            res,
            'GET',
            '/services/apexrest/mobile/venues/',
            params // <-- This is the crucial addition
        );

        if (data !== undefined && !res.headersSent) {
            res.json(data);
        }
    } catch (error) {
        console.error("❌ Venue fetch failed:", error.message);
    }
});

app.get("/api/venues/bookings", async (req, res) => {
    console.log(`🔄 Received request for /api/venues/bookings for date: ${req.query.selectedDate}`);
    try {
        const params = { venueId: req.query.venueId, selectedDate: req.query.selectedDate };
        const data = await proxyAsUserToSalesforce(req, res, 'GET', '/services/apexrest/mobile/venues/bookings', params);
        if (data !== undefined && !res.headersSent) { res.json(data); }
    } catch (error) { console.error("❌ Existing bookings fetch failed:", error.message); }
});

app.post("/api/venues/checkout/start", async (req, res) => {
    console.log("🔄 Received request for /api/venues/checkout/start");
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'POST', '/services/apexrest/mobile/venues/checkout/start', {}, req.body);
        if (data !== undefined && !res.headersSent) { res.status(201).json(data); }
    } catch (error) { console.error("❌ Start checkout failed:", error.message); }
});

app.post("/api/venues/checkout/finalize", async (req, res) => {
    console.log("🔄 Received request for /api/venues/checkout/finalize");
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'POST', '/services/apexrest/mobile/venues/checkout/finalize', {}, req.body);
        if (data !== undefined && !res.headersSent) { res.status(200).json(data); }
    } catch (error) { console.error("❌ Finalize payment failed:", error.message); }
});



// --- SERVICE REQUEST ENDPOINTS ---
app.get("/api/geocoding/autocomplete", async (req, res) => {
    try {
        console.log("🔄 Proxying autocomplete request to Salesforce...");
        const data = await proxyAsUserToSalesforce(req, res, 'GET', '/services/apexrest/geocoding-api/autocomplete', { q: req.query.q });
        if (data !== undefined && !res.headersSent) {
            console.log("✅ Received data from Salesforce. Sending to client:", JSON.stringify(data, null, 2));
            res.json(data);
        }
    } catch (error) { console.error("❌ Error in autocomplete endpoint on server:", error.message); }
});

app.get("/api/geocoding/details", async (req, res) => {
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'GET', '/services/apexrest/geocoding-api/getDetails', { placeId: req.query.placeId });
        if (data !== undefined && !res.headersSent) { res.json(data); }
    } catch (error) { console.error("❌ Error in details endpoint on server:", error.message); }
});

app.get("/api/geocoding/reverse", async (req, res) => {
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'GET', '/services/apexrest/geocoding-api/reverse', { lat: req.query.lat, lon: req.query.lon });
        if (data !== undefined && !res.headersSent) { res.json(data); }
    } catch (error) { console.error("❌ Error in reverse geocode endpoint on server:", error.message); }
});

app.post("/api/service-request", async (req, res) => {
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'POST', '/services/apexrest/complaints-api/', {}, req.body);
        if (data !== undefined && !res.headersSent) { res.status(201).json({ success: true, data }); }
    } catch (error) { console.error("Service request submission failed for the user."); }
});

// --- SUPPORT REQUEST (MOBILE) ENDPOINTS ---
app.post("/api/user-email", async (req, res) => {
    console.log("🔄 Received request for /api/user-email");
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'GET', '/services/apexrest/MobileSupport/user-email', {});
        if (data !== undefined && !res.headersSent) { res.json(data); }
    } catch (error) { console.error("User email fetch failed."); }
});

app.post("/api/create-case", async (req, res) => {
    console.log("🔄 Received request for /api/create-case");
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'POST', '/services/apexrest/MobileSupport/case', {}, req.body);
        if (data !== undefined && !res.headersSent) { res.status(201).json(data); }
    } catch (error) { console.error("Case creation failed."); }
});

// --- AI DESCRIPTION SUGGESTIONS (MOBILE) ENDPOINT ---
app.post("/api/ai/suggest-description", async (req, res) => {
    console.log("🔄 Received request for /api/ai/suggest-description");
    try {
        const data = await proxyAsUserToSalesforce(req, res, 'POST', '/services/apexrest/ai-suggestions/', {}, req.body);
        if (data !== undefined && !res.headersSent) { res.status(200).json(data); }
    } catch (error) { console.error("AI description suggestion failed."); }
});

// --- SERVER STARTUP LOGIC ---
const PORT = process.env.PORT || 4000;
const initializeServer = async () => {
  try {
    console.log("🚀 Initializing server...");
    const adminAuthData = await getAdminAccessToken();
    adminConnection.initialize({
      instanceUrl: adminAuthData.instance_url,
      accessToken: adminAuthData.access_token,
    });
    console.log(`✅ Successfully configured jsforce for instance: ${adminAuthData.instance_url}`);

    console.log("🔍 Fetching Person Account Record Type ID...");
    const result = await adminConnection.query("SELECT Id FROM RecordType WHERE SobjectType = 'Account' AND IsPersonType = true LIMIT 1");

    if (result.records && result.records.length > 0) {
      personAccountRecordTypeId = result.records[0].Id;
      console.log(`✅ Person Account Record Type ID found: ${personAccountRecordTypeId}`);
    } else {
      throw new Error("Could not find a Person Account Record Type.");
    }

    app.listen(PORT, () => {
      console.log(`✅ Server is fully ready and listening on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("❌ FATAL: Server startup failed.", error.message);
    process.exit(1);
  }
};

initializeServer();

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
