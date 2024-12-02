require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion } = require('mongodb');
const cors = require('cors');
const crypto = require('crypto'); 
const moment = require('moment-timezone');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const logsCollectionName = 'Activity';
const app = express();

const { ObjectId } = require('mongodb');
const router = express.Router();

app.use(cors({
  origin: 'https://www.isindueshan.me', // Allow your frontend's origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify the methods you want to allow
  allowedHeaders: ['Content-Type', 'Authorization'] // Allowed headers for the request
}));
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

const dbName = 'Cluster0';
const usersCollectionName = 'users';

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error("MongoDB connection error", error);
  }
}
run().catch(console.error);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  }
});

const JWT_SECRET = process.env.JWT_SECRET;

const OTP_EXPIRY = 5 * 60 * 1000; 

async function logUserActivity(userId, username, activityType) {
  const activity = {
    userId,
    username,
    activityType,
    timestamp: moment().tz('Asia/Kolkata').format('YYYY-MM-DD HH:mm:ss'), // GMT+5:30
  };

  try {
    await client.db(dbName).collection('Activity').insertOne(activity);
  } catch (error) {
    console.error('Error logging user activity:', error);
  }
}

// Session management setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: uri,
    dbName: dbName,
    collectionName: 'sessions'
  }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'All fields are required.' });
  }

  try {
    const existingUser = await client.db(dbName).collection(usersCollectionName).findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email is already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const token = jwt.sign({ username, email, password: hashedPassword }, JWT_SECRET, { expiresIn: '1h' });
    console.log("Generated Token:", token);

    const confirmLink = `https://securewrap-1621182990b0.herokuapp.com/api/confirm/${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Email Confirmation',
      html: `<h1>Welcome ${username}</h1><p>Click <a href="${confirmLink}">here</a> to confirm your email and complete your registration.</p>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Confirmation email sent. Please verify your email to complete registration.' });

    await logUserActivity(null, username, 'Signup');
  } catch (error) {
    console.error("Error in signup process:", error);
    res.status(500).json({ success: false, message: 'Server error during signup process.' });
  }
});

app.get('/api/confirm/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const existingUser = await client.db(dbName).collection(usersCollectionName).findOne({ email: decoded.email });
    if (existingUser && existingUser.confirmed) {
      return res.status(400).json({ error: 'User already confirmed' });
    }

    const user = {
      username: decoded.username,
      email: decoded.email,
      password: decoded.password,
      confirmed: true
    };

    await client.db(dbName).collection(usersCollectionName).insertOne(user);

    res.status(200).json({ message: 'Account confirmed and created!' });

    await logUserActivity(user._id, user.username, 'Email Confirmed');
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required.' });
  }

  try {
    const user = await client.db(dbName).collection(usersCollectionName).findOne({ email });
    if (!user || !user.confirmed) {
      return res.status(400).json({ success: false, message: 'User not confirmed or does not exist.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Incorrect password.' });
    }

    const activityType = (user.role === 'admin' || email === 'isindu980@gmail.com') ? 'Admin Login' : 'User Login';
    await logUserActivity(user._id, user.username, activityType);

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '5m' });

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiry = Date.now() + OTP_EXPIRY;

    await client.db(dbName).collection(usersCollectionName).updateOne(
      { email },
      { $set: { otp, otpExpiry } }
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your One-Time Password (OTP)',
      html: `<h1>Your OTP is ${otp}</h1><p>This OTP is valid for 5 minutes.</p>`
    };

    await transporter.sendMail(mailOptions);

    const navigateTo = (email === 'isindu980@gmail.com' || user.role === 'admin') ? 'admin-dashboard' : 'user-dashboard';

    res.json({
      success: true,
      message: 'OTP sent to your email. Please verify.',
      isAdmin: (email === 'isindu980@gmail.com' || user.role === 'admin'),
      token,
      userData: user,
      navigateTo
    });
  } catch (error) {
    console.error("Error during login process:", error);
    res.status(500).json({ success: false, message: 'Server error during login process.' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required.' });
  }

  try {
    const user = await client.db(dbName).collection(usersCollectionName).findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'User not found.' });
    }

    if (!user.otp || Date.now() > user.otpExpiry || user.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
    }

    await client.db(dbName).collection(usersCollectionName).updateOne(
      { email },
      { $unset: { otp: "", otpExpiry: "" } }
    );

    const role = user.role;
    const navigateTo = (email === 'isindu980@gmail.com') ? 'admin-dashboard' : 'user-dashboard';
    const token = jwt.sign({ email, role }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      success: true,
      message: 'OTP verified successfully.',
      token,
      role,
      navigateTo,
    });

    await logUserActivity(user._id, user.username, 'OTP Verified');
  } catch (error) {
    console.error("Error during OTP verification:", error);
    res.status(500).json({ success: false, message: 'Server error during OTP verification.' });
  }
});

app.get('/api/admin-dashboard', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; 

  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const adminEmail = 'isindu980@gmail.com';
    if (decoded.email !== adminEmail) {
      return res.status(403).json({ success: false, message: 'Access denied. Only admin can access this dashboard.' });
    }

    const adminUser = await client.db(dbName).collection(usersCollectionName).findOne({ email: decoded.email });

    if (!adminUser) {
      return res.status(404).json({ success: false, message: 'Admin user not found.' });
    }

    res.json({ success: true, message: 'Welcome to the Admin Dashboard!', admin: adminUser });

    await logUserActivity(adminUser._id, adminUser.username, 'Access Admin Dashboard');
  } catch (error) {
    console.error('Error accessing admin dashboard:', error);
    res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
});

app.get('/api/logs', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];  

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const logs = await client.db(dbName).collection('Activity').find().toArray();

    res.json({ success: true, logs });

    await logUserActivity(decoded.userId, decoded.username, 'View Logs');
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching logs' });
  }
});

app.get('/api/users', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.email !== 'isindu980@gmail.com') {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    const users = await client.db(dbName).collection(usersCollectionName).find().toArray();
    res.json({ success: true, users });

    await logUserActivity(decoded.userId, decoded.username, 'View Users');
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid token.' });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  const userId = req.params.id;
  const token = req.headers.authorization?.split(' ')[1];

  if (!ObjectId.isValid(userId)) {
    return res.status(400).json({ success: false, message: 'Invalid user ID format.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await client.db(dbName).collection(usersCollectionName).findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    if (user.email === 'isindu980@gmail.com') {
      return res.status(403).json({ success: false, message: 'Cannot delete the main admin account.' });
    }

    if (user.role === 'admin') {
      return res.status(403).json({ success: false, message: 'Cannot delete an admin account.' });
    }

    const result = await client.db(dbName).collection(usersCollectionName).deleteOne({ _id: new ObjectId(userId) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: 'No user deleted, user may not exist.' });
    }

    res.json({ success: true, message: 'User deleted successfully.' });

    await logUserActivity(decoded.userId, decoded.username, `Deleted User ${userId}`);
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ success: false, message: 'Error deleting user.', error: err.message });
  }
});

app.get('/api/user-dashboard', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; 

  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await client.db(dbName).collection(usersCollectionName).findOne({ email: decoded.email });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    res.json({ success: true, message: 'Welcome to your dashboard!', user });

    await logUserActivity(user._id, user.username, 'Access User Dashboard');
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token.' });
  }
});

app.post('/api/update-username', async (req, res) => {
  const { username } = req.body;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token || !username) {
    return res.status(400).json({ success: false, message: 'Token and new username are required.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await client.db(dbName).collection(usersCollectionName).findOne({ email: decoded.email });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    await client.db(dbName).collection(usersCollectionName).updateOne(
      { email: decoded.email },
      { $set: { username } }
    );

    res.json({ success: true, message: 'Username updated successfully.' });

    await logUserActivity(user._id, username, 'Update Username');
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error updating username.' });
  }
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});