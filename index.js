const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion } = require('mongodb');
const cors = require('cors');
const crypto = require('crypto'); // For generating OTP

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

const uri = "mongodb+srv://isindu:isindu980@cluster0.yjtla.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
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
    user: 'volunt23@gmail.com',
    pass: 'rdgr ghem kbqg ghdw',
  }
});

const JWT_SECRET = '45bc7637be2af856482261953f87d670d663af2bc9b3872e79b0dedd7b30f1a1acf15fec8a5e05ce80766f29f5d6aecf301b41cb21592af1166c43aa41616e117b332b6815dd41cef91c7d52e8e4abafe8665b2aeca199586e2ed8c332a4a8186f1ed0b73039919795275a2c4af9c997e45afdc6f25230139bb19d49d0f15a4e280918c84de34ebd264d11a2d40b98b5bd54657b3b73ac1fe60555b43cfa9512284ef0ef1e15457f9f223d5e65c2f113928b861d67a49fe0787a5d35e7f3de7fb6544f98da993a02b8b334352d814a08309652a4082e898d157d24ad63e67abbcabd6f65abf346d0c15ccb54eea5f3518cd4ae2f6bb114e4c5d4647f7a4f7ecb';

const OTP_EXPIRY = 5 * 60 * 1000; // OTP expiry time in milliseconds (5 minutes)

// Signup route (same as before)
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

    const confirmLink = `http://localhost:5000/api/confirm/${token}`;

    const mailOptions = {
      from: 'volunt23@gmail.com',
      to: email,
      subject: 'Email Confirmation',
      html: `<h1>Welcome ${username}</h1><p>Click <a href="${confirmLink}">here</a> to confirm your email and complete your registration.</p>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Confirmation email sent. Please verify your email to complete registration.' });

  } catch (error) {
    console.error("Error in signup process:", error);
    res.status(500).json({ success: false, message: 'Server error during signup process.' });
  }
});

// Email confirmation route (same as before)
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
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// Login route with OTP
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
    await logUserActivity(user._id, 'Login', 'User logged in');
    // Generate OTP and store it in the database with an expiry time
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiry = Date.now() + OTP_EXPIRY;

    await client.db(dbName).collection(usersCollectionName).updateOne(
      { email },
      { $set: { otp, otpExpiry } }
    );

    // Send OTP to the user's email
    const mailOptions = {
      from: 'volunt23@gmail.com',
      to: email,
      subject: 'Your One-Time Password (OTP)',
      html: `<h1>Your OTP is ${otp}</h1><p>This OTP is valid for 5 minutes.</p>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'OTP sent to your email. Please verify.' });

  } catch (error) {
    console.error("Error during login process:", error);
    res.status(500).json({ success: false, message: 'Server error during login process.' });
  }
});


// OTP Verification route
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
  
      // Validate OTP
      if (!user.otp || Date.now() > user.otpExpiry || user.otp !== otp) {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
      }
  
      // Clear OTP fields after successful verification
      await client.db(dbName).collection(usersCollectionName).updateOne(
        { email },
        { $unset: { otp: "", otpExpiry: "" } }
      );
  
      // Generate a JWT token for the user
      const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
  
      // Respond with success and the token
      res.status(200).json({ success: true, message: 'OTP verified successfully.', token });
    } catch (error) {
      console.error("Error during OTP verification:", error);
      res.status(500).json({ success: false, message: 'Server error during OTP verification.' });
    }
  });
  
  
// Protected route for user dashboard
app.get('/api/user-dashboard', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Bearer token

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
    await logUserActivity(user._id, 'Dashboard Access', 'User accessed their dashboard.');


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

      await logUserActivity(user._id, 'Update Username', `User changed their username to ${username}.`);

  
      res.json({ success: true, message: 'Username updated successfully.' });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Error updating username.' });
    }
  });


async function logUserActivity(userId, activityType, activityDetails) {
    const activity = {
      userId,
      activityType,
      activityDetails,
      timestamp: new Date(),
    };
  
    try {
      await client.db(dbName).collection('Activity').insertOne(activity);
    } catch (error) {
      console.error('Error logging user activity:', error);
    }
  }

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

