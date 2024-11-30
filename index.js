const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion } = require('mongodb');
const cors = require('cors');
const crypto = require('crypto'); 
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

const OTP_EXPIRY = 5 * 60 * 1000; 


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
  
     
      if (user.role === 'admin' || email === 'isindu980@gmail.com') {
        await logUserActivity(user._id, user.username, 'Admin Login');
      } else {
        await logUserActivity(user._id, user.username, 'User Login');
      }
     
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '5m' });
  

      const otp = crypto.randomInt(100000, 999999).toString();
      const otpExpiry = Date.now().toLocaleString() + OTP_EXPIRY;
  
      await client.db(dbName).collection(usersCollectionName).updateOne(
        { email },
        { $set: { otp, otpExpiry } }
      );
  
      const mailOptions = {
        from: 'volunt23@gmail.com',
        to: email,
        subject: 'Your One-Time Password (OTP)',
        html: `<h1>Your OTP is ${otp}</h1><p>This OTP is valid for 5 minutes.</p>`
      };
  
      await transporter.sendMail(mailOptions);
  
      
      if (email === 'isindu980@gmail.com') {
        return res.json({
          success: true,
          message: 'OTP sent to your email. Please verify.',
          isAdmin: true,
          token,
          userData: user,
          navigateTo: 'admin-dashboard', 
        });
      }
  
  
      if (user.role === 'admin') {
        return res.json({
          success: true,
          message: 'OTP sent to your email. Please verify.',
          isAdmin: true,
          token, 
          userData: user,
          navigateTo: 'admin-dashboard', 
        });
      }
  
      
      return res.json({
        success: true,
        message: 'OTP sent to your email. Please verify.',
        token,
        navigateTo: 'user-dashboard',
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
      let role = user.role;
      let navigateTo = 'dashboard';
      if (email === 'isindu980@gmail.com') {
        
        navigateTo = 'admin-dashboard';
      }
      const token = jwt.sign({ email, role }, JWT_SECRET, { expiresIn: '1h' });
  
      res.status(200).json({
        success: true,
        message: 'OTP verified successfully.',
        token,
        role,
        navigateTo,
      });
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
  
      console.log(`User with ID ${userId} deleted successfully by ${decoded.email}`);
      res.json({ success: true, message: 'User deleted successfully.' });
  
    } catch (err) {
    
      console.error('Error deleting user:', err);
      await logUserActivity(user._id, username, 'Update Username');
   
      if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ success: false, message: 'Invalid token.' });
      } else if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ success: false, message: 'Token expired.' });
      }
  
   
      res.status(500).json({ success: false, message: 'Error deleting user.', error: err.message });
    }
  });
  
 
  
//   app.get('/api/logs', async (req, res) => {
//     const logs = await client.db(dbName).collection('Activity').find().toArray();
//     res.json({ success: true, logs });
//   });
  

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
    await logUserActivity(user.id, user.username, '`User with ID ${userId} deleted successfully');


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

      await logUserActivity(user.id, username, 'Update Username');

  
      res.json({ success: true, message: 'Username updated successfully.' });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Error updating username.' });
    }
  });


async function logUserActivity(userId, username, activityType) {
  const activity = {
    userId,
    username,
    activityType,
    timestamp: new Date().toLocaleString(),
  };

  try {
    await client.db(dbName).collection('Activity').insertOne(activity);
  } catch (error) {
    console.error('Error logging user activity:', error);
  }
}

  
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

