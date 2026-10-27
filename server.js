require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const CryptographicService = require('./CryptographicService');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const cryptoService = new CryptographicService();
const JWT_SECRET = process.env.JWT_SECRET || 'super-jwt-secret-key';

// Dynamic User Directory (In-memory mock store supporting self-registration)
const USERS_DB = [
  { username: 'Dr_Smith', password: 'teacherpassword123', role: 'teacher', name: 'Dr. Smith (Faculty)' },
  { username: 'atan', password: 'studentpassatan', role: 'student', studentId: 'atan', name: 'Atan Bin Ahmad' },
  { username: 'siti', password: 'studentpasssiti', role: 'student', studentId: 'siti', name: 'Siti Nurhaliza' }
];

// In-memory encrypted mark storage
const markDatabase = [];

// --- Sign-Up / Registration Route ---
app.post('/api/v1/auth/signup', (req, res) => {
  const { username, password, role, name, studentId } = req.body;

  if (!username || !password || !role || !name) {
    return res.status(400).json({ error: 'Missing required registration fields.' });
  }

  // Check if username already exists
  const existingUser = USERS_DB.find(u => u.username === username);
  if (existingUser) {
    return res.status(409).json({ error: 'Username is already taken. Please choose another.' });
  }

  // If role is student, ensure studentId is provided
  const assignedStudentId = role === 'student' ? (studentId || username) : null;

  const newUser = {
    username,
    password, // In production, hash this using bcrypt or argon2
    role,
    name,
    studentId: assignedStudentId
  };

  USERS_DB.push(newUser);

  // Issue token immediately upon successful registration for seamless UX
  const tokenPayload = {
    username: newUser.username,
    role: newUser.role,
    name: newUser.name,
    studentId: newUser.studentId
  };

  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '30m' });
  res.status(201).json({ success: true, message: 'Account created successfully.', accessToken: token, user: tokenPayload });
});

// --- Authentication Login Route ---
app.post('/api/v1/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = USERS_DB.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const tokenPayload = {
    username: user.username,
    role: user.role,
    name: user.name,
    studentId: user.studentId || null
  };

  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '30m' });
  res.json({ accessToken: token, user: tokenPayload });
});

// --- RBAC Middleware ---
const verifyToken = (requiredRole) => {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token missing. Please log in.' });

    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
      if (err) return res.status(403).json({ error: 'Session expired or invalid token.' });
      if (requiredRole && decodedUser.role !== requiredRole) {
        return res.status(403).json({ error: `Access denied: Requires '${requiredRole}' privileges.` });
      }
      req.user = decodedUser;
      next();
    });
  };
};

// --- Teacher Portal: Secure Mark Entry ---
app.post('/api/v1/teacher/marks', verifyToken('teacher'), (req, res) => {
  const { studentId, subjectCode, grade, internalReport } = req.body;

  if (!studentId || !subjectCode || !grade) {
    return res.status(400).json({ error: 'Missing required mark fields.' });
  }

  const encGrade = cryptoService.encryptTier1(`Student ID: ${studentId} | Subject: ${subjectCode} | Grade: ${grade}`);
  let encReport = null;
  if (internalReport) {
    encReport = cryptoService.encryptTier2(internalReport);
  }

  const record = {
    recordId: Math.random().toString(36).substring(2, 9),
    studentId,
    subjectCode,
    gradeData: encGrade.data,
    gradeIv: encGrade.iv,
    gradeCipher: encGrade.cipher,
    reportData: encReport ? encReport.data : null,
    reportIv: encReport ? encReport.iv : null,
    submittedBy: req.user.username,
    createdAt: new Date().toISOString()
  };

  markDatabase.push(record);
  res.status(201).json({ success: true, message: 'Mark encrypted & stored securely.', recordId: record.recordId });
});

// --- Student Portal: Bound Read-Only Results ---
app.get('/api/v1/student/results', verifyToken('student'), (req, res) => {
  const studentId = req.user.studentId;
  const records = markDatabase.filter(r => r.studentId === studentId);

  const decryptedResults = records.map(record => {
    const decryptedDetails = cryptoService.decryptTier1(record.gradeData, record.gradeIv);
    return {
      recordId: record.recordId,
      subjectCode: record.subjectCode,
      details: decryptedDetails,
      cipherUsed: record.gradeCipher,
      createdAt: record.createdAt
    };
  });

  res.json({ studentId, studentName: req.user.name, results: decryptedResults });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[Secure Server] running on http://localhost:${PORT}`);
});