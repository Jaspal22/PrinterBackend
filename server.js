const express = require('express');
const { MongoClient, GridFSBucket, ObjectId } = require('mongodb');
const busboy = require('busboy');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/gridfs_rbac_db";
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_for_development';
const PORT = process.env.PORT || 5000;

let db, gridBucket;

async function connectDB() {
  try {
    const client = await MongoClient.connect(MONGO_URI);
    db = client.db();
    gridBucket = new GridFSBucket(db, { bucketName: 'uploads' });
    console.log('Connected to MongoDB & GridFSBucket initialized');
  } catch (err) {
    console.error('Failed to connect to MongoDB:', err);
    process.exit(1);
  }
}
connectDB();

// DB Check Middleware
app.use((req, res, next) => {
  if (!gridBucket || !db) {
    return res.status(503).json({ error: 'Database connection warming up...' });
  }
  next();
});

// ==========================================
// AUTHENTICATION & AUTHORIZATION MIDDLEWARES
// ==========================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = (authHeader && authHeader.split(' ')[1]) || req.query.token;

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied. Insufficient privileges.' });
    }
    next();
  };
};

// ==========================================
// AUTH & USER ROUTES
// ==========================================

// Register Route
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const assignedRole = ['Admin', 'Teacher', 'Student'].includes(role) ? role : 'Student';

    const newUser = {
      username,
      password: hashedPassword,
      // REMOVED: plainPassword security leak
      role: assignedRole,
      createdAt: new Date(),
    };

    const result = await db.collection('users').insertOne(newUser);
    res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.collection('users').findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid username or password.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid username or password.' });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, user: { id: user._id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all users
app.get('/api/admin/users', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  try {
    const users = await db.collection('users')
      .find({}, { projection: { password: 0 } })
      .toArray();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update User Role
app.patch('/api/admin/users/:id/role', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    const { role } = req.body;
    if (!['Admin', 'Teacher', 'Student'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified.' });
    }

    const _id = new ObjectId(req.params.id);
    await db.collection('users').updateOne({ _id }, { $set: { role } });
    res.json({ message: 'User role updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get Print Reports / Audit Logs
app.get('/api/admin/print-reports', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  try {
    const reports = await db.collection('print_logs')
      .find({})
      .sort({ printedAt: -1 })
      .toArray();
      
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// GRIDFS FILE ROUTES
// ==========================================

// Upload Route (Admin & Teacher Only) - Fixed Stream Piping & Memory Footprint
app.post('/api/upload', authenticateToken, authorizeRoles('Admin', 'Teacher'), (req, res) => {
  let bb;
  try {
    bb = busboy({ headers: req.headers });
  } catch (err) {
    return res.status(400).json({ error: 'Malformed headers or non-multipart request.' });
  }

  const fields = {};
  let uploadStream = null;
  let uploadFinished = false;

  bb.on('field', (fieldname, val) => {
    fields[fieldname] = val;
  });

  bb.on('file', (fieldname, fileStream, info) => {
    const { filename, mimeType } = info;

    // Directly pipe stream into GridFS to prevent loading file into RAM
    uploadStream = gridBucket.openUploadStream(filename, {
      metadata: {
        contentType: mimeType,
        uploadedAt: new Date(),
        uploadedBy: req.user.username,
        userRole: req.user.role,
        customName: fields.customName || filename,
        copies: parseInt(fields.copies, 10) || 1,
      },
    });

    fileStream.pipe(uploadStream);

    uploadStream.on('finish', () => {
      uploadFinished = true;
      res.status(201).json({
        message: 'File uploaded successfully',
        fileId: uploadStream.id,
        filename,
      });
    });

    uploadStream.on('error', (err) => {
      if (!res.headersSent) {
        res.status(500).json({ error: 'GridFS write error: ' + err.message });
      }
    });
  });

  bb.on('finish', () => {
    if (!uploadStream && !res.headersSent) {
      return res.status(400).json({ error: 'No file provided in request.' });
    }
  });

  bb.on('error', (err) => {
    if (!res.headersSent) {
      res.status(500).json({ error: 'Multipart parsing failed: ' + err.message });
    }
  });

  req.pipe(bb);
});

// List Files Route
app.get('/api/files', authenticateToken, async (req, res) => {
  try {
    const files = await gridBucket.find({}).toArray();
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Stream/Download Route
app.get('/api/files/:id', authenticateToken, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: 'Invalid file ID format' });
    }

    const _id = new ObjectId(req.params.id);
    const files = await gridBucket.find({ _id }).toArray();

    if (!files || files.length === 0) {
      return res.status(404).json({ error: 'File not found' });
    }

    const file = files[0];
    const fileSize = file.length;
    const range = req.headers.range;

    if (file.metadata?.contentType) {
      res.setHeader('Content-Type', file.metadata.contentType);
    }

    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const endParsed = parseInt(parts[1], 10);
      const end = !isNaN(endParsed) ? endParsed : fileSize - 1;
      const chunkSize = end - start + 1;

      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
      });

      const downloadStream = gridBucket.openDownloadStream(_id, { start, end: end + 1 });
      downloadStream.pipe(res);
    } else {
      res.setHeader('Content-Length', fileSize);
      res.setHeader('Accept-Ranges', 'bytes');

      const downloadStream = gridBucket.openDownloadStream(_id);
      downloadStream.pipe(res);
    }
  } catch (err) {
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    }
  }
});

// Delete File Route (Admin Only) - Saves log first, then deletes
app.delete('/api/files/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: 'Invalid file ID format' });
    }

    const _id = new ObjectId(req.params.id);
    const files = await gridBucket.find({ _id }).toArray();

    if (!files || files.length === 0) {
      return res.status(404).json({ error: 'File not found' });
    }

    const file = files[0];

    const printLog = {
      fileId: file._id,
      filename: file.filename,
      customName: file.metadata?.customName || file.filename,
      uploadedBy: file.metadata?.uploadedBy || 'Unknown',
      userRole: file.metadata?.userRole || 'Teacher',
      copies: file.metadata?.copies || 1,
      printedAt: new Date(),
      printedBy: req.user.username,
    };

    await db.collection('print_logs').insertOne(printLog);
    await gridBucket.delete(_id);

    res.json({ message: 'File printed/deleted successfully and logged to report.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));








// const express = require('express');
// const { MongoClient, GridFSBucket, ObjectId } = require('mongodb');
// const busboy = require('busboy');
// const cors = require('cors');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// require('dotenv').config();

// const app = express();
// app.use(cors());
// app.use(express.json());

// const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/gridfs_rbac_db" ;

// const JWT_SECRET = process.env.JWT_SECRET;
// const PORT = process.env.PORT;

// let db, gridBucket;

// async function connectDB() {
//   try {
//     const client = await MongoClient.connect(MONGO_URI);
//     db = client.db();
//     gridBucket = new GridFSBucket(db, { bucketName: 'uploads' });
//     console.log('Connected to MongoDB & GridFSBucket initialized');
//   } catch (err) {
//     console.error('Failed to connect to MongoDB:', err);
//     process.exit(1);
//   }
// }
// connectDB();

// // DB Check Middleware
// app.use((req, res, next) => {
//   if (!gridBucket || !db) {
//     return res.status(503).json({ error: 'Database connection warming up...' });
//   }
//   next();
// });

// // ==========================================
// // AUTHENTICATION & AUTHORIZATION MIDDLEWARES
// // ==========================================
// const authenticateToken = (req, res, next) => {
//   const authHeader = req.headers['authorization'];
  
//   // FIXED: Reads token from Authorization header OR URL query parameter (?token=...)
//   const token = (authHeader && authHeader.split(' ')[1]) || req.query.token;

//   if (!token) {
//     return res.status(401).json({ error: 'Access denied. No token provided.' });
//   }

//   jwt.verify(token, JWT_SECRET, (err, user) => {
//     if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
//     req.user = user;
//     next();
//   });
// };

// const authorizeRoles = (...allowedRoles) => {
//   return (req, res, next) => {
//     if (!req.user || !allowedRoles.includes(req.user.role)) {
//       return res.status(403).json({ error: 'Access denied. Insufficient privileges.' });
//     }
//     next();
//   };
// };

// // ==========================================
// // AUTH & USER ROUTES
// // ==========================================

// // Register Route
// app.post('/api/auth/register', async (req, res) => {
//   try {
//     const { username, password, role } = req.body;
//     if (!username || !password) {
//       return res.status(400).json({ error: 'Username and password are required.' });
//     }

//     const existingUser = await db.collection('users').findOne({ username });
//     if (existingUser) {
//       return res.status(400).json({ error: 'Username already exists.' });
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);
//     const assignedRole = ['Admin', 'Teacher', 'Student'].includes(role) ? role : 'Student';

//     const newUser = {
//       username,
//       password: hashedPassword,
//       plainPassword: password, // Retained for Admin dashboard review
//       role: assignedRole,
//       createdAt: new Date(),
//     };

//     const result = await db.collection('users').insertOne(newUser);
//     res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Login Route
// app.post('/api/auth/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     const user = await db.collection('users').findOne({ username });
//     if (!user) return res.status(400).json({ error: 'Invalid username or password.' });

//     const validPassword = await bcrypt.compare(password, user.password);
//     if (!validPassword) return res.status(400).json({ error: 'Invalid username or password.' });

//     const token = jwt.sign(
//       { id: user._id, username: user.username, role: user.role },
//       JWT_SECRET,
//       { expiresIn: '8h' }
//     );

//     res.json({ token, user: { id: user._id, username: user.username, role: user.role } });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Admin: Get all users & credentials
// app.get('/api/admin/users', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
//   try {
//     const users = await db.collection('users')
//       .find({}, { projection: { password: 0 } })
//       .toArray();
//     res.json(users);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Admin: Update User Role
// app.patch('/api/admin/users/:id/role', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
//   try {
//     const { role } = req.body;
//     if (!['Admin', 'Teacher', 'Student'].includes(role)) {
//       return res.status(400).json({ error: 'Invalid role specified.' });
//     }

//     const _id = new ObjectId(req.params.id);
//     await db.collection('users').updateOne({ _id }, { $set: { role } });
//     res.json({ message: 'User role updated successfully' });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // ==========================================
// // GRIDFS FILE ROUTES
// // ==========================================

// // Upload Route (Admin & Teacher Only)
// app.post('/api/upload', authenticateToken, authorizeRoles('Admin', 'Teacher'), (req, res) => {
//   const bb = busboy({ headers: req.headers });

//   bb.on('file', (fieldname, fileStream, info) => {
//     const { filename, mimeType } = info;

//     const uploadStream = gridBucket.openUploadStream(filename, {
//       metadata: {
//         contentType: mimeType,
//         uploadedAt: new Date(),
//         uploadedBy: req.user.username,
//       },
//     });

//     fileStream.pipe(uploadStream);

//     uploadStream.on('finish', () => {
//       res.status(201).json({
//         message: 'File uploaded successfully',
//         fileId: uploadStream.id,
//         filename,
//       });
//     });

//     uploadStream.on('error', (err) => {
//       res.status(500).json({ error: err.message });
//     });
//   });

//   bb.on('error', (err) => {
//     res.status(500).json({ error: 'Multipart parsing failed: ' + err.message });
//   });

//   req.pipe(bb);
// });

// // List Files Route (All Authenticated Users)
// app.get('/api/files', authenticateToken, async (req, res) => {
//   try {
//     const files = await gridBucket.find({}).toArray();
//     res.json(files);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Stream/Download Route (Supports Headers OR Query Parameter ?token=...)
// app.get('/api/files/:id', authenticateToken, async (req, res) => {
//   try {
//     if (!ObjectId.isValid(req.params.id)) {
//       return res.status(400).send('Invalid file ID format');
//     }

//     const _id = new ObjectId(req.params.id);
//     const files = await gridBucket.find({ _id }).toArray();

//     if (!files || files.length === 0) {
//       return res.status(404).send('File not found');
//     }

//     const file = files[0];
//     const fileSize = file.length;
//     const range = req.headers.range;

//     if (file.metadata?.contentType) {
//       res.setHeader('Content-Type', file.metadata.contentType);
//     }

//     // Handle Range Requests for Media Seeking
//     if (range) {
//       const parts = range.replace(/bytes=/, '').split('-');
//       const start = parseInt(parts[0], 10);
//       const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
//       const chunkSize = end - start + 1;

//       res.writeHead(206, {
//         'Content-Range': `bytes ${start}-${end}/${fileSize}`,
//         'Accept-Ranges': 'bytes',
//         'Content-Length': chunkSize,
//       });

//       const downloadStream = gridBucket.openDownloadStream(_id, { start, end: end + 1 });
//       downloadStream.pipe(res);
//     } else {
//       res.setHeader('Content-Length', fileSize);
//       res.setHeader('Accept-Ranges', 'bytes');
      
//       const downloadStream = gridBucket.openDownloadStream(_id);
//       downloadStream.pipe(res);
//     }
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Delete File Route (Admin Only)
// app.delete('/api/files/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
//   try {
//     if (!ObjectId.isValid(req.params.id)) {
//       return res.status(400).send('Invalid file ID format');
//     }

//     const _id = new ObjectId(req.params.id);
//     await gridBucket.delete(_id);
//     res.json({ message: 'File deleted successfully' });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.listen(PORT, () => console.log(`Server running on port${PORT}`));

















