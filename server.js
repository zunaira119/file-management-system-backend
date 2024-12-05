// Backend: Express.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const mysql = require('mysql2/promise');
const Joi = require('joi');

const app = express();
app.use(express.json());
app.use(cors());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// Local storage configuration for multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});

const upload = multer({ storage });
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'webApp',
});

// User Authentication
app.post('/register', async (req, res) => {
    const schema = Joi.object({
    username: Joi.string().min(5).required().messages({
      'string.min': 'Username must be at least 5 characters long',
      'any.required': 'Username is required',
    }),
    password: Joi.string().min(6).required().messages({
      'string.min': 'Password must be at least 6 characters long',
      'any.required': 'Password is required',
    }),
  });

  const { error } = schema.validate(req.body);

  if (error) {
    return res.status(400).json({
      errors: error.details.map((err) => ({
        message: err.message,
        path: err.path,
      })),
    });
  }
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.sendStatus(201);
});

app.post('/login', async (req, res) => {
    const schema = Joi.object({
    username: Joi.string().min(5).required().messages({
      'string.min': 'Username must be at least 5 characters long',
      'any.required': 'Username is required',
    }),
    password: Joi.string().min(6).required().messages({
      'string.min': 'Password must be at least 6 characters long',
      'any.required': 'Password is required',
    }),
  });

  const { error } = schema.validate(req.body);

  if (error) {
    return res.status(400).json({
      errors: error.details.map((err) => ({
        message: err.message,
        path: err.path,
      })),
    });
  }
    const { username, password } = req.body;
    const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];
    if (user && (await bcrypt.compare(password, user.password))) {
        const token = jwt.sign({ userId: user.id }, 'your-secret-key');
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    console.log(token);
    if (token) {
        jwt.verify(token, 'your-secret-key', (err, decoded) => {
            if (err) return res.sendStatus(403);
            req.userId = decoded.userId;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// File Upload and Management
app.post('/upload', authenticate, upload.single('file'), async (req, res) => {
    const { tags, type } = req.body;
    const shareableLink = `http://localhost:3000/uploads/${req.file.filename}`;
    await db.execute(
        'INSERT INTO files (url, tags,type,name, userId, views, shareableLink) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [req.file.path, tags, type, req.file.filename, req.userId, 0, shareableLink]
    );
    res.status(201).json({ url: shareableLink, tags, shareableLink });
});

app.get('/files', authenticate, async (req, res) => {
    const [rows] = await db.execute('SELECT * FROM files WHERE userId = ?', [req.userId]);
    res.json(rows);
});

app.get('/get/files', async (req, res) => {
    const [rows] = await db.execute('SELECT * FROM files');
    res.json(rows);
});

app.get('/file/:id', async (req, res) => {
    console.log(req.params.id,'here it is');
    const [rows] = await db.execute('SELECT * FROM files WHERE id = ?', [req.params.id]);
    const file = rows[0];
    console.log(file,'here it  is new');
    if (file) {
        await db.execute('UPDATE files SET views = views + 1 WHERE id = ?', [req.params.id]);
        res.redirect(file.url);
    } else {
        res.sendStatus(404);
    }
});
// (async () => {
//   await db.execute(`
//     CREATE TABLE IF NOT EXISTS users (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       username VARCHAR(255) NOT NULL,
//       password VARCHAR(255) NOT NULL
//     );
//   `);

//   await db.execute(`
//     CREATE TABLE IF NOT EXISTS files (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       url VARCHAR(255) NOT NULL,
//       name VARCHAR(255),
//       type VARCHAR(255),
//       tags json,
//       userId INT NOT NULL,
//       views INT DEFAULT 0,
//       shareableLink VARCHAR(255),
//       FOREIGN KEY (userId) REFERENCES users(id)
//     );
//   `);
app.listen(5000, () => console.log('Server running on http://localhost:5000'));
//   })();


