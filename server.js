const express = require('express');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json()); 

let users = [];
const SECRET_KEY = "your_secret_key"; 

const upload = multer({
    dest: path.join(__dirname, 'public/img'),
    limits: { fileSize: 5 * 1024 * 1024 }, 
});

app.get('/api/images', (req, res) => {
    const imagesDir = path.join(__dirname, 'public/img');
    fs.readdir(imagesDir, (err, files) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to read images directory' });
        }
        const images = files.map((file, index) => ({
            id: index + 1,
            url: `/img/${file}`,
        }));
        res.json(images);
    });
});

app.post('/api/upload', upload.single('image'), (req, res) => {
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const tempPath = file.path;
    const targetPath = path.join(__dirname, 'public/img', file.originalname);

    fs.rename(tempPath, targetPath, (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to save image' });
        }
        res.status(200).json({ message: 'Image uploaded successfully', url: `/img/${file.originalname}` });
    });
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = { username, password: hashedPassword };
    users.push(user);

    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ error: 'Invalid username or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
});

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
});

app.get('/api/protected', authenticate, (req, res) => {
    res.json({ message: `Welcome, ${req.user.username}!` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
