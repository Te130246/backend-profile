require('dotenv').config(); // โหลดตัวแปรจากไฟล์ .env
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// ตรวจสอบและสร้างโฟลเดอร์ uploads หากไม่มี
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Error: File upload only supports the following filetypes - jpeg, jpg, png, gif'));
    }
});

// ดึงค่าจาก DATABASE_URL
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    console.error('DATABASE_URL is not defined in .env file');
    process.exit(1);
}

// แยกค่าจาก DATABASE_URL
const url = new URL(databaseUrl);
const dbConfig = {
    host: url.hostname,
    port: url.port,
    user: url.username,
    password: url.password,
    database: url.pathname.replace('/', ''), // ตัด '/' ออก
    ssl: JSON.parse(url.searchParams.get('ssl')) // ดึงค่า SSL
};

// MySQL Connection
const db = mysql.createConnection(dbConfig);

// Connect to MySQL
db.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL Database:', err.message);
        process.exit(1); // ออกจากโปรแกรมหากเชื่อมต่อไม่ได้
    }
    console.log('Connected to MySQL Database');
});

// API สำหรับดึงข้อมูลโปรไฟล์ทั้งหมด
app.get('/api/profiles', (req, res) => {
    const sql = 'SELECT * FROM Profiles';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching profiles:', err);
            return res.status(500).send({ message: 'Error fetching profiles', error: err.message });
        }
        res.status(200).send(results);
    });
});

// API สำหรับลงทะเบียนผู้ใช้
app.post('/api/register', (req, res) => {
    const { first_name, last_name, email, password } = req.body;

    // ตรวจสอบว่าข้อมูลครบถ้วนหรือไม่
    if (!first_name || !last_name || !email || !password) {
        return res.status(400).send({ message: 'Please provide all required fields.' });
    }

    // ตรวจสอบรูปแบบอีเมล
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).send({ message: 'Invalid email format.' });
    }

    // ตรวจสอบว่าอีเมลซ้ำในฐานข้อมูลหรือไม่
    const checkEmailQuery = 'SELECT * FROM Users WHERE email = ?';
    db.query(checkEmailQuery, [email], (err, results) => {
        if (err) {
            console.error('Error checking email:', err);
            return res.status(500).send({ message: 'Error checking email', error: err.message });
        }
        if (results.length > 0) {
            return res.status(400).send({ message: 'Email already exists' });
        }

        // เข้ารหัสรหัสผ่าน
        const hashedPassword = bcrypt.hashSync(password, 8);

        // บันทึกข้อมูลผู้ใช้ใหม่
        const sql = 'INSERT INTO Users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)';
        db.query(sql, [first_name, last_name, email, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).send({ message: 'Error registering user', error: err.message });
            }
            res.status(201).send({ message: 'ลงทะเบียนสำเร็จ' });
        });
    });
});

// API สำหรับเข้าสู่ระบบผู้ใช้
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    // ตรวจสอบว่าข้อมูลครบถ้วนหรือไม่
    if (!email || !password) {
        return res.status(400).send({ message: 'Please provide both email and password.' });
    }

    const sql = 'SELECT * FROM Users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Error during login:', err);
            return res.status(500).send({ message: 'Error during login', error: err.message });
        }
        if (results.length === 0) {
            return res.status(404).send({ message: 'User not found' });
        }

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).send({ message: 'Invalid Password!' });
        }

        res.status(200).send({ 
            id: user.id,
            email: user.email,
            message: 'เข้าสู่ระบบสำเร็จ',
            success: true,
        });
    });
});

// API สำหรับอัปโหลดไฟล์
app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send({ message: 'No file uploaded.' });
    }
    res.status(200).send({ 
        message: 'File uploaded successfully.',
        filePath: `/uploads/${req.file.filename}`
    });
});

// เริ่มเซิร์ฟเวอร์
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
