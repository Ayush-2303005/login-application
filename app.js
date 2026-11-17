
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const initSqlJs = require("sql.js");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
let db;
const dbPath = path.join(__dirname, "users.db");

async function initializeDatabase() {
    const SQL = await initSqlJs();

    if (fs.existsSync(dbPath)) {
        const fileBuffer = fs.readFileSync(dbPath);
        db = new SQL.Database(fileBuffer);
    } else {
        db = new SQL.Database();
    }

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    saveDatabase();
}

function saveDatabase() {
    const data = db.export();
    fs.writeFileSync(dbPath, Buffer.from(data));
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || "change-this-secret-before-deployment",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax"
    }
}));

app.use(express.static(path.join(__dirname, "public")));

// Health check route
app.get("/health", (req, res) => {
    res.status(200).json({
        status: "OK",
        message: "Login application is running",
        timestamp: new Date().toISOString()
    });
});

// Register route
app.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password || password.length < 8) {
            return res.status(400).json({
                message: "Username and password (minimum 8 characters) are required"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        db.run(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [username, hashedPassword]
        );

        saveDatabase();

        res.status(201).json({
            message: "Registration successful"
        });

    } catch (error) {
        res.status(400).json({
            message: "Registration failed. Username may already exist."
        });
    }
});

// Login route
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password are required"
            });
        }

        const result = db.exec(
            "SELECT * FROM users WHERE username = ?",
            [username]
        );

        if (!result.length || !result[0].values.length) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        const user = result[0].values[0];

        const validPassword = await bcrypt.compare(
            password,
            user[2]
        );

        if (!validPassword) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        req.session.user = {
            id: user[0],
            username: user[1]
        };

        res.json({
            message: "Login successful",
            username: user[1]
        });

    } catch (error) {
        res.status(500).json({
            message: "Login failed"
        });
    }
});

// Dashboard route
app.get("/dashboard", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            message: "Unauthorized. Please login."
        });
    }

    res.json({
        message: "Welcome to your dashboard",
        user: req.session.user
    });
});

// Logout route
app.post("/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).json({
                message: "Logout failed"
            });
        }

        res.clearCookie("connect.sid");

        res.json({
            message: "Logout successful"
        });
    });
});

// Start server
async function startServer() {
    try {
        await initializeDatabase();

        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
            console.log(`Health check: http://localhost:${PORT}/health`);
        });

    } catch (error) {
        console.error("Database initialization failed:", error);
        process.exit(1);
    }
}

if (require.main === module) {
    startServer();
}

module.exports = app;
module.exports.initializeDatabase = initializeDatabase;
