
const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "development-secret-change-this",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax"
        }
    })
);

// In-memory users for this demo application.
// Data resets when the server restarts.
const users = [];

// Serve frontend files
app.use(express.static(path.join(__dirname, "public")));

// Register
app.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password are required"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must contain at least 8 characters"
            });
        }

        const existingUser = users.find(
            user => user.username === username
        );

        if (existingUser) {
            return res.status(409).json({
                message: "Username already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        users.push({
            username,
            password: hashedPassword
        });

        return res.status(201).json({
            message: "Registration successful"
        });

    } catch (error) {
        return res.status(500).json({
            message: "Registration failed"
        });
    }
});

// Login
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password are required"
            });
        }

        const user = users.find(
            item => item.username === username
        );

        if (!user) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        const passwordMatches = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatches) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        req.session.user = {
            username: user.username
        };

        return res.status(200).json({
            message: "Login successful"
        });

    } catch (error) {
        return res.status(500).json({
            message: "Login failed"
        });
    }
});

// Authentication middleware
function authenticate(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            message: "Unauthorized. Please login first."
        });
    }

    next();
}

// Dashboard
app.get("/dashboard", authenticate, (req, res) => {
    res.status(200).json({
        message: "Welcome to dashboard",
        username: req.session.user.username
    });
});

// Logout
app.post("/logout", (req, res) => {
    req.session.destroy(error => {
        if (error) {
            return res.status(500).json({
                message: "Logout failed"
            });
        }

        res.clearCookie("connect.sid");

        return res.status(200).json({
            message: "Logout successful"
        });
    });
});

// Health check
app.get("/health", (req, res) => {
    res.status(200).json({
        status: "OK"
    });
});

// Start server only when running directly.
// This allows Supertest to import the Express app.
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });
}

module.exports = app;
