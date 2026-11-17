
const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const initSqlJs = require("sql.js");
const fs = require("fs");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || "local-development-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax"
    }
}));

app.use(express.static(path.join(__dirname, "public")));

let db;

function saveDatabase() {
    const data = db.export();

    fs.writeFileSync(
        path.join(__dirname, "users.db"),
        Buffer.from(data)
    );
}

async function startApp() {

    const SQL = await initSqlJs();

    const dbPath = path.join(__dirname, "users.db");

    if (fs.existsSync(dbPath)) {
        db = new SQL.Database(
            new Uint8Array(fs.readFileSync(dbPath))
        );
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

    app.post("/register", async (req, res) => {
        try {
            const { username, password } = req.body;

            if (!username || !password || password.length < 8) {
                return res.status(400).send("Invalid registration details");
            }

            const hash = await bcrypt.hash(password, 12);

            db.run(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                [username, hash]
            );

            saveDatabase();

            res.status(201).send("Registration successful");

        } catch (error) {
            res.status(400).send("Registration failed");
        }
    });

    app.post("/login", async (req, res) => {
        const { username, password } = req.body;

        const result = db.exec(
            "SELECT id, password FROM users WHERE username = ?",
            [username]
        );

        if (!result.length || !result[0].values.length) {
            return res.status(401).send("Invalid username or password");
        }

        const [id, hashedPassword] = result[0].values[0];

        if (!(await bcrypt.compare(password, hashedPassword))) {
            return res.status(401).send("Invalid username or password");
        }

        req.session.userId = id;

        res.send("Login successful");
    });

    app.get("/dashboard", (req, res) => {
        if (!req.session.userId) {
            return res.status(401).send("Please login first");
        }

        res.send("Welcome to your dashboard!");
    });

    app.post("/logout", (req, res) => {
        req.session.destroy(() => {
            res.send("Logged out successfully");
        });
    });

    app.listen(3000, () => {
        console.log("Application running on port 3000");
    });
}

if (require.main === module) {
    startApp().catch(error => {
        console.error("Application startup failed:", error);
        process.exit(1);
    });
}

module.exports = { app };
