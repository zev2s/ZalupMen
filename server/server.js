const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// =========================================================
// ENV
// =========================================================

require("dotenv").config({
    path: path.resolve(__dirname, "..", ".env"),
    override: true
});

const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const nodemailer = require("nodemailer");
console.log("");
console.log("========== SMTP DEBUG ==========");

console.log("Файл server.js:", __filename);

console.log(
    "ENV:",
    require("path").resolve(__dirname, "..", ".env")
);

console.log(
    "SMTP_SERVICE:",
    process.env.SMTP_SERVICE || "(пусто)"
);

console.log(
    "SMTP_USER:",
    process.env.SMTP_USER || "(пусто)"
);

console.log(
    "SMTP_PASS:",
    process.env.SMTP_PASS ? "ЕСТЬ" : "НЕТ"
);

console.log(
    "SMTP_FROM:",
    process.env.SMTP_FROM || "(пусто)"
);

console.log("================================");
console.log("");

const app = express();
const PORT = process.env.PORT || 3000;

const ROOT = __dirname;
const DB_FILE = path.join(ROOT, "myapp.db");

const UPLOADS_DIR = path.join(ROOT, "uploads");
const IMAGE_DIR = path.join(UPLOADS_DIR, "images");
const VIDEO_DIR = path.join(UPLOADS_DIR, "videos");
const AUDIO_DIR = path.join(UPLOADS_DIR, "audio");

for (const dir of [
    UPLOADS_DIR,
    IMAGE_DIR,
    VIDEO_DIR,
    AUDIO_DIR
]) {
    fs.mkdirSync(dir, {
        recursive: true
    });
}

app.use(cors());

app.use(express.json({
    limit: "20mb"
}));

app.use(express.urlencoded({
    extended: true
}));

app.use(
    "/uploads",
    express.static(UPLOADS_DIR)
);

const db = new Database(DB_FILE);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");


/* =========================================================
   HELPERS
========================================================= */

function ensureColumn(table, column, definition) {
    const columns = db
        .prepare(`PRAGMA table_info(${table})`)
        .all();

    if (!columns.some(c => c.name === column)) {
        db.prepare(`
            ALTER TABLE ${table}
            ADD COLUMN ${column} ${definition}
        `).run();
    }
}


/* =========================================================
   TABLES
========================================================= */

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        username_lower TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        avatar TEXT DEFAULT '',
        title TEXT DEFAULT '',
        custom_title TEXT DEFAULT '',
        description TEXT DEFAULT '',
        accent TEXT DEFAULT '#8b5cf6',
        title_color TEXT DEFAULT '#ffffff',
        avatar_color TEXT DEFAULT '#8b5cf6',
        verified INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        text TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blocker_id INTEGER NOT NULL,
        blocked_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(blocker_id, blocked_id),
        FOREIGN KEY(blocker_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(blocked_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts INTEGER DEFAULT 0,
        used INTEGER DEFAULT 0,
        reset_token_hash TEXT DEFAULT '',
        reset_token_expires_at INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT (strftime('%s','now')),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
`);


/* =========================================================
   MIGRATIONS
========================================================= */

const userColumns = [
    ["avatar", "TEXT DEFAULT ''"],
    ["title", "TEXT DEFAULT ''"],
    ["custom_title", "TEXT DEFAULT ''"],
    ["description", "TEXT DEFAULT ''"],
    ["accent", "TEXT DEFAULT '#8b5cf6'"],
    ["title_color", "TEXT DEFAULT '#ffffff'"],
    ["avatar_color", "TEXT DEFAULT '#8b5cf6'"],
    ["verified", "INTEGER DEFAULT 0"],
    ["created_at", "TEXT DEFAULT CURRENT_TIMESTAMP"],
    ["last_seen", "TEXT DEFAULT CURRENT_TIMESTAMP"]
];

for (const [name, definition] of userColumns) {
    ensureColumn(
        "users",
        name,
        definition
    );
}

const messageColumns = [
    ["message_type", "TEXT DEFAULT 'text'"],
    ["media_url", "TEXT DEFAULT ''"],
    ["media_name", "TEXT DEFAULT ''"],
    ["media_size", "INTEGER DEFAULT 0"],
    ["mime_type", "TEXT DEFAULT ''"],
    ["deleted_for_sender", "INTEGER DEFAULT 0"],
    ["deleted_for_receiver", "INTEGER DEFAULT 0"],
    ["deleted_for_all", "INTEGER DEFAULT 0"],
    ["read_at", "TEXT DEFAULT NULL"]
];

for (const [name, definition] of messageColumns) {
    ensureColumn(
        "messages",
        name,
        definition
    );
}

const resetColumns = [
    ["reset_token_hash", "TEXT DEFAULT ''"],
    ["reset_token_expires_at", "INTEGER DEFAULT 0"]
];

for (const [name, definition] of resetColumns) {
    ensureColumn(
        "password_resets",
        name,
        definition
    );
}


/* =========================================================
   SESSIONS
========================================================= */

const sessions = new Map();

function createToken(userId) {
    const token =
        crypto.randomBytes(32).toString("hex");

    sessions.set(token, {
        userId: Number(userId),
        createdAt: Date.now()
    });

    return token;
}

function getUserFromToken(token) {
    if (!token) {
        return null;
    }

    const session =
        sessions.get(token);

    if (!session) {
        return null;
    }

    const user =
        db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(session.userId);

    return user || null;
}

function auth(req, res, next) {
    const header =
        req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Не авторизован"
        });
    }

    const token =
        header.substring(7);

    const user =
        getUserFromToken(token);

    if (!user) {
        return res.status(401).json({
            error: "Сессия истекла"
        });
    }

    req.token = token;
    req.user = user;

    db.prepare(`
        UPDATE users
        SET last_seen = CURRENT_TIMESTAMP
        WHERE id = ?
    `).run(user.id);

    next();
}


/* =========================================================
   SETTINGS
========================================================= */

const VERIFICATION_ADMIN_EMAIL =
    "guranexx2@gmail.com";

const RESERVED_TITLES = [
    "owner",
    "admin",
    "administrator",
    "moderator",
    "mod",
    "staff",
    "developer",
    "dev",
    "founder",
    "co-owner",
    "coowner",
    "manager",
    "support",
    "official",
    "system",
    "root",
    "владелец",
    "админ",
    "администратор",
    "модератор",
    "мод",
    "сотрудник",
    "разработчик",
    "разраб",
    "основатель",
    "создатель",
    "поддержка",
    "официальный",
    "система"
];


/* =========================================================
   SMTP — ИСПРАВЛЕННАЯ ВЕРСИЯ
========================================================= */

const SMTP_SERVICE =
    String(
        process.env.SMTP_SERVICE || ""
    ).trim();

const SMTP_HOST =
    String(
        process.env.SMTP_HOST || ""
    ).trim();

const SMTP_PORT =
    Number(
        process.env.SMTP_PORT || 465
    );

const SMTP_USER =
    String(
        process.env.SMTP_USER || ""
    ).trim();

const SMTP_PASS =
    String(
        process.env.SMTP_PASS || ""
    ).trim();

const SMTP_FROM =
    String(
        process.env.SMTP_FROM ||
        SMTP_USER
    ).trim();

let mailer = null;

console.log("");
console.log("========== SMTP ==========");
console.log(
    "ENV FILE:",
    path.resolve(
        __dirname,
        "..",
        ".env"
    )
);
console.log(
    "SMTP_SERVICE:",
    SMTP_SERVICE || "(пусто)"
);
console.log(
    "SMTP_USER:",
    SMTP_USER || "(пусто)"
);
console.log(
    "SMTP_PASS:",
    SMTP_PASS
        ? "ЕСТЬ"
        : "НЕТ"
);
console.log(
    "SMTP_FROM:",
    SMTP_FROM || "(пусто)"
);

if (
    SMTP_USER &&
    SMTP_PASS
) {
    try {
        mailer =
            nodemailer.createTransport({
                host:
                    SMTP_HOST ||
                    "smtp.gmail.com",

                port:
                    SMTP_PORT || 465,

                secure:
                    (SMTP_PORT || 465) === 465,

                auth: {
                    user:
                        SMTP_USER,

                    pass:
                        SMTP_PASS
                }
            });

        console.log(
            "SMTP TRANSPORT СОЗДАН ✓"
        );

    } catch (error) {
        console.error(
            "SMTP INITIALIZATION ERROR:"
        );

        console.error(
            error
        );

        mailer = null;
    }
} else {
    console.error(
        "SMTP НЕ СОЗДАН ✗"
    );

    console.error(
        "Проверь .env"
    );
}

console.log(
    "=========================="
);
console.log("");


/* =========================================================
   GENERAL HELPERS
========================================================= */

function normalizeTitle(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}

function isReservedTitle(value) {
    const title =
        normalizeTitle(value);

    if (!title) {
        return false;
    }

    return RESERVED_TITLES.some(
        item =>
            title === item ||
            title.includes(item)
    );
}

function publicUser(user) {
    if (!user) {
        return null;
    }

    let online = false;

    if (user.last_seen) {
        const timestamp =
            new Date(
                user.last_seen.replace(
                    " ",
                    "T"
                ) + "Z"
            ).getTime();

        if (!Number.isNaN(timestamp)) {
            online =
                Date.now() -
                timestamp <
                120000;
        }
    }

    return {
        id: user.id,
        username: user.username,
        email: user.email,
        avatar: user.avatar || "",
        title: user.title || "",
        custom_title:
            user.custom_title || "",
        description:
            user.description || "",
        accent:
            user.accent ||
            "#8b5cf6",
        title_color:
            user.title_color ||
            "#ffffff",
        avatar_color:
            user.avatar_color ||
            "#8b5cf6",
        verified:
            Boolean(user.verified),
        online
    };
}

function getBlockStatus(a, b) {
    const row =
        db.prepare(`
            SELECT
                EXISTS(
                    SELECT 1
                    FROM blocks
                    WHERE blocker_id = ?
                    AND blocked_id = ?
                ) AS blocked_by_me,

                EXISTS(
                    SELECT 1
                    FROM blocks
                    WHERE blocker_id = ?
                    AND blocked_id = ?
                ) AS blocked_me
        `).get(
            a,
            b,
            b,
            a
        );

    return {
        blocked_by_me:
            Boolean(
                row.blocked_by_me
            ),

        blocked_me:
            Boolean(
                row.blocked_me
            )
    };
}

function canTalk(a, b) {
    const status =
        getBlockStatus(a, b);

    return (
        !status.blocked_by_me &&
        !status.blocked_me
    );
}

function deleteUploadedFile(filePath) {
    if (!filePath) {
        return;
    }

    try {
        if (
            fs.existsSync(filePath)
        ) {
            fs.unlinkSync(filePath);
        }
    } catch (error) {
        console.error(
            "FILE DELETE ERROR:",
            error
        );
    }
}


/* =========================================================
   PASSWORD RESET HELPERS
========================================================= */

function generateResetCode() {
    return String(
        crypto.randomInt(
            100000,
            1000000
        )
    );
}

function hashResetCode(code) {
    return crypto
        .createHash("sha256")
        .update(String(code))
        .digest("hex");
}

function createResetToken() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

function hashResetToken(token) {
    return crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");
}

function escapeHtml(value) {
    return String(value || "")
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}

/* =========================================================
   GENERAL HELPERS
========================================================= */

function normalizeTitle(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}

function isReservedTitle(value) {
    const title = normalizeTitle(value);

    if (!title) {
        return false;
    }

    return RESERVED_TITLES.some(item =>
        title === item ||
        title.includes(item)
    );
}

function publicUser(user) {
    if (!user) {
        return null;
    }

    let online = false;

    if (user.last_seen) {
        const timestamp =
            new Date(
                user.last_seen.replace(
                    " ",
                    "T"
                ) + "Z"
            ).getTime();

        if (!Number.isNaN(timestamp)) {
            online =
                Date.now() - timestamp <
                120000;
        }
    }

    return {
        id: user.id,
        username: user.username,
        email: user.email,
        avatar: user.avatar || "",
        title: user.title || "",
        custom_title:
            user.custom_title || "",
        description:
            user.description || "",
        accent:
            user.accent || "#8b5cf6",
        title_color:
            user.title_color || "#ffffff",
        avatar_color:
            user.avatar_color ||
            "#8b5cf6",
        verified:
            Boolean(user.verified),
        online
    };
}

function getBlockStatus(a, b) {
    const row = db.prepare(`
        SELECT
            EXISTS(
                SELECT 1
                FROM blocks
                WHERE blocker_id = ?
                AND blocked_id = ?
            ) AS blocked_by_me,

            EXISTS(
                SELECT 1
                FROM blocks
                WHERE blocker_id = ?
                AND blocked_id = ?
            ) AS blocked_me
    `).get(
        a,
        b,
        b,
        a
    );

    return {
        blocked_by_me:
            Boolean(row.blocked_by_me),

        blocked_me:
            Boolean(row.blocked_me)
    };
}

function canTalk(a, b) {
    const status =
        getBlockStatus(a, b);

    return (
        !status.blocked_by_me &&
        !status.blocked_me
    );
}

function deleteUploadedFile(filePath) {
    if (!filePath) {
        return;
    }

    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    } catch (error) {
        console.error(
            "FILE DELETE ERROR:",
            error
        );
    }
}


/* =========================================================
   PASSWORD RESET HELPERS
========================================================= */

function generateResetCode() {
    return String(
        crypto.randomInt(
            100000,
            1000000
        )
    );
}

function hashResetCode(code) {
    return crypto
        .createHash("sha256")
        .update(String(code))
        .digest("hex");
}

function createResetToken() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

function hashResetToken(token) {
    return crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");
}

function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* =========================================================
   HEALTH
========================================================= */

app.get("/", (req, res) => {
    res.json({
        success: true,
        app: "ZalupMen",
        server: "online"
    });
});


/* =========================================================
   REGISTER
========================================================= */

app.post("/register", (req, res) => {
    try {
        const username =
            String(
                req.body.username || ""
            ).trim();

        const email =
            String(
                req.body.email || ""
            )
                .trim()
                .toLowerCase();

        const password =
            String(
                req.body.password || ""
            );

        if (!username || !email || !password) {
            return res.status(400).json({
                error: "Заполни все поля"
            });
        }

        if (
            username.length < 3 ||
            username.length > 32
        ) {
            return res.status(400).json({
                error:
                    "Ник должен содержать от 3 до 32 символов"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error:
                    "Пароль должен содержать минимум 6 символов"
            });
        }

        if (
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                email
            )
        ) {
            return res.status(400).json({
                error: "Неверный email"
            });
        }

        const usernameLower =
            username.toLowerCase();

        const existing = db.prepare(`
            SELECT id
            FROM users
            WHERE username_lower = ?
               OR lower(email) = ?
        `).get(
            usernameLower,
            email
        );

        if (existing) {
            return res.status(409).json({
                error:
                    "Пользователь или email уже существует"
            });
        }

        const passwordHash =
            bcrypt.hashSync(
                password,
                12
            );

        const result = db.prepare(`
            INSERT INTO users
            (
                username,
                username_lower,
                email,
                password_hash
            )
            VALUES (?, ?, ?, ?)
        `).run(
            username,
            usernameLower,
            email,
            passwordHash
        );

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(
            result.lastInsertRowid
        );

        const token =
            createToken(user.id);

        res.json({
            success: true,
            token,
            user: publicUser(user)
        });

    } catch (error) {
        console.error(
            "REGISTER ERROR:",
            error
        );

        res.status(500).json({
            error:
                "Ошибка регистрации"
        });
    }
});


/* =========================================================
   LOGIN
========================================================= */

app.post("/login", (req, res) => {
    try {
        const login =
            String(
                req.body.login || ""
            ).trim();

        const password =
            String(
                req.body.password || ""
            );

        if (!login || !password) {
            return res.status(400).json({
                error:
                    "Введите логин и пароль"
            });
        }

        const loginLower =
            login.toLowerCase();

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE username_lower = ?
               OR lower(email) = ?
            LIMIT 1
        `).get(
            loginLower,
            loginLower
        );

        console.log("LOGIN USER CHECK:", {
            login,
            found: !!user,
            userId: user ? user.id : null,
            username: user ? user.username : null,
            email: user ? user.email : null,
            hasPasswordHash: !!(user && user.password_hash),
            passwordHashLength: user && user.password_hash
                ? user.password_hash.length
                : 0
        });

        if (!user) {
            return res.status(401).json({
                error:
                    "Неверный логин или пароль"
            });
        }

        let valid = false;

        try {
            valid =
                bcrypt.compareSync(
                    password,
                    user.password_hash
                );
        } catch (error) {
            console.error(
                "PASSWORD CHECK ERROR:",
                error
            );
        }

        if (!valid) {
            return res.status(401).json({
                error:
                    "Неверный логин или пароль"
            });
        }

        db.prepare(`
            UPDATE users
            SET last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(user.id);

        const token =
            createToken(user.id);

        res.json({
            success: true,
            token,
            user: publicUser(user)
        });

    } catch (error) {
        console.error(
            "LOGIN ERROR:",
            error
        );

        res.status(500).json({
            error:
                "Ошибка входа"
        });
    }
});


/* =========================================================
   LOGOUT
========================================================= */

app.post("/logout", auth, (req, res) => {
    sessions.delete(req.token);

    res.json({
        success: true
    });
});


/* =========================================================
   ME
========================================================= */

app.get("/me", auth, (req, res) => {
    res.json({
        success: true,
        user: publicUser(req.user)
    });
});


/* =========================================================
   PROFILE
========================================================= */

app.put("/me", auth, (req, res) => {
    try {
        const {
            username,
            title,
            custom_title,
            description,
            accent,
            title_color,
            avatar_color
        } = req.body;

        let newUsername =
            req.user.username;

        if (username !== undefined) {
            newUsername =
                String(username).trim();

            if (
                newUsername.length < 3 ||
                newUsername.length > 32
            ) {
                return res.status(400).json({
                    error:
                        "Ник должен содержать от 3 до 32 символов"
                });
            }

            const exists = db.prepare(`
                SELECT id
                FROM users
                WHERE username_lower = ?
                AND id != ?
            `).get(
                newUsername.toLowerCase(),
                req.user.id
            );

            if (exists) {
                return res.status(409).json({
                    error:
                        "Этот ник уже занят"
                });
            }
        }

        const newTitle =
            title !== undefined
                ? String(title).trim()
                : req.user.title || "";

        const newCustomTitle =
            custom_title !== undefined
                ? String(custom_title).trim()
                : req.user.custom_title || "";

        const isAdmin =
            String(req.user.email)
                .toLowerCase() ===
            VERIFICATION_ADMIN_EMAIL.toLowerCase();

        if (
            !isAdmin &&
            (
                isReservedTitle(newTitle) ||
                isReservedTitle(newCustomTitle)
            )
        ) {
            return res.status(400).json({
                error:
                    "Это название зарезервировано администрацией"
            });
        }

        db.prepare(`
            UPDATE users
            SET
                username = ?,
                username_lower = ?,
                title = ?,
                custom_title = ?,
                description = ?,
                accent = ?,
                title_color = ?,
                avatar_color = ?
            WHERE id = ?
        `).run(
            newUsername,
            newUsername.toLowerCase(),
            newTitle,
            newCustomTitle,
            description !== undefined
                ? String(description).slice(0, 500)
                : req.user.description || "",
            accent ||
                req.user.accent ||
                "#8b5cf6",
            title_color ||
                req.user.title_color ||
                "#ffffff",
            avatar_color ||
                req.user.avatar_color ||
                "#8b5cf6",
            req.user.id
        );

        const updated = db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(req.user.id);

        res.json({
            success: true,
            user: publicUser(updated)
        });

    } catch (error) {
        console.error(
            "PROFILE UPDATE ERROR:",
            error
        );

        res.status(500).json({
            error:
                "Не удалось сохранить профиль"
        });
    }
});


/* =========================================================
   AVATAR
========================================================= */

app.put("/me/avatar", auth, (req, res) => {
    try {
        const avatar =
            String(
                req.body.avatar || ""
            );

        if (avatar.length > 2_000_000) {
            return res.status(400).json({
                error:
                    "Аватар слишком большой"
            });
        }

        db.prepare(`
            UPDATE users
            SET avatar = ?
            WHERE id = ?
        `).run(
            avatar,
            req.user.id
        );

        const updated = db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(req.user.id);

        res.json({
            success: true,
            user: publicUser(updated)
        });

    } catch (error) {
        console.error(
            "AVATAR ERROR:",
            error
        );

        res.status(500).json({
            error:
                "Не удалось сохранить аватар"
        });
    }
});


/* =========================================================
   USERS
========================================================= */

app.get("/users", auth, (req, res) => {
    try {
        const search =
            String(
                req.query.search || ""
            )
                .trim()
                .toLowerCase();

        let users;

        if (search) {
            users = db.prepare(`
                SELECT *
                FROM users
                WHERE id != ?
                AND (
                    lower(username) LIKE ?
                    OR lower(email) LIKE ?
                )
                ORDER BY username COLLATE NOCASE
                LIMIT 100
            `).all(
                req.user.id,
                `%${search}%`,
                `%${search}%`
            );
        } else {
            users = db.prepare(`
                SELECT *
                FROM users
                WHERE id != ?
                ORDER BY username COLLATE NOCASE
                LIMIT 100
            `).all(
                req.user.id
            );
        }

        res.json({
            success: true,
            users:
                users.map(publicUser)
        });

    } catch (error) {
        console.error(
            "USERS ERROR:",
            error
        );

        res.status(500).json({
            error:
                "Не удалось получить пользователей"
        });
    }
});


/* =========================================================
   USER PROFILE
========================================================= */

app.get(
    "/users/:id/profile",
    auth,
    (req, res) => {
        const id =
            Number(req.params.id);

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(id);

        if (!user) {
            return res.status(404).json({
                error:
                    "Пользователь не найден"
            });
        }

        res.json({
            success: true,
            user: publicUser(user),
            block:
                getBlockStatus(
                    req.user.id,
                    id
                )
        });
    }
);


/* =========================================================
   BLOCK
========================================================= */

app.post(
    "/users/:id/block",
    auth,
    (req, res) => {
        const id =
            Number(req.params.id);

        if (id === req.user.id) {
            return res.status(400).json({
                error:
                    "Нельзя заблокировать себя"
            });
        }

        const user = db.prepare(`
            SELECT id
            FROM users
            WHERE id = ?
        `).get(id);

        if (!user) {
            return res.status(404).json({
                error:
                    "Пользователь не найден"
            });
        }

        db.prepare(`
            INSERT OR IGNORE INTO blocks
            (
                blocker_id,
                blocked_id
            )
            VALUES (?, ?)
        `).run(
            req.user.id,
            id
        );

        res.json({
            success: true
        });
    }
);

app.delete(
    "/users/:id/block",
    auth,
    (req, res) => {
        const id =
            Number(req.params.id);

        db.prepare(`
            DELETE FROM blocks
            WHERE blocker_id = ?
            AND blocked_id = ?
        `).run(
            req.user.id,
            id
        );

        res.json({
            success: true
        });
    }
);

app.get(
    "/users/:id/block-status",
    auth,
    (req, res) => {
        const id =
            Number(req.params.id);

        res.json({
            success: true,
            block:
                getBlockStatus(
                    req.user.id,
                    id
                )
        });
    }
);


/* =========================================================
   CONVERSATIONS
========================================================= */

app.get(
    "/conversations",
    auth,
    (req, res) => {
        try {
            const rows = db.prepare(`
                SELECT
                    u.*,

                    m.id AS last_message_id,
                    m.text AS last_message_text,
                    m.message_type AS last_message_type,
                    m.media_url AS last_media_url,
                    m.media_name AS last_media_name,
                    m.created_at AS last_message_created_at,
                    m.sender_id AS last_message_sender_id

                FROM users u

                JOIN messages m
                ON m.id = (
                    SELECT m2.id
                    FROM messages m2
                    WHERE
                    (
                        (
                            m2.sender_id = ?
                            AND m2.receiver_id = u.id
                        )
                        OR
                        (
                            m2.sender_id = u.id
                            AND m2.receiver_id = ?
                        )
                    )

                    AND m2.deleted_for_all = 0

                    ORDER BY m2.id DESC
                    LIMIT 1
                )

                WHERE u.id != ?

                ORDER BY m.created_at DESC
            `).all(
                req.user.id,
                req.user.id,
                req.user.id
            );

            const conversations =
                rows.map(row => ({
                    user:
                        publicUser(row),

                    lastMessage: {
                        id:
                            row.last_message_id,

                        text:
                            row.last_message_text || "",

                        type:
                            row.last_message_type || "text",

                        media_url:
                            row.last_media_url || "",

                        media_name:
                            row.last_media_name || "",

                        created_at:
                            row.last_message_created_at,

                        sender_id:
                            row.last_message_sender_id
                    }
                }));

            res.json({
                success: true,
                conversations
            });

        } catch (error) {
            console.error(
                "CONVERSATIONS ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Не удалось получить чаты"
            });
        }
    }
);


/* =========================================================
   GET MESSAGES
========================================================= */

app.get(
    "/messages/:userId",
    auth,
    (req, res) => {
        try {
            const otherUserId =
                Number(req.params.userId);

            const rows = db.prepare(`
                SELECT *
                FROM messages
                WHERE
                (
                    (
                        sender_id = ?
                        AND receiver_id = ?
                    )
                    OR
                    (
                        sender_id = ?
                        AND receiver_id = ?
                    )
                )

                AND deleted_for_all = 0

                AND
                (
                    (
                        sender_id = ?
                        AND deleted_for_sender = 0
                    )
                    OR
                    (
                        receiver_id = ?
                        AND deleted_for_receiver = 0
                    )
                )

                ORDER BY id ASC
            `).all(
                req.user.id,
                otherUserId,
                otherUserId,
                req.user.id,
                req.user.id,
                req.user.id
            );

            res.json({
                success: true,
                messages: rows
            });

        } catch (error) {
            console.error(
                "MESSAGES ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Не удалось получить сообщения"
            });
        }
    }
);


/* =========================================================
   SEND TEXT
========================================================= */

app.post(
    "/messages",
    auth,
    (req, res) => {
        try {
            const receiverId =
                Number(
                    req.body.receiver_id
                );

            const text =
                String(
                    req.body.text ??
                    req.body.content ??
                    ""
                ).trim();

            if (!receiverId) {
                return res.status(400).json({
                    error:
                        "Не указан получатель"
                });
            }

            if (!text) {
                return res.status(400).json({
                    error:
                        "Сообщение пустое"
                });
            }

            if (text.length > 5000) {
                return res.status(400).json({
                    error:
                        "Сообщение слишком длинное"
                });
            }

            if (
                receiverId ===
                req.user.id
            ) {
                return res.status(400).json({
                    error:
                        "Нельзя отправить сообщение самому себе"
                });
            }

            const receiver = db.prepare(`
                SELECT id
                FROM users
                WHERE id = ?
            `).get(receiverId);

            if (!receiver) {
                return res.status(404).json({
                    error:
                        "Пользователь не найден"
                });
            }

            if (
                !canTalk(
                    req.user.id,
                    receiverId
                )
            ) {
                return res.status(403).json({
                    error:
                        "Нельзя отправить сообщение этому пользователю"
                });
            }

            const result = db.prepare(`
                INSERT INTO messages
                (
                    sender_id,
                    receiver_id,
                    text,
                    message_type
                )
                VALUES (?, ?, ?, 'text')
            `).run(
                req.user.id,
                receiverId,
                text
            );

            const message = db.prepare(`
                SELECT *
                FROM messages
                WHERE id = ?
            `).get(
                result.lastInsertRowid
            );

            res.json({
                success: true,
                message
            });

        } catch (error) {
            console.error(
                "SEND MESSAGE ERROR:",
                error
            );

            res.status(500).json({
                error:
                    error.message ||
                    "Не удалось отправить сообщение"
            });
        }
    }
);


/* =========================================================
   READ
========================================================= */

app.post(
    "/messages/:userId/read",
    auth,
    (req, res) => {
        const otherUserId =
            Number(req.params.userId);

        db.prepare(`
            UPDATE messages
            SET read_at = CURRENT_TIMESTAMP
            WHERE sender_id = ?
            AND receiver_id = ?
            AND read_at IS NULL
        `).run(
            otherUserId,
            req.user.id
        );

        res.json({
            success: true
        });
    }
);


/* =========================================================
   MEDIA
========================================================= */

const storage =
    multer.diskStorage({
        destination:
            (req, file, cb) => {
                if (
                    file.mimetype.startsWith(
                        "image/"
                    )
                ) {
                    cb(
                        null,
                        IMAGE_DIR
                    );
                } else if (
                    file.mimetype.startsWith(
                        "video/"
                    )
                ) {
                    cb(
                        null,
                        VIDEO_DIR
                    );
                } else if (
                    file.mimetype.startsWith(
                        "audio/"
                    )
                ) {
                    cb(
                        null,
                        AUDIO_DIR
                    );
                } else {
                    cb(
                        new Error(
                            "Неподдерживаемый файл"
                        )
                    );
                }
            },

        filename:
            (req, file, cb) => {
                let ext =
                    path.extname(
                        file.originalname
                    );

                if (!ext) {
                    if (
                        file.mimetype ===
                        "audio/webm"
                    ) {
                        ext = ".webm";
                    } else if (
                        file.mimetype ===
                        "audio/ogg"
                    ) {
                        ext = ".ogg";
                    } else if (
                        file.mimetype ===
                        "audio/mpeg"
                    ) {
                        ext = ".mp3";
                    }
                }

                const name =
                    Date.now() +
                    "_" +
                    crypto
                        .randomBytes(8)
                        .toString("hex") +
                    ext;

                cb(null, name);
            }
    });

const upload =
    multer({
        storage,

        limits: {
            fileSize:
                50 * 1024 * 1024
        },

        fileFilter:
            (req, file, cb) => {
                if (
                    file.mimetype.startsWith(
                        "image/"
                    ) ||
                    file.mimetype.startsWith(
                        "video/"
                    ) ||
                    file.mimetype.startsWith(
                        "audio/"
                    )
                ) {
                    cb(null, true);
                } else {
                    cb(
                        new Error(
                            "Разрешены только изображения, видео и аудио"
                        )
                    );
                }
            }
    });

app.post(
    "/messages/media",
    auth,
    (req, res) => {
        upload.single("file")(
            req,
            res,
            error => {
                if (error) {
                    console.error(
                        "UPLOAD ERROR:",
                        error
                    );

                    return res.status(400).json({
                        error:
                            error.message ||
                            "Не удалось загрузить файл"
                    });
                }

                try {
                    const receiverId =
                        Number(
                            req.body.receiver_id
                        );

                    if (!receiverId) {
                        deleteUploadedFile(
                            req.file?.path
                        );

                        return res.status(400).json({
                            error:
                                "Не указан получатель"
                        });
                    }

                    if (!req.file) {
                        return res.status(400).json({
                            error:
                                "Файл не выбран"
                        });
                    }

                    if (
                        receiverId ===
                        req.user.id
                    ) {
                        deleteUploadedFile(
                            req.file.path
                        );

                        return res.status(400).json({
                            error:
                                "Нельзя отправить файл самому себе"
                        });
                    }

                    const receiver =
                        db.prepare(`
                            SELECT id
                            FROM users
                            WHERE id = ?
                        `).get(receiverId);

                    if (!receiver) {
                        deleteUploadedFile(
                            req.file.path
                        );

                        return res.status(404).json({
                            error:
                                "Пользователь не найден"
                        });
                    }

                    if (
                        !canTalk(
                            req.user.id,
                            receiverId
                        )
                    ) {
                        deleteUploadedFile(
                            req.file.path
                        );

                        return res.status(403).json({
                            error:
                                "Нельзя отправить сообщение этому пользователю"
                        });
                    }

                    let type = "file";
                    let folder = "";

                    if (
                        req.file.mimetype.startsWith(
                            "image/"
                        )
                    ) {
                        type = "image";
                        folder = "images";
                    } else if (
                        req.file.mimetype.startsWith(
                            "video/"
                        )
                    ) {
                        type = "video";
                        folder = "videos";
                    } else if (
                        req.file.mimetype.startsWith(
                            "audio/"
                        )
                    ) {
                        type = "audio";
                        folder = "audio";
                    }

                    const mediaUrl =
                        `/uploads/${folder}/${req.file.filename}`;

                    const result =
                        db.prepare(`
                            INSERT INTO messages
                            (
                                sender_id,
                                receiver_id,
                                text,
                                message_type,
                                media_url,
                                media_name,
                                media_size,
                                mime_type
                            )
                            VALUES
                            (?, ?, '', ?, ?, ?, ?, ?)
                        `).run(
                            req.user.id,
                            receiverId,
                            type,
                            mediaUrl,
                            req.file.originalname,
                            req.file.size,
                            req.file.mimetype
                        );

                    const message =
                        db.prepare(`
                            SELECT *
                            FROM messages
                            WHERE id = ?
                        `).get(
                            result.lastInsertRowid
                        );

                    res.json({
                        success: true,
                        message
                    });

                } catch (error) {
                    console.error(
                        "MEDIA ERROR:",
                        error
                    );

                    deleteUploadedFile(
                        req.file?.path
                    );

                    res.status(500).json({
                        error:
                            error.message ||
                            "Не удалось отправить файл"
                    });
                }
            }
        );
    }
);


/* =========================================================
   DELETE MESSAGE
========================================================= */

app.delete(
    "/messages/:id",
    auth,
    (req, res) => {
        try {
            const messageId =
                Number(req.params.id);

            const message =
                db.prepare(`
                    SELECT *
                    FROM messages
                    WHERE id = ?
                `).get(messageId);

            if (!message) {
                return res.status(404).json({
                    error:
                        "Сообщение не найдено"
                });
            }

            if (
                message.sender_id !==
                    req.user.id &&
                message.receiver_id !==
                    req.user.id
            ) {
                return res.status(403).json({
                    error:
                        "Нет доступа"
                });
            }

            if (
                message.sender_id ===
                req.user.id
            ) {
                db.prepare(`
                    UPDATE messages
                    SET deleted_for_sender = 1
                    WHERE id = ?
                `).run(messageId);
            } else {
                db.prepare(`
                    UPDATE messages
                    SET deleted_for_receiver = 1
                    WHERE id = ?
                `).run(messageId);
            }

            res.json({
                success: true
            });

        } catch (error) {
            console.error(
                "DELETE MESSAGE ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Не удалось удалить сообщение"
            });
        }
    }
);


/* =========================================================
   DELETE FOR EVERYONE
========================================================= */

app.delete(
    "/messages/:id/everyone",
    auth,
    (req, res) => {
        try {
            const messageId =
                Number(req.params.id);

            const message =
                db.prepare(`
                    SELECT *
                    FROM messages
                    WHERE id = ?
                `).get(messageId);

            if (!message) {
                return res.status(404).json({
                    error:
                        "Сообщение не найдено"
                });
            }

            if (
                message.sender_id !==
                req.user.id
            ) {
                return res.status(403).json({
                    error:
                        "Удалять сообщение у всех может только отправитель"
                });
            }

            db.prepare(`
                UPDATE messages
                SET deleted_for_all = 1
                WHERE id = ?
            `).run(messageId);

            res.json({
                success: true
            });

        } catch (error) {
            console.error(
                "DELETE EVERYONE ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Не удалось удалить сообщение"
            });
        }
    }
);


/* =========================================================
   DELETE CHAT
========================================================= */

app.delete(
    "/conversations/:userId",
    auth,
    (req, res) => {
        try {
            const otherUserId =
                Number(req.params.userId);

            db.prepare(`
                UPDATE messages
                SET
                    deleted_for_sender =
                        CASE
                            WHEN sender_id = ?
                            THEN 1
                            ELSE deleted_for_sender
                        END,

                    deleted_for_receiver =
                        CASE
                            WHEN receiver_id = ?
                            THEN 1
                            ELSE deleted_for_receiver
                        END

                WHERE
                (
                    sender_id = ?
                    AND receiver_id = ?
                )
                OR
                (
                    sender_id = ?
                    AND receiver_id = ?
                )
            `).run(
                req.user.id,
                req.user.id,
                req.user.id,
                otherUserId,
                otherUserId,
                req.user.id
            );

            res.json({
                success: true
            });

        } catch (error) {
            console.error(
                "DELETE CHAT ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Не удалось удалить чат"
            });
        }
    }
);


/* =========================================================
   PASSWORD RESET
========================================================= */

/*
    Поддерживаются оба адреса:

    POST /forgot-password
    POST /forgot-password/request

    Это нужно для совместимости с текущим frontend.
*/

async function requestPasswordReset(req, res) {
    try {
        const email =
            String(
                req.body.email || ""
            )
                .trim()
                .toLowerCase();

        if (!email) {
            return res.status(400).json({
                error:
                    "Введите email"
            });
        }

        if (
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                email
            )
        ) {
            return res.status(400).json({
                error:
                    "Неверный email"
            });
        }

        if (!mailer) {
            console.error(
                "SMTP IS NOT CONFIGURED"
            );

            return res.status(500).json({
                error:
                    "Почтовая система не настроена на сервере"
            });
        }

        const user =
            db.prepare(`
                SELECT
                    id,
                    username,
                    email
                FROM users
                WHERE lower(email) = ?
                LIMIT 1
            `).get(email);

        if (!user) {
            return res.json({
                success: true,
                message:
                    "Если такой email зарегистрирован, код отправлен"
            });
        }

        /*
            Отключаем старые коды.
        */

        db.prepare(`
            UPDATE password_resets
            SET used = 1
            WHERE user_id = ?
            AND used = 0
        `).run(user.id);

        const code =
            generateResetCode();

        const codeHash =
            hashResetCode(code);

        const expiresAt =
            Date.now() +
            10 * 60 * 1000;

        db.prepare(`
            INSERT INTO password_resets
            (
                user_id,
                email,
                code_hash,
                expires_at,
                attempts,
                used,
                reset_token_hash,
                reset_token_expires_at
            )
            VALUES (?, ?, ?, ?, 0, 0, '', 0)
        `).run(
            user.id,
            user.email,
            codeHash,
            expiresAt
        );

        const safeUsername =
            escapeHtml(user.username);

        await mailer.sendMail({
            from: SMTP_FROM || SMTP_USER,

            to: user.email,

            subject:
                "ZalupMen — восстановление пароля",

            text:
                `Здравствуйте, ${user.username}!\n\n` +
                `Код для восстановления пароля: ${code}\n\n` +
                `Код действует 10 минут.\n\n` +
                `Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.\n\n` +
                `ZalupMen`,

            html: `
<!DOCTYPE html>
<html>
<body style="
    margin:0;
    padding:0;
    background:#0b0b0f;
    font-family:Arial,sans-serif;
">
    <div style="
        max-width:560px;
        margin:40px auto;
        background:#15131d;
        color:#ffffff;
        border-radius:20px;
        padding:35px;
    ">

        <h1 style="
            margin-top:0;
            color:#a78bfa;
        ">
            ZalupMen
        </h1>

        <p>
            Здравствуйте,
            <b>${safeUsername}</b>!
        </p>

        <p>
            Вы запросили восстановление
            пароля для своего аккаунта.
        </p>

        <p>
            Ваш код:
        </p>

        <div style="
            background:#211a35;
            border:1px solid #4c3b72;
            border-radius:15px;
            padding:22px;
            text-align:center;
            font-size:34px;
            font-weight:bold;
            letter-spacing:9px;
        ">
            ${code}
        </div>

        <p style="
            margin-top:25px;
            color:#bbbbc7;
        ">
            Код действует
            <b style="color:#ffffff">
                10 минут
            </b>.
        </p>

        <p style="
            color:#888894;
            font-size:13px;
        ">
            Если вы не запрашивали
            восстановление пароля,
            просто проигнорируйте это письмо.
        </p>

    </div>
</body>
</html>
`
        });

        console.log(
            `PASSWORD RESET CODE SENT TO: ${user.email}`
        );

        res.json({
            success: true,
            message:
                "Если такой email зарегистрирован, код отправлен"
        });

    } catch (error) {
        console.error(
            "FORGOT PASSWORD ERROR:",
            error
        );

        res.status(500).json({
            error:
                "Не удалось отправить код. Попробуйте позже."
        });
    }
}

app.post(
    "/forgot-password",
    requestPasswordReset
);

app.post(
    "/forgot-password/request",
    requestPasswordReset
);


/* =========================================================
   VERIFY RESET CODE
========================================================= */

app.post(
    "/forgot-password/verify",
    (req, res) => {
        try {
            const email =
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();

            const code =
                String(
                    req.body.code || ""
                ).trim();

            if (!email || !code) {
                return res.status(400).json({
                    error:
                        "Введите email и код"
                });
            }

            if (!/^\d{6}$/.test(code)) {
                return res.status(400).json({
                    error:
                        "Код должен содержать 6 цифр"
                });
            }

            const reset =
                db.prepare(`
                    SELECT *
                    FROM password_resets
                    WHERE lower(email) = ?
                    AND used = 0
                    ORDER BY id DESC
                    LIMIT 1
                `).get(email);

            if (!reset) {
                return res.status(400).json({
                    error:
                        "Код не найден или уже использован"
                });
            }

            if (
                Date.now() >
                reset.expires_at
            ) {
                db.prepare(`
                    UPDATE password_resets
                    SET used = 1
                    WHERE id = ?
                `).run(reset.id);

                return res.status(400).json({
                    error:
                        "Срок действия кода истёк"
                });
            }

            if (reset.attempts >= 5) {
                db.prepare(`
                    UPDATE password_resets
                    SET used = 1
                    WHERE id = ?
                `).run(reset.id);

                return res.status(429).json({
                    error:
                        "Слишком много неправильных попыток. Запросите новый код."
                });
            }

            const codeHash =
                hashResetCode(code);

            if (
                codeHash !==
                reset.code_hash
            ) {
                db.prepare(`
                    UPDATE password_resets
                    SET attempts = attempts + 1
                    WHERE id = ?
                `).run(reset.id);

                return res.status(400).json({
                    error:
                        "Неверный код"
                });
            }

            const resetToken =
                createResetToken();

            const resetTokenHash =
                hashResetToken(resetToken);

            /*
                Токен действует ещё 10 минут.
            */

            const resetTokenExpiresAt =
                Date.now() +
                10 * 60 * 1000;

            db.prepare(`
                UPDATE password_resets
                SET
                    reset_token_hash = ?,
                    reset_token_expires_at = ?
                WHERE id = ?
            `).run(
                resetTokenHash,
                resetTokenExpiresAt,
                reset.id
            );

            res.json({
                success: true,
                resetToken
            });

        } catch (error) {
            console.error(
                "VERIFY RESET ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Не удалось проверить код"
            });
        }
    }
);


/* =========================================================
   RESET PASSWORD
========================================================= */

app.post(
    "/forgot-password/reset",
    (req, res) => {
        try {
            const email =
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();

            const resetToken =
                String(
                    req.body.resetToken || ""
                ).trim();

            /*
                Поддерживаем оба варианта
                frontend:

                password
                newPassword
            */

            const newPassword =
                String(
                    req.body.newPassword ??
                    req.body.password ??
                    ""
                );

            if (
                !email ||
                !resetToken ||
                !newPassword
            ) {
                return res.status(400).json({
                    error:
                        "Не заполнены обязательные поля"
                });
            }

            if (newPassword.length < 6) {
                return res.status(400).json({
                    error:
                        "Новый пароль должен содержать минимум 6 символов"
                });
            }

            if (newPassword.length > 128) {
                return res.status(400).json({
                    error:
                        "Пароль слишком длинный"
                });
            }

            const tokenHash =
                hashResetToken(
                    resetToken
                );

            const reset =
                db.prepare(`
                    SELECT *
                    FROM password_resets
                    WHERE lower(email) = ?
                    AND reset_token_hash = ?
                    AND used = 0
                    ORDER BY id DESC
                    LIMIT 1
                `).get(
                    email,
                    tokenHash
                );

            if (!reset) {
                return res.status(400).json({
                    error:
                        "Сессия восстановления недействительна"
                });
            }

            if (
                !reset.reset_token_expires_at ||
                Date.now() >
                reset.reset_token_expires_at
            ) {
                db.prepare(`
                    UPDATE password_resets
                    SET used = 1
                    WHERE id = ?
                `).run(reset.id);

                return res.status(400).json({
                    error:
                        "Срок действия восстановления истёк"
                });
            }

            const passwordHash =
                bcrypt.hashSync(
                    newPassword,
                    12
                );

            db.prepare(`
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
            `).run(
                passwordHash,
                reset.user_id
            );

            /*
                Токен больше нельзя использовать.
            */

            db.prepare(`
                UPDATE password_resets
                SET
                    used = 1,
                    reset_token_hash = '',
                    reset_token_expires_at = 0
                WHERE id = ?
            `).run(reset.id);

            /*
                Завершаем все старые сессии.
            */

            for (
                const [
                    token,
                    session
                ] of sessions.entries()
            ) {
                if (
                    session.userId ===
                    reset.user_id
                ) {
                    sessions.delete(token);
                }
            }

            res.json({
                success: true,
                message:
                    "Пароль успешно изменён"
            });

        } catch (error) {
            console.error(
                "RESET PASSWORD ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Не удалось изменить пароль"
            });
        }
    }
);


/* =========================================================
   VERIFICATION
========================================================= */

app.get(
    "/verification/admin",
    auth,
    (req, res) => {
        const isAdmin =
            String(req.user.email)
                .toLowerCase() ===
            VERIFICATION_ADMIN_EMAIL.toLowerCase();

        if (!isAdmin) {
            return res.status(403).json({
                error:
                    "Нет доступа"
            });
        }

        const users =
            db.prepare(`
                SELECT *
                FROM users
                ORDER BY id DESC
            `).all();

        res.json({
            success: true,
            users:
                users.map(publicUser)
        });
    }
);

app.post(
    "/users/:id/verify",
    auth,
    (req, res) => {
        const isAdmin =
            String(req.user.email)
                .toLowerCase() ===
            VERIFICATION_ADMIN_EMAIL.toLowerCase();

        if (!isAdmin) {
            return res.status(403).json({
                error:
                    "Нет доступа"
            });
        }

        const id =
            Number(req.params.id);

        db.prepare(`
            UPDATE users
            SET verified = 1
            WHERE id = ?
        `).run(id);

        res.json({
            success: true
        });
    }
);

app.delete(
    "/users/:id/verify",
    auth,
    (req, res) => {
        const isAdmin =
            String(req.user.email)
                .toLowerCase() ===
            VERIFICATION_ADMIN_EMAIL.toLowerCase();

        if (!isAdmin) {
            return res.status(403).json({
                error:
                    "Нет доступа"
            });
        }

        const id =
            Number(req.params.id);

        db.prepare(`
            UPDATE users
            SET verified = 0
            WHERE id = ?
        `).run(id);

        res.json({
            success: true
        });
    }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {
        console.error(
            "SERVER ERROR:",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        res.status(500).json({
            error:
                error.message ||
                "Ошибка сервера"
        });
    }
);

/* =========================================================
   TEMPORARY DELETE ALL USERS
========================================================= */

app.get("/delete-all-users-9x7k2", (req, res) => {
    try {
        db.prepare("DELETE FROM messages").run();
        db.prepare("DELETE FROM blocks").run();
        db.prepare("DELETE FROM password_resets").run();
        db.prepare("DELETE FROM users").run();

        res.json({
            success: true,
            message: "Все аккаунты удалены"
        });

    } catch (error) {
        console.error(
            "DELETE ALL USERS ERROR:",
            error
        );

        res.status(500).json({
            error: "Ошибка удаления аккаунтов"
        });
    }
});

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    () => {
        console.log("");
        console.log(
            "================================"
        );
        console.log(
            "          ZalupMen Server"
        );
        console.log(
            "================================"
        );
        console.log("");

        console.log(
            "Сервер запущен:"
        );

        console.log(
            `http://localhost:${PORT}`
        );

        console.log("");

        console.log(
            "Медиа:"
        );

        console.log(
            `http://localhost:${PORT}/uploads/`
        );

        console.log("");

        console.log(
            "Восстановление пароля:"
        );

        console.log(
            mailer
                ? "SMTP настроен ✓"
                : "SMTP НЕ настроен ✗"
        );

        if (!mailer) {
            console.log("");
            console.log(
                "Проверь файл .env:"
            );
            console.log(
                "SMTP_SERVICE=gmail"
            );
            console.log(
                "SMTP_USER=твой_email@gmail.com"
            );
            console.log(
                "SMTP_PASS=пароль_приложения"
            );
            console.log(
                "SMTP_FROM=твой_email@gmail.com"
            );
        }

        console.log("");

        console.log(
            "================================"
        );
    }
);