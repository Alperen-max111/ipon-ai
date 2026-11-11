
import path from "path";
import crypto from "crypto";
import { promisify } from "util";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import pg from "pg";

dotenv.config();

const { Pool } = pg;
const app = express();
app.set("trust proxy", 1);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DATABASE_URL = process.env.DATABASE_URL;

const scrypt = promisify(crypto.scrypt);

if (!GROQ_API_KEY) throw new Error("GROQ_API_KEY eksik!");
if (!ADMIN_PASSWORD) throw new Error("ADMIN_PASSWORD eksik!");
if (!DATABASE_URL) throw new Error("DATABASE_URL eksik!");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`);

await pool.query(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx
  ON users (LOWER(username))
`);

await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS chat_sharing_consent BOOLEAN NOT NULL DEFAULT FALSE
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS user_chat_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chat_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT 'Yeni Sohbet',
    messages JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, chat_id)
  )
`);

/* İNSAN DESTEKLİ SOHBET TABLOLARI */
await pool.query(`
  CREATE TABLE IF NOT EXISTS human_chat_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chat_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'active', 'closed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, chat_id)
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS human_chat_messages (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL
      REFERENCES human_chat_sessions(id) ON DELETE CASCADE,
    sender TEXT NOT NULL CHECK (sender IN ('user', 'host')),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`);

console.log("PostgreSQL bağlantısı hazır!");

app.use(cors());
app.use(express.json({ limit: "10mb" }));

app.use("/api/", rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
}));

app.use(express.static(__dirname));

const adminSessions = new Map();
const userSessions = new Map();

const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000;

const GOOD_MODE = `
Sen IPON AI isimli Türkçe konuşan bir yapay zekâ asistanısın.
Kibar, samimi, neşeli ve yardımsever ol.
Doğru bilgiler ver, bilmediğin şeyleri uydurma.
`;

const BAD_MODE = `
Sen IPON AI isimli bir yapay zekâ asistanısın.
KÖTÜ MODDASIN.
Türkçe konuş.
Asi, huysuz, sert ve eğlenceli bir karakter ol.
Bazen büyük harflerle tepki verebilirsin.
Şakacı şekilde laf sokabilirsin.
Tehdit etme, ağır hakaret etme veya kullanıcıyı aşağılama.
Yine de faydalı ve doğru cevaplar ver.
`;

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scrypt(password, salt, 64);
  return `${salt}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
  try {
    const [salt, key] = storedHash.split(":");
    if (!salt || !key) return false;

    const derivedKey = await scrypt(password, salt, 64);
    const storedKey = Buffer.from(key, "hex");

    return (
      storedKey.length === derivedKey.length &&
      crypto.timingSafeEqual(storedKey, derivedKey)
    );
  } catch {
    return false;
  }
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

async function getUserFromRequest(req) {
  const token = getBearerToken(req);
  if (!token) return null;

  const session = userSessions.get(token);

  if (!session || session.expiry < Date.now()) {
    userSessions.delete(token);
    return null;
  }

  const result = await pool.query(
    `SELECT id, username, created_at, chat_sharing_consent
     FROM users WHERE id = $1`,
    [session.userId]
  );

  return result.rows[0] || null;
}

function isValidAdmin(req) {
  const token = getBearerToken(req);
  if (!token) return false;

  const expiry = adminSessions.get(token);

  if (!expiry || expiry < Date.now()) {
    adminSessions.delete(token);
    return false;
  }

  return true;
}

function requireAdmin(req, res) {
  if (!isValidAdmin(req)) {
    res.status(401).json({ error: "HOST yetkisi gerekli." });
    return false;
  }
  return true;
}

async function getHumanSessionForUser(userId, chatId) {
  const result = await pool.query(
    `SELECT * FROM human_chat_sessions
     WHERE user_id = $1 AND chat_id = $2`,
    [userId, chatId]
  );
  return result.rows[0] || null;
}

async function getHumanMessages(sessionId) {
  const result = await pool.query(
    `SELECT id, sender, content, created_at
     FROM human_chat_messages
     WHERE session_id = $1
     ORDER BY id ASC
     LIMIT 200`,
    [sessionId]
  );
  return result.rows;
}

/* KULLANICI KAYDI */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({
        error: "Kullanıcı adı ve şifre gerekli."
      });
    }

    const cleanUsername = username.trim();

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(cleanUsername)) {
      return res.status(400).json({
        error: "Kullanıcı adı 3-20 karakter olmalı."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Şifre en az 8, en fazla 128 karakter olmalı."
      });
    }

    const passwordHash = await hashPassword(password);
    const id = crypto.randomUUID();

    let result;

    try {
      result = await pool.query(
        `INSERT INTO users (id, username, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, username`,
        [id, cleanUsername, passwordHash]
      );
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "Bu kullanıcı adı zaten alınmış."
        });
      }
      throw error;
    }

    const user = result.rows[0];
    const token = createToken();

    userSessions.set(token, {
      userId: user.id,
      expiry: Date.now() + SESSION_DURATION
    });

    res.status(201).json({ success: true, token, user });
  } catch (error) {
    console.error("Kayıt hatası:", error.message);
    res.status(500).json({ error: "Kayıt sırasında sorun oluştu." });
  }
});

/* KULLANICI GİRİŞİ */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({
        error: "Kullanıcı adı ve şifre gerekli."
      });
    }

    const result = await pool.query(
      `SELECT id, username, password_hash
       FROM users WHERE LOWER(username) = LOWER($1)`,
      [username.trim()]
    );

    const user = result.rows[0];

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({
        error: "Kullanıcı adı veya şifre yanlış."
      });
    }

    const token = createToken();

    userSessions.set(token, {
      userId: user.id,
      expiry: Date.now() + SESSION_DURATION
    });

    res.json({
      success: true,
      token,
      user: { id: user.id, username: user.username }
    });
  } catch (error) {
    console.error("Giriş hatası:", error.message);
    res.status(500).json({ error: "Giriş sırasında sorun oluştu." });
  }
});

/* OTURUM KONTROLÜ */
app.get("/api/auth/me", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);

    if (!user) {
      return res.status(401).json({ error: "Oturum bulunamadı." });
    }

    res.json({
      valid: true,
      user: {
        id: user.id,
        username: user.username,
        chatSharingConsent: user.chat_sharing_consent
      }
    });
  } catch (error) {
    console.error("Oturum kontrol hatası:", error.message);
    res.status(500).json({ error: "Oturum kontrol edilemedi." });
  }
});

/* KULLANICI ÇIKIŞI */
app.post("/api/auth/logout", (req, res) => {
  userSessions.delete(getBearerToken(req));
  res.json({ success: true });
});

/* SOHBET PAYLAŞIM İZNİ */
app.get("/api/user/privacy", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ error: "Giriş gerekli." });

    res.json({ consent: user.chat_sharing_consent });
  } catch (error) {
    console.error("İzin kontrol hatası:", error.message);
    res.status(500).json({ error: "İzin bilgisi alınamadı." });
  }
});

app.put("/api/user/privacy", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ error: "Giriş gerekli." });

    const { consent } = req.body || {};
    if (typeof consent !== "boolean") {
      return res.status(400).json({ error: "Geçersiz izin değeri." });
    }

    await pool.query(
      `UPDATE users SET chat_sharing_consent = $1 WHERE id = $2`,
      [consent, user.id]
    );

    if (!consent) {
      await pool.query(
        "DELETE FROM user_chat_logs WHERE user_id = $1",
        [user.id]
      );
    }

    res.json({
      success: true,
      consent,
      message: consent
        ? "Sohbet paylaşımı açıldı."
        : "İzin kapatıldı ve sunucudaki sohbet kayıtları silindi."
    });
  } catch (error) {
    console.error("İzin güncelleme hatası:", error.message);
    res.status(500).json({ error: "İzin güncellenemedi." });
  }
});

/* KULLANICI SOHBETLERİNİ SENKRONİZE ET */
app.post("/api/user/chats/sync", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ error: "Giriş gerekli." });

    if (!user.chat_sharing_consent) {
      return res.status(403).json({
        error: "Sohbet paylaşım izni verilmemiş."
      });
    }

    const { chats } = req.body || {};

    if (!Array.isArray(chats) || chats.length > 100) {
      return res.status(400).json({ error: "Sohbet listesi geçersiz." });
    }

    for (const chat of chats) {
      if (
        !chat ||
        (typeof chat.id !== "string" && typeof chat.id !== "number") ||
        !Array.isArray(chat.messages) ||
        chat.messages.length > 200
      ) continue;

      const safeMessages = chat.messages
        .filter(m =>
          m &&
          ["user", "assistant"].includes(m.role) &&
          typeof m.content === "string"
        )
        .slice(-200)
        .map(m => ({
          role: m.role,
          content: m.content.slice(0, 8000),
          imageName: typeof m.imageName === "string"
            ? m.imageName.slice(0, 150)
            : ""
        }));

      await pool.query(
        `INSERT INTO user_chat_logs
          (user_id, chat_id, title, messages, updated_at)
         VALUES ($1, $2, $3, $4::jsonb, NOW())
         ON CONFLICT (user_id, chat_id)
         DO UPDATE SET
           title = EXCLUDED.title,
           messages = EXCLUDED.messages,
           updated_at = NOW()
         WHERE EXISTS (
           SELECT 1 FROM users
           WHERE id = $1 AND chat_sharing_consent = TRUE
         )`,
        [
          user.id,
          String(chat.id).slice(0, 100),
          typeof chat.title === "string"
            ? chat.title.slice(0, 100)
            : "Yeni Sohbet",
          JSON.stringify(safeMessages)
        ]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Sohbet senkronizasyon hatası:", error.message);
    res.status(500).json({ error: "Sohbetler kaydedilemedi." });
  }
});

/* HOST GİRİŞİ */
app.post("/api/admin/login", (req, res) => {
  try {
    const password = req.body?.password;

    if (typeof password !== "string") {
      return res.status(400).json({ error: "Şifre gerekli." });
    }

    const a = Buffer.from(password);
    const b = Buffer.from(ADMIN_PASSWORD);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: "Şifre yanlış!" });
    }

    const token = createToken();
    adminSessions.set(token, Date.now() + 60 * 60 * 1000);
    res.json({ token });
  } catch (error) {
    console.error("HOST giriş hatası:", error.message);
    res.status(500).json({ error: "Giriş hatası." });
  }
});

app.get("/api/admin/check", (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json({ valid: true });
});

/* HOST KULLANICI LİSTESİ */
app.get("/api/admin/users", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const result = await pool.query(
      `SELECT id, username, created_at, chat_sharing_consent
       FROM users ORDER BY created_at DESC`
    );

    res.json({
      users: result.rows.map(user => ({
        id: user.id,
        username: user.username,
        createdAt: user.created_at,
        chatSharingConsent: user.chat_sharing_consent
      }))
    });
  } catch (error) {
    console.error("Kullanıcı listesi hatası:", error.message);
    res.status(500).json({ error: "Kullanıcı listesi alınamadı." });
  }
});

/* HOST: İZİN VEREN KULLANICININ SOHBETLERİ */
app.get("/api/admin/users/:userId/chats", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const userResult = await pool.query(
      `SELECT id, username, chat_sharing_consent
       FROM users WHERE id = $1`,
      [req.params.userId]
    );

    const user = userResult.rows[0];

    if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });

    if (!user.chat_sharing_consent) {
      return res.status(403).json({
        error: "Bu kullanıcı sohbet görüntüleme izni vermemiş."
      });
    }

    const result = await pool.query(
      `SELECT chat_id, title, messages, updated_at
       FROM user_chat_logs
       WHERE user_id = $1
       ORDER BY updated_at DESC`,
      [user.id]
    );

    res.json({ username: user.username, chats: result.rows });
  } catch (error) {
    console.error("HOST sohbet görüntüleme hatası:", error.message);
    res.status(500).json({ error: "Sohbetler alınamadı." });
  }
});

/* HOST: TEK SEFERLİK EĞLENCE TALİMATI */
app.post("/api/admin/user-instruction", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  res.status(501).json({
    error: "Eğlence talimatı özelliği bu sürümde henüz etkin değil."
  });
});

/* --------------------------------------------------
   İNSAN DESTEKLİ SOHBET API'LERİ
-------------------------------------------------- */

/* KULLANICI: İNSAN DESTEKLİ SOHBET İSTEĞİ */
app.post("/api/human-chat/request", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ error: "Giriş gerekli." });

    const { chatId } = req.body || {};

    if (typeof chatId !== "string" || !chatId.trim() || chatId.length > 100) {
      return res.status(400).json({ error: "Geçerli sohbet seçilmedi." });
    }

    let session = await getHumanSessionForUser(user.id, chatId);

    if (session && session.status !== "closed") {
      return res.json({
        success: true,
        sessionId: session.id,
        status: session.status
      });
    }

    const result = await pool.query(
      `INSERT INTO human_chat_sessions (user_id, chat_id, status)
       VALUES ($1, $2, 'pending')
       ON CONFLICT (user_id, chat_id)
       DO UPDATE SET
         status = 'pending',
         updated_at = NOW()
       WHERE human_chat_sessions.status = 'closed'
       RETURNING *`,
      [user.id, chatId]
    );

    session = result.rows[0];

    if (!session) {
      session = await getHumanSessionForUser(user.id, chatId);
    }

    res.json({
      success: true,
      sessionId: session.id,
      status: session.status
    });
  } catch (error) {
    console.error("İnsan destek isteği hatası:", error.message);
    res.status(500).json({ error: "İstek oluşturulamadı." });
  }
});

/* KULLANICI: SOHBET DURUMUNU VE MESAJLARI AL */
app.get("/api/human-chat/status", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ error: "Giriş gerekli." });

    const chatId = String(req.query.chatId || "");

    if (!chatId || chatId.length > 100) {
      return res.status(400).json({ error: "Sohbet kimliği geçersiz." });
    }

    const session = await getHumanSessionForUser(user.id, chatId);

    if (!session) {
      return res.json({ status: "none", messages: [] });
    }

    const messages = await getHumanMessages(session.id);

    res.json({
      sessionId: session.id,
      status: session.status,
      messages
    });
  } catch (error) {
    console.error("İnsan destek durumu hatası:", error.message);
    res.status(500).json({ error: "Sohbet durumu alınamadı." });
  }
});

/* KULLANICI: İNSAN DESTEKLİ SOHBETE MESAJ GÖNDER */
app.post("/api/human-chat/message", async (req, res) => {
  try {
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ error: "Giriş gerekli." });

    const { chatId, content } = req.body || {};

    if (
      typeof chatId !== "string" ||
      !chatId.trim() ||
      chatId.length > 100 ||
      typeof content !== "string" ||
      !content.trim() ||
      content.length > 4000
    ) {
      return res.status(400).json({ error: "Mesaj geçersiz." });
    }

    const session = await getHumanSessionForUser(user.id, chatId);

    if (!session || !["pending", "active"].includes(session.status)) {
      return res.status(403).json({
        error: "Bu sohbet için insan destek modu açık değil."
      });
    }

    await pool.query(
      `INSERT INTO human_chat_messages (session_id, sender, content)
       VALUES ($1, 'user', $2)`,
      [session.id, content.trim()]
    );

    await pool.query(
      `UPDATE human_chat_sessions SET updated_at = NOW() WHERE id = $1`,
      [session.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error("Kullanıcı insan mesajı hatası:", error.message);
    res.status(500).json({ error: "Mesaj gönderilemedi." });
  }
});

/* HOST: BEKLEYEN VE AÇIK SOHBETLERİ LİSTELE */
app.get("/api/admin/human-chats", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const result = await pool.query(
      `SELECT s.id, s.user_id, s.chat_id, s.status,
              s.created_at, s.updated_at, u.username,
              (SELECT COUNT(*) FROM human_chat_messages m
               WHERE m.session_id = s.id) AS message_count
       FROM human_chat_sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.status IN ('pending', 'active')
       ORDER BY
         CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END,
         s.updated_at DESC
       LIMIT 100`
    );

    res.json({ sessions: result.rows });
  } catch (error) {
    console.error("HOST insan sohbet listesi hatası:", error.message);
    res.status(500).json({ error: "Sohbet listesi alınamadı." });
  }
});

/* HOST: BİR SOHBETİN MESAJLARINI GÖR */
app.get("/api/admin/human-chats/:sessionId", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const result = await pool.query(
      `SELECT s.id, s.status, s.chat_id, u.username
       FROM human_chat_sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = $1`,
      [req.params.sessionId]
    );

    const session = result.rows[0];
    if (!session) return res.status(404).json({ error: "Sohbet bulunamadı." });

    const messages = await getHumanMessages(session.id);
    res.json({ session, messages });
  } catch (error) {
    console.error("HOST insan sohbet mesajları hatası:", error.message);
    res.status(500).json({ error: "Mesajlar alınamadı." });
  }
});

/* HOST: SOHBETİ KABUL ET */
app.post("/api/admin/human-chats/:sessionId/accept", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const result = await pool.query(
      `UPDATE human_chat_sessions
       SET status = 'active', updated_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING id`,
      [req.params.sessionId]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Bekleyen sohbet bulunamadı."
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("HOST sohbet kabul hatası:", error.message);
    res.status(500).json({ error: "Sohbet kabul edilemedi." });
  }
});

/* HOST: KULLANICIYA CEVAP YAZ */
app.post("/api/admin/human-chats/:sessionId/reply", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const { content } = req.body || {};

    if (
      typeof content !== "string" ||
      !content.trim() ||
      content.length > 4000
    ) {
      return res.status(400).json({ error: "Cevap geçersiz." });
    }

    const sessionResult = await pool.query(
      `SELECT id, status FROM human_chat_sessions WHERE id = $1`,
      [req.params.sessionId]
    );

    const session = sessionResult.rows[0];

    if (!session || session.status !== "active") {
      return res.status(403).json({
        error: "Bu sohbet aktif değil."
      });
    }

    await pool.query(
      `INSERT INTO human_chat_messages (session_id, sender, content)
       VALUES ($1, 'host', $2)`,
      [session.id, content.trim()]
    );

    await pool.query(
      `UPDATE human_chat_sessions SET updated_at = NOW() WHERE id = $1`,
      [session.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error("HOST cevap hatası:", error.message);
    res.status(500).json({ error: "Cevap gönderilemedi." });
  }
});

/* HOST: SOHBETİ KAPAT */
app.post("/api/admin/human-chats/:sessionId/close", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const result = await pool.query(
      `UPDATE human_chat_sessions
       SET status = 'closed', updated_at = NOW()
       WHERE id = $1 AND status IN ('pending', 'active')
       RETURNING id`,
      [req.params.sessionId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Açık sohbet bulunamadı." });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("HOST sohbet kapatma hatası:", error.message);
    res.status(500).json({ error: "Sohbet kapatılamadı." });
  }
});

/* HOST ÇIKIŞI */
app.post("/api/admin/logout", (req, res) => {
  adminSessions.delete(getBearerToken(req));
  res.json({ success: true });
});

/* YAPAY ZEKA SOHBETİ */
app.post("/api/chat", async (req, res) => {
  try {
    const {
      messages,
      mode,
      trollMode,
      isHost,
      hostMemory,
      image
    } = req.body || {};

    const hostAuthorized = isHost === true && isValidAdmin(req);
    const user = await getUserFromRequest(req);

    if (!user && !hostAuthorized) {
      return res.status(401).json({
        error: "Sohbet etmek için giriş yapmalısın."
      });
    }

    if (!Array.isArray(messages)) {
      return res.status(400).json({ error: "Mesaj listesi geçersiz." });
    }

    const clean = messages
      .filter(m =>
        m &&
        ["user", "assistant"].includes(m.role) &&
        typeof m.content === "string" &&
        m.content.trim().length > 0
      )
      .slice(-20)
      .map(m => ({
        role: m.role,
        content: m.content.slice(0, 8000)
      }));

    if (!clean.length) {
      return res.status(400).json({ error: "Önce bir mesaj yaz." });
    }

    let systemPrompt = mode === "bad" ? BAD_MODE : GOOD_MODE;

    if (trollMode === true) {
      systemPrompt += `
TROLLEME MODU AÇIK.
Zararsız, komik ve kısa sürpriz şakalar yapabilirsin.
Şakanın sonunda bunun bir şaka olduğunu açıkla.
Kullanıcıyı korkutma veya ciddi bir konuda yanıltma.
`;
    }

    if (hostAuthorized) {
      systemPrompt += `
Bu oturum HOST oturumudur.
Kullanıcının adı Alperen'dir.
`;

      if (typeof hostMemory === "string" && hostMemory.trim()) {
        systemPrompt += `
HOST bilgileri:
${hostMemory.slice(0, 3000)}
`;
      }
    }

    const finalMessages = clean.map(m => ({
      role: m.role,
      content: m.content
    }));

    let model = "openai/gpt-oss-20b";

    if (typeof image === "string" && image.length > 0) {
      if (
        !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(image) ||
        image.length > 7 * 1024 * 1024
      ) {
        return res.status(400).json({
          error: "Fotoğraf biçimi veya boyutu geçersiz."
        });
      }

      const lastUserIndex = finalMessages
        .map(m => m.role)
        .lastIndexOf("user");

      if (lastUserIndex === -1) {
        return res.status(400).json({
          error: "Fotoğraf için mesaj gerekli."
        });
      }

      finalMessages[lastUserIndex] = {
        role: "user",
        content: [
          { type: "text", text: finalMessages[lastUserIndex].content },
          { type: "image_url", image_url: { url: image } }
        ]
      };

      model = "qwen/qwen3.8-27b";
    }

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${GROQ_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: "system", content: systemPrompt },
            ...finalMessages
          ]
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Groq hatası:", data.error?.message || data);
      return res.status(502).json({
        error: "Yapay zekâ bağlantısında sorun oluştu."
      });
    }

    const answer = data.choices?.[0]?.message?.content;

    if (typeof answer !== "string") {
      throw new Error("Yapay zekâ boş cevap verdi.");
    }

    res.json({ answer });
  } catch (error) {
    console.error("IPON AI hatası:", error.message);
    res.status(500).json({
      error: "IPON AI şu anda cevap veremedi."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("IPON AI hazır!");
});
