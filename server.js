
import express from "express";
import cors from "cors";
import pg from "pg";
import {
  randomBytes,
  createHmac,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";
import { scrypt as scryptCallback } from "node:crypto";

const scrypt = promisify(scryptCallback);
const app = express();
const { Pool } = pg;

app.use(cors());
app.use(express.json({ limit: "12mb" }));

const PORT = process.env.PORT || 10000;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DATABASE_URL = process.env.DATABASE_URL;

if (!GROQ_API_KEY || !ADMIN_PASSWORD || !DATABASE_URL) {
  console.error("Eksik ortam değişkeni! GROQ_API_KEY, ADMIN_PASSWORD ve DATABASE_URL gerekli.");
  process.exit(1);
}

const TOKEN_SECRET =
  process.env.TOKEN_SECRET || ADMIN_PASSWORD;

if (!process.env.TOKEN_SECRET) {
  console.warn("Uyarı: Render ortam değişkenlerine TOKEN_SECRET eklemen önerilir.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const MODEL = "openai/gpt-oss-20b";

// -------------------------
// GENEL YARDIMCILAR
// -------------------------

function makeToken(payload) {
  const data = Buffer.from(JSON.stringify({
    ...payload,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString("base64url");

  const signature = createHmac("sha256", TOKEN_SECRET)
    .update(data)
    .digest("base64url");

  return data + "." + signature;
}

function readToken(token) {
  try {
    const [data, signature] = String(token || "").split(".");
    if (!data || !signature) return null;

    const expected = createHmac("sha256", TOKEN_SECRET)
      .update(data)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString()
    );

    if (!payload.exp || payload.exp < Date.now()) return null;

    return payload;
  } catch {
    return null;
  }
}

function getBearer(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ")
    ? header.slice(7)
    : "";
}

function requireUser(req, res, next) {
  const payload = readToken(getBearer(req));

  if (!payload || payload.role !== "user") {
    return res.status(401).json({ error: "Oturum geçersiz. Tekrar giriş yap." });
  }

  req.user = payload;
  next();
}

function requireAdmin(req, res, next) {
  const payload = readToken(req.headers["x-admin-token"]);

  if (!payload || payload.role !== "admin") {
    return res.status(401).json({ error: "HOST oturumu geçersiz." });
  }

  req.admin = payload;
  next();
}

function safeEqual(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  return first.length === second.length &&
    timingSafeEqual(first, second);
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = await scrypt(password, salt, 64);

  return salt + ":" + Buffer.from(hash).toString("hex");
}

async function verifyPassword(password, stored) {
  try {
    const [salt, savedHash] = stored.split(":");
    const hash = await scrypt(password, salt, 64);

    return safeEqual(
      Buffer.from(hash).toString("hex"),
      savedHash
    );
  } catch {
    return false;
  }
}

function validChatId(value) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 100;
}

// -------------------------
// VERİTABANI
// -------------------------

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(20) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      share_consent BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS share_consent BOOLEAN NOT NULL DEFAULT FALSE
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ipon_chat_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      chat_id VARCHAR(100) NOT NULL,
      messages JSONB NOT NULL DEFAULT '[]'::jsonb,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, chat_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS human_chat_sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      chat_id VARCHAR(100) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS human_chat_messages (
      id BIGSERIAL PRIMARY KEY,
      session_id BIGINT NOT NULL REFERENCES human_chat_sessions(id) ON DELETE CASCADE,
      sender VARCHAR(20) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("PostgreSQL bağlantısı hazır!");
}

// -------------------------
// SAĞLIK KONTROLÜ
// -------------------------

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", app: "IPON AI" });
});

// -------------------------
// KAYIT VE GİRİŞ
// -------------------------

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_]{3,20}$/.test(username)
    ) {
      return res.status(400).json({
        error: "Kullanıcı adı 3-20 karakter olmalı. Harf, rakam ve _ kullanabilirsin."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Şifre 8-128 karakter arasında olmalı."
      });
    }

    const passwordHash = await hashPassword(password);

    const result = await pool.query(
      `INSERT INTO users (username, password_hash)
       VALUES ($1, $2)
       RETURNING id, username`,
      [username, passwordHash]
    );

    const user = result.rows[0];
    const token = makeToken({
      id: user.id,
      username: user.username,
      role: "user"
    });

    res.status(201).json({ token, user });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "Bu kullanıcı adı zaten kullanılıyor."
      });
    }

    console.error("Kayıt hatası:", err);
    res.status(500).json({ error: "Kayıt oluşturulamadı." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Bilgileri kontrol et." });
    }

    const result = await pool.query(
      "SELECT id, username, password_hash FROM users WHERE username = $1",
      [username]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Kullanıcı adı veya şifre yanlış."
      });
    }

    const user = result.rows[0];
    const correct = await verifyPassword(password, user.password_hash);

    if (!correct) {
      return res.status(401).json({
        error: "Kullanıcı adı veya şifre yanlış."
      });
    }

    const token = makeToken({
      id: user.id,
      username: user.username,
      role: "user"
    });

    res.json({
      token,
      user: { id: user.id, username: user.username }
    });
  } catch (err) {
    console.error("Giriş hatası:", err);
    res.status(500).json({ error: "Giriş yapılamadı." });
  }
});

app.get("/api/auth/me", requireUser, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    }

    res.json({ user: result.rows[0] });
  } catch {
    res.status(500).json({ error: "Kullanıcı bilgisi alınamadı." });
  }
});

// -------------------------
// GİZLİLİK VE PAYLAŞIM İZNİ
// -------------------------

app.get("/api/privacy", requireUser, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT share_consent FROM users WHERE id = $1",
      [req.user.id]
    );

    res.json({
      allowed: !!result.rows[0]?.share_consent
    });
  } catch {
    res.status(500).json({ error: "İzin bilgisi alınamadı." });
  }
});

app.post("/api/privacy", requireUser, async (req, res) => {
  try {
    const allowed = req.body.allowed;

    if (typeof allowed !== "boolean") {
      return res.status(400).json({ error: "Geçersiz izin değeri." });
    }

    await pool.query(
      "UPDATE users SET share_consent = $1 WHERE id = $2",
      [allowed, req.user.id]
    );

    if (!allowed) {
      await pool.query(
        `UPDATE human_chat_sessions
         SET status = 'closed', updated_at = NOW()
         WHERE user_id = $1 AND status IN ('pending', 'accepted')`,
        [req.user.id]
      );
    }

    res.json({ success: true, allowed });
  } catch (err) {
    console.error("İzin hatası:", err);
    res.status(500).json({ error: "İzin güncellenemedi." });
  }
});

// -------------------------
// GROQ YAPAY ZEKA
// -------------------------

app.post("/api/chat", requireUser, async (req, res) => {
  try {
    const { messages, mode, trollMode, image, chatId } = req.body;

    if (image) {
      return res.status(400).json({
        error: "Fotoğraf yükleme arayüzü hazır; görsel analiz modeli henüz bağlanmadı."
      });
    }

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: "Mesaj bulunamadı." });
    }

    if (messages.length > 40) {
      return res.status(400).json({ error: "Sohbet çok uzun." });
    }

    const safeMessages = messages
      .filter(m =>
        m &&
        ["user", "assistant"].includes(m.role) &&
        typeof m.content === "string"
      )
      .slice(-30)
      .map(m => ({
        role: m.role,
        content: m.content.slice(0, 8000)
      }));

    const systemPrompt = mode === "bad"
      ? "Sen IPON AI'sin. Türkçe konuş. Daha sert, alaycı, esprili ve dobra olabilirsin. Ancak tehdit etme, ağır aşağılamalara girme ve kişileri hedef gösterme. Kullanıcının yaşına uygun, güvenli cevaplar ver."
      : "Sen IPON AI'sin. Türkçe konuş. Samimi, eğlenceli, yardımcı ve arkadaş canlısı ol. Kullanıcının yaşına uygun ve güvenli cevaplar ver.";

    const extraPrompt = trollMode
      ? " Kullanıcı trolleme modunu açtı. Zararsız şakalar yapabilir, mizah kullanabilirsin; korkutma, tehdit veya gerçek dışı tehlike iddiaları oluşturma."
      : "";

    const groqResponse = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${GROQ_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: MODEL,
          messages: [
            { role: "system", content: systemPrompt + extraPrompt },
            ...safeMessages
          ],
          max_completion_tokens: 1200,
          temperature: 0.8
        })
      }
    );

    const result = await groqResponse.json();

    if (!groqResponse.ok) {
      console.error("Groq hatası:", result);
      return res.status(502).json({
        error: result.error?.message || "Yapay zeka servisi yanıt vermedi."
      });
    }

    const reply = result.choices?.[0]?.message?.content;

    if (!reply) {
      return res.status(502).json({ error: "Yapay zeka boş yanıt verdi." });
    }

    // Kullanıcı paylaşım izni verdiyse sohbeti kaydet.
    const consent = await pool.query(
      "SELECT share_consent FROM users WHERE id = $1",
      [req.user.id]
    );

    if (consent.rows[0]?.share_consent) {
      const id = validChatId(chatId) ? chatId : "main";

      await pool.query(
        `INSERT INTO ipon_chat_logs (user_id, chat_id, messages)
         VALUES ($1, $2, $3::jsonb)
         ON CONFLICT (user_id, chat_id)
         DO UPDATE SET messages = EXCLUDED.messages,
                       updated_at = NOW()`,
        [req.user.id, id, JSON.stringify([
          ...safeMessages,
          { role: "assistant", content: reply }
        ])]
      );
    }

    res.json({ reply });
  } catch (err) {
    console.error("Sohbet hatası:", err);
    res.status(500).json({ error: "Sohbet sırasında bir hata oluştu." });
  }
});

// -------------------------
// HOST GİRİŞİ
// -------------------------

app.post("/api/admin/login", (req, res) => {
  const password = req.body.password;

  if (typeof password !== "string" || !safeEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: "HOST şifresi yanlış." });
  }

  const token = makeToken({
    role: "admin",
    username: "HOST"
  });

  res.json({ token });
});

// -------------------------
// HOST KULLANICI LİSTESİ
// -------------------------

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, created_at
       FROM users
       WHERE share_consent = TRUE
       ORDER BY created_at DESC`
    );

    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Kullanıcılar alınamadı." });
  }
});

// -------------------------
// HOST KULLANICI SOHBETLERİ
// -------------------------

app.get("/api/admin/users/:id/chats", requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (!Number.isInteger(userId)) {
      return res.status(400).json({ error: "Geçersiz kullanıcı." });
    }

    const consent = await pool.query(
      "SELECT share_consent FROM users WHERE id = $1",
      [userId]
    );

    if (!consent.rows[0]?.share_consent) {
      return res.status(403).json({ error: "Kullanıcı paylaşım izni vermemiş." });
    }

    const result = await pool.query(
      `SELECT chat_id, messages, updated_at
       FROM ipon_chat_logs
       WHERE user_id = $1
       ORDER BY updated_at DESC`,
      [userId]
    );

    res.json({
      chats: result.rows.map(row => ({
        title: row.chat_id,
        messages: row.messages || []
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Sohbetler alınamadı." });
  }
});

// -------------------------
// KULLANICI HOST DESTEĞİ İSTER
// -------------------------

app.post("/api/human-chat/request", requireUser, async (req, res) => {
  try {
    const { chatId } = req.body;

    if (!validChatId(chatId)) {
      return res.status(400).json({ error: "Sohbet numarası geçersiz." });
    }

    const consent = await pool.query(
      "SELECT share_consent FROM users WHERE id = $1",
      [req.user.id]
    );

    if (!consent.rows[0]?.share_consent) {
      return res.status(403).json({
        error: "Önce HOST desteği ve sohbet paylaşımı izni vermelisin."
      });
    }

    const existing = await pool.query(
      `SELECT id, status FROM human_chat_sessions
       WHERE user_id = $1 AND chat_id = $2
       AND status IN ('pending', 'accepted')
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.id, chatId]
    );

    if (existing.rows.length) {
      return res.json({
        sessionId: existing.rows[0].id,
        status: existing.rows[0].status
      });
    }

    const created = await pool.query(
      `INSERT INTO human_chat_sessions (user_id, chat_id, status)
       VALUES ($1, $2, 'pending')
       RETURNING id, status`,
      [req.user.id, chatId]
    );

    res.json({
      sessionId: created.rows[0].id,
      status: created.rows[0].status
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "HOST isteği oluşturulamadı." });
  }
});

// -------------------------
// KULLANICI HOST SOHBET DURUMU
// -------------------------

app.get("/api/human-chat/status", requireUser, async (req, res) => {
  try {
    const chatId = req.query.chatId;

    if (!validChatId(chatId)) {
      return res.status(400).json({ error: "Sohbet numarası geçersiz." });
    }

    const session = await pool.query(
      `SELECT id, status
       FROM human_chat_sessions
       WHERE user_id = $1 AND chat_id = $2
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.id, chatId]
    );

    if (!session.rows.length) {
      return res.json({ status: "none", messages: [] });
    }

    const current = session.rows[0];

    const messages = await pool.query(
      `SELECT id, sender, content, created_at
       FROM human_chat_messages
       WHERE session_id = $1
       ORDER BY created_at ASC`,
      [current.id]
    );

    res.json({
      sessionId: current.id,
      status: current.status,
      messages: messages.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "HOST sohbet durumu alınamadı." });
  }
});

// -------------------------
// KULLANICI HOST'A MESAJ GÖNDERİR
// -------------------------

app.post("/api/human-chat/message", requireUser, async (req, res) => {
  try {
    const { chatId, content } = req.body;

    if (!validChatId(chatId) ||
        typeof content !== "string" ||
        !content.trim() ||
        content.length > 4000) {
      return res.status(400).json({ error: "Mesaj geçersiz." });
    }

    const consent = await pool.query(
      "SELECT share_consent FROM users WHERE id = $1",
      [req.user.id]
    );

    if (!consent.rows[0]?.share_consent) {
      return res.status(403).json({ error: "HOST paylaşım iznin kapalı." });
    }

    const session = await pool.query(
      `SELECT id, status
       FROM human_chat_sessions
       WHERE user_id = $1 AND chat_id = $2
       AND status IN ('pending', 'accepted')
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.id, chatId]
    );

    if (!session.rows.length) {
      return res.status(404).json({ error: "Aktif HOST sohbeti bulunamadı." });
    }

    await pool.query(
      `INSERT INTO human_chat_messages (session_id, sender, content)
       VALUES ($1, 'user', $2)`,
      [session.rows[0].id, content.trim()]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Mesaj gönderilemedi." });
  }
});

// -------------------------
// HOST DESTEK TALEPLERİ
// -------------------------

app.get("/api/admin/human-chats", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.user_id, s.chat_id, s.status, s.created_at,
              u.username
       FROM human_chat_sessions s
       JOIN users u ON u.id = s.user_id
       WHERE u.share_consent = TRUE
       ORDER BY s.created_at DESC
       LIMIT 100`
    );

    res.json({ sessions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "HOST talepleri alınamadı." });
  }
});

// -------------------------
// HOST BİR SOHBETİ GÖRÜNTÜLER
// -------------------------

app.get("/api/admin/human-chats/:sessionId", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.sessionId);

    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: "Geçersiz sohbet." });
    }

    const session = await pool.query(
      `SELECT s.id, s.status, s.chat_id, u.username, u.share_consent
       FROM human_chat_sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = $1`,
      [id]
    );

    if (!session.rows.length || !session.rows[0].share_consent) {
      return res.status(404).json({ error: "Sohbet bulunamadı veya izin kapalı." });
    }

    const messages = await pool.query(
      `SELECT id, sender, content, created_at
       FROM human_chat_messages
       WHERE session_id = $1
       ORDER BY created_at ASC`,
      [id]
    );

    res.json({
      session: session.rows[0],
      messages: messages.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Sohbet alınamadı." });
  }
});

// -------------------------
// HOST SOHBETİ KABUL EDER
// -------------------------

app.post("/api/admin/human-chats/:sessionId/accept", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.sessionId);

    const result = await pool.query(
      `UPDATE human_chat_sessions s
       SET status = 'accepted', updated_at = NOW()
       FROM users u
       WHERE s.id = $1
       AND s.user_id = u.id
       AND u.share_consent = TRUE
       AND s.status = 'pending'
       RETURNING s.id`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Bekleyen talep bulunamadı veya izin kapalı."
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Talep kabul edilemedi." });
  }
});

// -------------------------
// HOST YANIT GÖNDERİR
// -------------------------

app.post("/api/admin/human-chats/:sessionId/reply", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.sessionId);
    const content = req.body.content;

    if (!Number.isInteger(id) ||
        typeof content !== "string" ||
        !content.trim() ||
        content.length > 4000) {
      return res.status(400).json({ error: "Yanıt geçersiz." });
    }

    const session = await pool.query(
      `SELECT s.id
       FROM human_chat_sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = $1
       AND s.status = 'accepted'
       AND u.share_consent = TRUE`,
      [id]
    );

    if (!session.rows.length) {
      return res.status(404).json({
        error: "Aktif HOST sohbeti bulunamadı."
      });
    }

    await pool.query(
      `INSERT INTO human_chat_messages (session_id, sender, content)
       VALUES ($1, 'host', $2)`,
      [id, content.trim()]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "HOST yanıtı gönderilemedi." });
  }
});

// -------------------------
// HOST SOHBETİ KAPATIR
// -------------------------

app.post("/api/admin/human-chats/:sessionId/close", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.sessionId);

    const result = await pool.query(
      `UPDATE human_chat_sessions
       SET status = 'closed', updated_at = NOW()
       WHERE id = $1 AND status IN ('pending', 'accepted')
       RETURNING id`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Aktif sohbet bulunamadı." });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Sohbet kapatılamadı." });
  }
});

// -------------------------
// HATA YAKALAMA
// -------------------------

app.use((err, req, res, next) => {
  console.error("Sunucu hatası:", err);
  res.status(500).json({ error: "Sunucuda beklenmeyen bir hata oluştu." });
});

// -------------------------
// SUNUCUYU BAŞLAT
// -------------------------

async function startServer() {
  try {
    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("IPON AI hazır!");
      console.log("Port:", PORT);
    });
  } catch (err) {
    console.error("Sunucu başlatılamadı:", err);
    process.exit(1);
  }
}

startServer();
