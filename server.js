import path from "path";
import fs from "fs/promises";
import crypto from "crypto";
import { promisify } from "util";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Render kalıcı disk bağlanınca DATA_DIR=/var/data olacak.
const DATA_DIR = process.env.DATA_DIR || __dirname;
const USERS_FILE = path.join(DATA_DIR, "users.json");

const scrypt = promisify(crypto.scrypt);

if (!GROQ_API_KEY) {
  throw new Error("GROQ_API_KEY eksik!");
}

if (!ADMIN_PASSWORD) {
  throw new Error("ADMIN_PASSWORD eksik!");
}

await fs.mkdir(DATA_DIR, { recursive: true });

let users = [];

try {
  const savedUsers = await fs.readFile(USERS_FILE, "utf8");
  users = JSON.parse(savedUsers);

  if (!Array.isArray(users)) {
    users = [];
  }
} catch {
  await fs.writeFile(USERS_FILE, "[]", "utf8");
}

let saveQueue = Promise.resolve();

function saveUsers() {
  saveQueue = saveQueue.then(async () => {
    const temporaryFile = USERS_FILE + ".tmp";
    await fs.writeFile(
      temporaryFile,
      JSON.stringify(users, null, 2),
      "utf8"
    );
    await fs.rename(temporaryFile, USERS_FILE);
  });

  return saveQueue;
}

app.use(cors());
app.use(express.json({ limit: "10mb" }));

app.use("/api/", rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
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

// TOKEN OLUŞTURMA
function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

// ŞİFRE HASHLEME
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scrypt(password, salt, 64);

  return `${salt}:${derivedKey.toString("hex")}`;
}

// ŞİFRE KONTROLÜ
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

// KULLANICI TOKEN KONTROLÜ
function getUserFromRequest(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7);
  const session = userSessions.get(token);

  if (!session || session.expiry < Date.now()) {
    userSessions.delete(token);
    return null;
  }

  return users.find(user => user.id === session.userId) || null;
}

// HOST TOKEN KONTROLÜ
function isValidAdmin(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) return false;

  const expiry = adminSessions.get(token);

  if (!expiry || expiry < Date.now()) {
    adminSessions.delete(token);
    return false;
  }

  return true;
}

// KULLANICI KAYDI
app.post("/api/auth/register", async (req, res) => {
  try {
    const username = req.body?.username;
    const password = req.body?.password;

    if (
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Kullanıcı adı ve şifre gerekli."
      });
    }

    const cleanUsername = username.trim();

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(cleanUsername)) {
      return res.status(400).json({
        error: "Kullanıcı adı 3-20 karakter olmalı. Harf, rakam ve _ kullanabilirsin."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Şifre en az 8, en fazla 128 karakter olmalı."
      });
    }

    const exists = users.some(
      user => user.username.toLowerCase() === cleanUsername.toLowerCase()
    );

    if (exists) {
      return res.status(409).json({
        error: "Bu kullanıcı adı zaten alınmış."
      });
    }

    const user = {
      id: crypto.randomUUID(),
      username: cleanUsername,
      passwordHash: await hashPassword(password),
      createdAt: new Date().toISOString()
    };

    users.push(user);
    await saveUsers();

    const token = createToken();

    userSessions.set(token, {
      userId: user.id,
      expiry: Date.now() + SESSION_DURATION
    });

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error("Kayıt hatası:", error.message);

    res.status(500).json({
      error: "Kayıt sırasında bir sorun oluştu."
    });
  }
});

// KULLANICI GİRİŞİ
app.post("/api/auth/login", async (req, res) => {
  try {
    const username = req.body?.username;
    const password = req.body?.password;

    if (
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Kullanıcı adı ve şifre gerekli."
      });
    }

    const user = users.find(
      item => item.username.toLowerCase() === username.trim().toLowerCase()
    );

    if (!user || !(await verifyPassword(password, user.passwordHash))) {
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
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error("Giriş hatası:", error.message);

    res.status(500).json({
      error: "Giriş sırasında bir sorun oluştu."
    });
  }
});

// OTURUM KONTROLÜ
app.get("/api/auth/me", (req, res) => {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({
      error: "Oturum bulunamadı."
    });
  }

  res.json({
    valid: true,
    user: {
      id: user.id,
      username: user.username
    }
  });
});

// KULLANICI ÇIKIŞI
app.post("/api/auth/logout", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  userSessions.delete(token);

  res.json({ success: true });
});

// HOST GİRİŞİ
app.post("/api/admin/login", (req, res) => {
  try {
    const password = req.body?.password;

    if (typeof password !== "string") {
      return res.status(400).json({
        error: "Şifre gerekli."
      });
    }

    const a = Buffer.from(password);
    const b = Buffer.from(ADMIN_PASSWORD);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return res.status(401).json({
        error: "Şifre yanlış!"
      });
    }

    const token = createToken();

    adminSessions.set(token, Date.now() + 60 * 60 * 1000);

    res.json({ token });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Giriş hatası."
    });
  }
});

// HOST YETKİSİ KONTROLÜ
app.get("/api/admin/check", (req, res) => {
  if (!isValidAdmin(req)) {
    return res.status(401).json({
      error: "HOST yetkisi bulunamadı."
    });
  }

  res.json({ valid: true });
});

// HOST KULLANICI LİSTESİ
app.get("/api/admin/users", (req, res) => {
  if (!isValidAdmin(req)) {
    return res.status(401).json({
      error: "HOST yetkisi gerekli."
    });
  }

  res.json({
    users: users.map(user => ({
      id: user.id,
      username: user.username,
      createdAt: user.createdAt
    }))
  });
});

// HOST ÇIKIŞI
app.post("/api/admin/logout", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  adminSessions.delete(token);

  res.json({ success: true });
});

// YAPAY ZEKA SOHBETİ
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

    if (!Array.isArray(messages)) {
      return res.status(400).json({
        error: "Mesaj listesi geçersiz."
      });
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
      return res.status(400).json({
        error: "Önce bir mesaj yaz."
      });
    }

    const hostAuthorized = isHost === true && isValidAdmin(req);

    let systemPrompt =
      mode === "bad" ? BAD_MODE : GOOD_MODE;

    if (trollMode === true) {
      systemPrompt += `
TROLLEME MODU AÇIK.
Zararsız, komik ve kısa sürpriz şakalar yapabilirsin.
Şakayı gerçekmiş gibi uzun süre sürdürme.
Şakanın sonunda bunun bir şaka olduğunu açıkla.
Kullanıcıyı korkutma veya ciddi bir konuda yanıltma.
`;
    }

    if (hostAuthorized) {
      systemPrompt += `
Bu oturum HOST oturumudur.
Kullanıcının adı Alperen'dir.
HOST ile konuşurken bunu dikkate al.
`;

      if (typeof hostMemory === "string" && hostMemory.trim()) {
        systemPrompt += `
HOST tarafından kaydedilmiş özel bilgiler:
${hostMemory.slice(0, 3000)}
Bu bilgileri yalnızca bu yetkili HOST oturumunda kullan.
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

      const lastMessage = finalMessages[lastUserIndex];

      finalMessages[lastUserIndex] = {
        role: "user",
        content: [
          {
            type: "text",
            text: lastMessage.content
          },
          {
            type: "image_url",
            image_url: { url: image }
          }
        ]
      };

      model = "meta-llama/llama-4-scout-17b-16e-instruct";
    }

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${GROQ_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: "system",
              content: systemPrompt
            },
            ...finalMessages
          ]
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Groq hatası:", data.error?.message);

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
