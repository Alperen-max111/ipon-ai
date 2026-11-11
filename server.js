import path from "path";
import crypto from "crypto";
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

if (!GROQ_API_KEY) {
  throw new Error("GROQ_API_KEY eksik!");
}

app.use(cors());
app.use(express.json({ limit: "10mb" }));

app.use("/api/", rateLimit({
  windowMs: 60000,
  limit: 20
}));

app.use(express.static(__dirname));

const adminSessions = new Map();

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

// HOST GİRİŞİ
app.post("/api/admin/login", (req, res) => {
  try {
    if (!ADMIN_PASSWORD) {
      return res.status(500).json({
        error: "ADMIN_PASSWORD sunucuda ayarlanmamış."
      });
    }

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

    const token = crypto.randomBytes(32).toString("hex");

    adminSessions.set(token, Date.now() + 60 * 60 * 1000);

    res.json({ token });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Giriş hatası." });
  }
});

// HOST YETKİSİ KONTROLÜ
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

app.get("/api/admin/check", (req, res) => {
  if (!isValidAdmin(req)) {
    return res.status(401).json({
      error: "HOST yetkisi bulunamadı."
    });
  }

  res.json({ valid: true });
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

    // HOST bilgileri yalnızca geçerli HOST oturumunda kullanılır.
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

    // Fotoğraf gönderilmişse görsel destekli model kullan.
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
