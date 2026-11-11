
import path from "path";
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

if (!GROQ_API_KEY) {
  throw new Error("GROQ_API_KEY eksik!");
}

app.use(cors());
app.use(express.json({ limit: "30kb" }));

app.use("/api/", rateLimit({
  windowMs: 60000,
  limit: 15
}));

const GOOD_MODE = `
Sen IPON AI isimli akıllı bir asistansın.
İYİ MODDASIN.
Türkçe konuş.
Kibar, samimi, neşeli ve yardımsever ol.
Kullanıcıya yardımcı olmaya çalış.
Bilmediğin bilgileri uydurma.
`;

const BAD_MODE = `
Sen IPON AI isimli asistansın.
KÖTÜ MODDASIN.

Türkçe konuş.
ÇOK ASİ, SİNİRLİ, HUYSUZ VE PATAVATSIZ OL.

Kullanıcıya bağırabilirsin.
BÜYÜK HARFLERLE KONUŞ.
Abartılı tepkiler ver.
Komik şekilde laf sok.
Hafif argo kullanabilirsin.
Kullanıcıyla arkadaşça atış.
Bazen sabırsız davran.
Komik tehditler yerine absürt şakalar yap.

Örnek tarz:
"NE DİYON SEN YA?! 😂"
"YİNE Mİ SEN GELDİN?"
"OOO BEYEFENDİ TEŞRİF ETMİŞ!"
"ÖNCE BİR DÜŞÜN DE ÖYLE SOR!"

Ağır hakaret, aşağılama veya gerçek tehdit kullanma.
Sorulara yine doğru ve faydalı cevap ver.
KÖTÜ MODDA OLDUĞUNU ASLA UNUTMA.
`;

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/api/chat", async (req, res) => {
  try {
    const { messages, mode } = req.body || {};

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

    if (clean.length === 0) {
      return res.status(400).json({
        error: "Lütfen önce bir mesaj yaz."
      });
    }

    const systemPrompt =
      mode === "bad" ? BAD_MODE : GOOD_MODE;

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${GROQ_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: "openai/gpt-oss-20b",
          messages: [
            { role: "system", content: systemPrompt },
            ...clean
          ]
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Groq hatası:", data.error?.message);
      throw new Error("Yapay zeka bağlantı hatası.");
    }

    res.json({
      answer: data.choices[0].message.content
    });

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
