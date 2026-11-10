
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import OpenAI from "openai";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.OPENAI_API_KEY) {
  throw new Error("API anahtarı eksik!");
}

const ai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

app.use(cors());
app.use(express.json({ limit: "30kb" }));

app.use("/api/", rateLimit({
  windowMs: 60000,
  limit: 15
}));

const SYSTEM = `
Sen IPON AI isimli akıllı bir asistansın.

- Türkçe konuş.
- Doğal ve samimi ol.
- Aynı cevapları gereksiz yere tekrarlama.
- Önceki konuşmaları dikkate al.
- Kod yaz ve sorunları çöz.
- Bilmediğin bilgileri uydurma.
- Gerektiğinde internetten araştırma yap.
- Kendini IPON AI olarak tanıt.
`;

app.get("/", (req, res) => {
  res.send("IPON AI çalışıyor! 🚀");
});

app.post("/api/chat", async (req, res) => {
  try {
    const messages = req.body.messages;

    if (!Array.isArray(messages) || messages.length === 0 ||
        messages.length > 20) {
      return res.status(400).json({
        error: "Geçersiz mesaj."
      });
    }

    const clean = messages.map(m => {
      if (!m ||
          !["user", "assistant"].includes(m.role) ||
          typeof m.content !== "string" ||
          m.content.length > 8000) {
        throw new Error("Geçersiz mesaj.");
      }

      return {
        role: m.role,
        content: m.content
      };
    });

    const result = await ai.responses.create({
      model: "gpt-5.5",
      instructions: SYSTEM,
      input: clean
    });

    res.json({
      answer: result.output_text
    });

  } catch (error) {
    console.error(error.message);

    res.status(500).json({
      error: "IPON AI cevap veremedi."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("IPON AI hazır!");
});
