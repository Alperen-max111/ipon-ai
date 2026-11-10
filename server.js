
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
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

const SYSTEM = `
Sen IPON AI isimli akıllı bir asistansın.
Türkçe konuş.
Doğal ve samimi ol.
Aynı cevapları gereksiz yere tekrarlama.
Önceki konuşmaları dikkate al.
Kod yazabilir ve sorun çözebilirsin.
Bilmediğin bilgileri uydurma.
`;

app.get("/", (req, res) => {
  res.send("IPON AI çalışıyor!");
});

app.post("/api/chat", async (req, res) => {
  try {
    const messages = req.body.messages;

    if (!Array.isArray(messages) ||
        messages.length === 0 ||
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

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${GROQ_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          messages: [
            { role: "system", content: SYSTEM },
            ...clean
          ],
          temperature: 0.8
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.error?.message || "Groq bağlantı hatası."
      );
    }

    res.json({
      answer: data.choices[0].message.content
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

});
