// server.js - Auto-Detect & Select Best Groq Model (with automatic fallback on failure)
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Serve index.html and any other static assets (css/js/images) from the
// project root. Without this, Express has no route for GET / and returns
// "Cannot GET /" — this line was missing again in the last upload.
app.use(express.static(__dirname));

// --- 1. CONFIGURATION ---
const GROQ_API_KEY = process.env.GROQ_API_KEY;
if (!GROQ_API_KEY) {
    console.error("❌ GROQ_API_KEY is not set. Add it in your environment (e.g. Render's Environment tab).");
}

// --- 2. MODEL LIST ---
// Ordered by preference. Enterprise-tier models (llama-3.1-8b-instant,
// llama-3.3-70b-versatile) are kept as long-shot entries at the end since
// they 404/403 unless your account specifically has that access.
const MODEL_PRIORITY = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "moonshotai/kimi-k2-instruct",
    "qwen/qwen3-32b",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant"
];

let ACTIVE_MODEL = MODEL_PRIORITY[0];

// --- 3. AUTO-DETECT LOGIC ---
async function autoSelectBestModel() {
    console.log("🔍 Scanning Groq API for available models...");
    try {
        const response = await axios.get("https://api.groq.com/openai/v1/models", {
            headers: { 'Authorization': `Bearer ${GROQ_API_KEY}` }
        });
        const availableModels = response.data.data.map(m => m.id);
        const bestMatch = MODEL_PRIORITY.find(p => availableModels.includes(p));
        if (bestMatch) {
            ACTIVE_MODEL = bestMatch;
            console.log(`✅ AUTO-SELECTED BEST MODEL: ${ACTIVE_MODEL}`);
        } else {
            console.warn("⚠️ None of the priority models were found. Keeping default:", ACTIVE_MODEL);
        }
    } catch (error) {
        console.error("❌ Model scan failed. Check if your key is active:", error.message);
    }
}
autoSelectBestModel();
setInterval(autoSelectBestModel, 6 * 60 * 60 * 1000);

// --- 4. SHARED GROQ CALL (with fallback across the priority list) ---
// Used by every AI-backed route below so the fallback logic lives in one place.
async function callGroq(messages) {
    const url = "https://api.groq.com/openai/v1/chat/completions";
    const candidates = [ACTIVE_MODEL, ...MODEL_PRIORITY.filter(m => m !== ACTIVE_MODEL)];
    let lastError = null;

    for (const model of candidates) {
        try {
            const response = await axios.post(url, {
                model,
                messages,
                temperature: 0.7
            }, {
                headers: {
                    'Authorization': `Bearer ${GROQ_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            });

            if (ACTIVE_MODEL !== model) {
                console.log(`↪️ Switched active model to ${model} after fallback`);
                ACTIVE_MODEL = model;
            }
            return { reply: response.data.choices[0].message.content, model_used: model };

        } catch (error) {
            const status = error.response?.status;
            lastError = error.response?.data?.error?.message || error.message;
            console.warn(`⚠️ Model "${model}" failed (${status}): ${lastError}`);
            const isModelAccessError = status === 404 || status === 400 || status === 403;
            if (!isModelAccessError) break;
        }
    }
    throw new Error(lastError || "All candidate models failed");
}

// --- 5. ROUTES ---

// General chat prompt (kept for backward compatibility with any direct callers)
app.post('/api/ai', async (req, res) => {
    try {
        const { prompt } = req.body;
        const result = await callGroq([{ role: "user", content: prompt }]);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: "Service unavailable. Check API key status and model access.", detail: err.message });
    }
});

// Used by: interview chat, resume ATS scanner, AI learning path generator
app.post('/api/interview', async (req, res) => {
    try {
        const { role, message, history = [] } = req.body;
        const messages = [
            { role: "system", content: `You are acting as: ${role || "a helpful career assistant"}.` },
            ...history.map(h => ({ role: h.role === 'ai' ? 'assistant' : 'user', content: h.content })),
            { role: "user", content: message }
        ];
        const result = await callGroq(messages);
        res.json({ reply: result.reply });
    } catch (err) {
        console.error("interview error:", err.message);
        res.status(500).json({ error: "AI request failed", detail: err.message });
    }
});

// Used by: salary negotiation script generator
app.post('/api/salary-negotiate', async (req, res) => {
    try {
        const { role, offer, experience } = req.body;
        const prompt = `Write a professional, polite salary negotiation email script. Role: ${role}. Current offer: ${offer}. Years of experience: ${experience}. Keep it concise and confident.`;
        const result = await callGroq([{ role: "user", content: prompt }]);
        res.json({ script: result.reply });
    } catch (err) {
        console.error("salary-negotiate error:", err.message);
        res.status(500).json({ error: "AI request failed", detail: err.message });
    }
});

// Used by: skill matcher and live jobs feed. Returns a plain JSON array,
// since the frontend maps directly over the response.
app.post('/api/find-jobs', async (req, res) => {
    try {
        const { role } = req.body;
        const prompt = `List 5 realistic, currently plausible job openings for someone with these skills/role: "${role}". Return ONLY a valid JSON array, no markdown fences, no commentary. Each item: { "title": "...", "company": "...", "location": "...", "salary": "..." }`;
        const result = await callGroq([{ role: "user", content: prompt }]);
        let clean = result.reply.replace(/```json/g, '').replace(/```/g, '').trim();
        const match = clean.match(/\[[\s\S]*\]/);
        if (match) clean = match[0];
        const jobs = JSON.parse(clean);
        res.json(jobs);
    } catch (err) {
        console.error("find-jobs error:", err.message);
        res.status(500).json([]);
    }
});

app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});
