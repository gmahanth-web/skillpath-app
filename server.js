// server.js - Auto-Detect & Select Best Groq Model (with automatic fallback on failure)
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// --- 1. CONFIGURATION ---
// Never hardcode a fallback key here. Fail loudly instead so a missing
// env var is obvious in the logs rather than silently using a leaked key.
const GROQ_API_KEY = process.env.GROQ_API_KEY;
if (!GROQ_API_KEY) {
    console.error("❌ GROQ_API_KEY is not set. Add it in your environment (e.g. Render's Environment tab).");
}

// --- 2. MODEL LIST ---
// Ordered by preference. Only models actually usable on a standard key belong
// here — Enterprise-tier models (currently llama-3.1-8b-instant and
// llama-3.3-70b-versatile) will 404/403 unless your account has that access,
// so they're kept as long-shot entries at the end, not first.
const MODEL_PRIORITY = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "moonshotai/kimi-k2-instruct",
    "qwen/qwen3-32b",
    "llama-3.3-70b-versatile",   // Enterprise-only as of Sep 2026 — kept in case your account has access
    "llama-3.1-8b-instant"       // Enterprise-only as of Sep 2026 — kept in case your account has access
];

let ACTIVE_MODEL = MODEL_PRIORITY[0];
let AVAILABLE_MODELS = [];

// --- 3. AUTO-DETECT LOGIC ---
async function autoSelectBestModel() {
    console.log("🔍 Scanning Groq API for available models...");
    try {
        const response = await axios.get("https://api.groq.com/openai/v1/models", {
            headers: { 'Authorization': `Bearer ${GROQ_API_KEY}` }
        });

        AVAILABLE_MODELS = response.data.data.map(m => m.id);

        const bestMatch = MODEL_PRIORITY.find(p => AVAILABLE_MODELS.includes(p));

        if (bestMatch) {
            ACTIVE_MODEL = bestMatch;
            console.log(`✅ AUTO-SELECTED BEST MODEL: ${ACTIVE_MODEL}`);
        } else {
            console.warn("⚠️ None of the priority models were found in the account's model list. Keeping default:", ACTIVE_MODEL);
        }
    } catch (error) {
        console.error("❌ Model scan failed. Check if your key is active:", error.message);
    }
}

// Run the scan on startup, then re-check periodically in case Groq
// changes access tiers again while the server is running.
autoSelectBestModel();
setInterval(autoSelectBestModel, 6 * 60 * 60 * 1000); // every 6 hours

// --- 4. AI ENGINE ROUTE (with automatic fallback across the priority list) ---
app.post('/api/ai', async (req, res) => {
    const { prompt } = req.body;
    const url = "https://api.groq.com/openai/v1/chat/completions";

    // Try the currently active model first, then walk the rest of the
    // priority list if it fails with a "model unavailable" style error.
    const candidates = [ACTIVE_MODEL, ...MODEL_PRIORITY.filter(m => m !== ACTIVE_MODEL)];

    let lastError = null;

    for (const model of candidates) {
        try {
            const response = await axios.post(url, {
                model,
                messages: [{ role: "user", content: prompt }],
                temperature: 0.7
            }, {
                headers: {
                    'Authorization': `Bearer ${GROQ_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            });

            // This model worked — remember it so future requests skip straight to it.
            if (ACTIVE_MODEL !== model) {
                console.log(`↪️ Switched active model to ${model} after fallback`);
                ACTIVE_MODEL = model;
            }

            return res.json({
                reply: response.data.choices[0].message.content,
                model_used: model
            });

        } catch (error) {
            const status = error.response?.status;
            const message = error.response?.data?.error?.message || error.message;
            lastError = message;

            // Only fall through to the next model on "model not found / no access"
            // style errors (400/404). Other errors (bad prompt, rate limit, etc.)
            // should surface immediately instead of masking the real problem.
            const isModelAccessError = status === 404 || status === 400 || status === 403;
            console.warn(`⚠️ Model "${model}" failed (${status}): ${message}`);

            if (!isModelAccessError) break;
        }
    }

    console.error("AI processing error — all candidate models failed:", lastError);
    res.status(500).json({ error: "Service unavailable. Check API key status and model access.", detail: lastError });
});

app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});
