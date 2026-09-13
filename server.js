// server.js - Auto-Detect & Select Best Groq Model (Firebase handles auth client-side now)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// --- 1. CONFIGURATION ---
// No hardcoded fallbacks — set these in Render's Environment tab.
// (Any key that was previously hardcoded here should be treated as leaked and rotated.)
const GROQ_API_KEY = process.env.GROQ_API_KEY;
if (!GROQ_API_KEY) {
    console.error("❌ GROQ_API_KEY is not set. Set it in Render's Environment tab.");
}

// --- 2. GLOBAL VARIABLE FOR MODEL ---
// llama3-8b-8192, llama3-70b-8192, llama-3.1-70b-versatile, and llama-3.3-70b-versatile
// are all decommissioned by Groq. Default to a currently-live model instead.
let ACTIVE_MODEL = "llama-3.1-8b-instant";

// --- 3. AUTO-DETECT FUNCTION ---
async function autoSelectModel() {
    console.log("🔍 Scanning for active Groq models...");
    try {
        const response = await axios.get("https://api.groq.com/openai/v1/models", {
            headers: { 'Authorization': `Bearer ${GROQ_API_KEY}` }
        });
        const models = response.data.data;
        // Re-check current IDs at https://console.groq.com/docs/deprecations periodically.
        const priorities = [
            "llama-3.3-70b-versatile",
            "meta-llama/llama-4-maverick-17b-128e-instruct",
            "meta-llama/llama-4-scout-17b-16e-instruct",
            "llama-3.1-8b-instant"
        ];
        const bestMatch = priorities.find(p => models.some(m => m.id === p));
        if (bestMatch) { ACTIVE_MODEL = bestMatch; console.log(`✅ SELECTED BEST MODEL: ${ACTIVE_MODEL}`); }
    } catch (error) {
        console.error("❌ Model Scan Failed, using fallback:", ACTIVE_MODEL);
    }
}
autoSelectModel();

// --- 4. MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const upload = multer({ storage: multer.memoryStorage() });

// --- 5. AI ENGINE ---
async function getDirectAI(prompt, history = []) {
    const url = "https://api.groq.com/openai/v1/chat/completions";
    const messages = history.map(msg => ({
        role: (msg.role === 'model' || msg.role === 'ai') ? 'assistant' : 'user',
        content: msg.content
    }));
    messages.push({ role: "user", content: prompt });
    try {
        const response = await axios.post(url, {
            model: ACTIVE_MODEL,
            messages: messages,
            temperature: 0.5
        }, {
            headers: { 'Authorization': `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' }
        });
        return response.data.choices[0].message.content;
    } catch (error) {
        const groqMessage = error.response?.data?.error?.message || error.message;
        console.error("AI processing error:", groqMessage);
        return `AI Error: ${groqMessage}`;
    }
}

// --- 6. ROUTES ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/interview', async (req, res) => {
    const { message, history } = req.body;
    const response = await getDirectAI(message, history);
    res.json({ reply: response });
});

app.post('/api/resume-scan', upload.single('resume'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file" });
        const pdfData = await pdfParse(req.file.buffer);
        const text = pdfData.text;
        if (!text || text.length < 50) return res.json({ score: 0, missing: ["Empty"], summary: "PDF has no text." });
        const prompt = `Analyze resume text: "${text.substring(0, 3000)}...". Return ONLY valid JSON: { "score": 85, "missing": ["Skill1"], "summary": "Feedback" }`;
        const rawResponse = await getDirectAI(prompt);
        let cleanJson = rawResponse.replace(/```json/g, '').replace(/```/g, '').trim();
        const match = cleanJson.match(/\{[\s\S]*\}/);
        if (match) cleanJson = match[0];
        res.json(JSON.parse(cleanJson));
    } catch (e) { res.json({ score: 0, missing: ["Error"], summary: "Could not analyze resume." }); }
});

app.post('/api/salary-negotiate', async (req, res) => {
    const script = await getDirectAI(`Write a salary negotiation email for ${req.body.role}.`);
    res.json({ script });
});

app.post('/api/find-jobs', async (req, res) => {
    const data = await getDirectAI(`Generate 3 fake job listings for ${req.body.role}. JSON array: [{"title": "Job", "company": "Co", "location": "Loc", "salary": "$100k"}]`);
    try {
        let clean = data.replace(/```json/g, '').replace(/```/g, '').trim();
        const match = clean.match(/\[[\s\S]*\]/);
        if (match) clean = match[0];
        res.json(JSON.parse(clean));
    } catch (e) { res.json([]); }
});

app.listen(port, () => console.log(`✅ Server running at port ${port}`));
