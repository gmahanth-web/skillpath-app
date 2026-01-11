// server.js - Auto-Detect & Select Best Groq Model
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');
const multer = require('multer');
const pdfParse = require('pdf-parse'); 

const app = express();
const port = process.env.PORT || 3000;

// --- 1. CONFIGURATION ---
const GOOGLE_CLIENT_ID = "451204160392-h75kaosps63hqkom5h0rk41bpggb0s41.apps.googleusercontent.com";
const GOOGLE_CLIENT_SECRET = "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"; 

// ✅ YOUR GROQ KEY
const GROQ_API_KEY = "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"; 

const MONGO_URI = "mongodb+srv://gmahanth_db_user:gh5VrTr99zy1U288@skillpath.qbtqjzy.mongodb.net/skillpath?retryWrites=true&w=majority&appName=skillpath";

// --- 2. GLOBAL VARIABLE FOR MODEL ---
let ACTIVE_MODEL = "llama3-8b-8192"; // Default fallback

// --- 3. AUTO-DETECT FUNCTION ---
async function autoSelectModel() {
    console.log("🔍 Scanning for active Groq models...");
    try {
        const response = await axios.get("https://api.groq.com/openai/v1/models", {
            headers: { 'Authorization': `Bearer ${GROQ_API_KEY}` }
        });

        const models = response.data.data;
        console.log("\n📋 AVAILABLE MODELS:");
        models.forEach(m => console.log(`   - ${m.id}`));

        // Priority List (Try the best ones first)
        const priorities = [
            "llama-3.3-70b-versatile",
            "llama-3.1-70b-versatile",
            "llama3-70b-8192",
            "llama-3.1-8b-instant",
            "llama3-8b-8192"
        ];

        // Find the first matching model from our priority list that actually exists
        const bestMatch = priorities.find(p => models.some(m => m.id === p));

        if (bestMatch) {
            ACTIVE_MODEL = bestMatch;
            console.log(`\n✅ SELECTED BEST MODEL: ${ACTIVE_MODEL}\n`);
        } else {
            console.log(`\n⚠️ No priority model found. Using fallback: ${ACTIVE_MODEL}\n`);
        }

    } catch (error) {
        console.error("❌ Model Scan Failed:", error.message);
        console.log("Using default fallback model.");
    }
}

// Run the scan immediately on startup
autoSelectModel();

// --- 4. MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));
app.use(session({ secret: 'skillpath_secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
const upload = multer({ storage: multer.memoryStorage() });

// --- 5. DATABASE ---
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.log("❌ DB Error:", err));

const UserSchema = new mongoose.Schema({ username: String, googleId: String, email: String });
const User = mongoose.model('User', UserSchema);

// --- 6. AUTH ---
passport.use(new GoogleStrategy({ clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET, callbackURL: "http://localhost:3000/auth/google/callback" },
  async (token, tokenSecret, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) { user = new User({ username: profile.displayName, googleId: profile.id, email: profile.emails[0].value }); await user.save(); }
        return done(null, user);
    } catch (err) { return done(err, null); }
  }
));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => { const user = await User.findById(id); done(null, user); });

// --- 7. AI ENGINE (Uses Auto-Selected Model) ---
async function getDirectAI(prompt, history = []) {
    const url = "https://api.groq.com/openai/v1/chat/completions";
    
    // Convert to OpenAI format
    const messages = history.map(msg => ({
        role: (msg.role === 'model' || msg.role === 'ai') ? 'assistant' : 'user', 
        content: msg.content
    }));
    messages.push({ role: "user", content: prompt });

    try {
        const response = await axios.post(url, {
            model: ACTIVE_MODEL, // ✅ Uses the auto-detected model
            messages: messages,
            temperature: 0.5
        }, {
            headers: {
                'Authorization': `Bearer ${GROQ_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        return response.data.choices[0].message.content;

    } catch (error) {
        console.error(`❌ AI Error (${ACTIVE_MODEL}):`, error.response ? error.response.data : error.message);
        
        // If the selected model fails, try one quick fallback
        if (ACTIVE_MODEL !== "llama3-8b-8192") {
            console.log("⚠️ Switching to backup model: llama3-8b-8192");
            ACTIVE_MODEL = "llama3-8b-8192";
            return await getDirectAI(prompt, history); // Retry once
        }
        return "AI Error: Service unavailable.";
    }
}

// --- 8. ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/?loggedin=true'));
app.get('/api/current_user', (req, res) => res.json(req.isAuthenticated() ? { success: true, user: req.user } : { success: false }));
app.get('/api/logout', (req, res) => req.logout(() => res.redirect('/')));

// CHAT
app.post('/api/interview', async (req, res) => {
    const { message, history } = req.body;
    const response = await getDirectAI(message, history); 
    res.json({ reply: response });
});

// RESUME
app.post('/api/resume-scan', upload.single('resume'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file" });
        console.log("📄 Reading PDF...");
        const pdfData = await pdfParse(req.file.buffer);
        const text = pdfData.text;

        if(!text || text.length < 50) return res.json({ score: 0, missing: ["Empty"], summary: "PDF has no text." });

        const prompt = `Analyze resume text: "${text.substring(0, 3000)}...". 
        Return ONLY valid JSON: { "score": 85, "missing": ["Skill1"], "summary": "Feedback" }`;
        
        const rawResponse = await getDirectAI(prompt);
        let cleanJson = rawResponse.replace(/```json/g, '').replace(/```/g, '').trim();
        const match = cleanJson.match(/\{[\s\S]*\}/);
        if (match) cleanJson = match[0];

        res.json(JSON.parse(cleanJson));
    } catch (e) {
        console.log("Resume Error:", e);
        res.json({ score: 0, missing: ["Error"], summary: "Could not analyze resume." });
    }
});

// SALARY
app.post('/api/salary-negotiate', async (req, res) => {
    const script = await getDirectAI(`Write a salary negotiation email for ${req.body.role}.`);
    res.json({ script });
});

// JOBS
app.post('/api/find-jobs', async (req, res) => {
    const data = await getDirectAI(`Generate 3 fake job listings for ${req.body.role}. JSON array: [{"title": "Job", "company": "Co", "location": "Loc", "salary": "$100k"}]`);
    try { 
        let clean = data.replace(/```json/g, '').replace(/```/g, '').trim();
        const match = clean.match(/\[[\s\S]*\]/);
        if(match) clean = match[0];
        res.json(JSON.parse(clean)); 
    } catch(e) { res.json([]); }
});

app.listen(port, () => console.log(`✅ Server running at http://localhost:${port}`));