require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const multer = require("multer");

const app = express();

const PORT = process.env.PORT || 3000;

// ----------------------------------------------------
// BASIC MIDDLEWARE
// ----------------------------------------------------

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Serve frontend files
app.use(express.static(__dirname));

// ----------------------------------------------------
// GROQ CONFIGURATION
// ----------------------------------------------------

const GROQ_API_KEY = process.env.GROQ_API_KEY;

const GROQ_MODELS = [
    process.env.GROQ_MODEL,
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant"
].filter(Boolean);

async function callGroq(messages, options = {}) {

    if (!GROQ_API_KEY) {
        throw new Error("GROQ_API_KEY is missing in environment variables.");
    }

    let lastError = null;

    for (const model of GROQ_MODELS) {

        try {

            const response = await axios.post(
                "https://api.groq.com/openai/v1/chat/completions",
                {
                    model,
                    messages,
                    temperature: options.temperature ?? 0.4,
                    max_tokens: options.max_tokens ?? 4000,
                    ...(options.response_format
                        ? { response_format: options.response_format }
                        : {})
                },
                {
                    headers: {
                        Authorization: `Bearer ${GROQ_API_KEY}`,
                        "Content-Type": "application/json"
                    },
                    timeout: options.timeout || 60000
                }
            );

            return response.data.choices?.[0]?.message?.content || "";

        } catch (error) {

            lastError = error;

            console.error(
                `Groq model failed: ${model}`,
                error.response?.data || error.message
            );
        }
    }

    throw lastError || new Error("Groq request failed.");
}

// ----------------------------------------------------
// HOME
// ----------------------------------------------------

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/index.html");
});

// ----------------------------------------------------
// HEALTH CHECK
// ----------------------------------------------------

app.get("/api/health", (req, res) => {

    res.json({
        success: true,
        message: "SkillPath AI server is running",
        timestamp: new Date().toISOString()
    });

});

// ----------------------------------------------------
// GENERAL AI
// ----------------------------------------------------

app.post("/api/ai", async (req, res) => {

    try {

        const { prompt, system } = req.body;

        if (!prompt) {
            return res.status(400).json({
                error: "Prompt is required."
            });
        }

        const messages = [];

        if (system) {
            messages.push({
                role: "system",
                content: system
            });
        }

        messages.push({
            role: "user",
            content: prompt
        });

        const reply = await callGroq(messages);

        res.json({
            success: true,
            reply
        });

    } catch (error) {

        console.error("/api/ai error:", error);

        res.status(500).json({
            error: "AI request failed.",
            details: error.message
        });

    }

});

// ----------------------------------------------------
// AI INTERVIEW
// ----------------------------------------------------

app.post("/api/interview", async (req, res) => {

    try {

        const {
            role,
            question,
            answer,
            difficulty
        } = req.body;

        if (!question) {
            return res.status(400).json({
                error: "Question is required."
            });
        }

        const prompt = `
You are an expert technical interviewer.

Role: ${role || "Software Developer"}
Difficulty: ${difficulty || "medium"}

Interview Question:
${question}

Candidate Answer:
${answer || "(No answer provided)"}

Evaluate the candidate's answer.

Return:

1. Score out of 10
2. What was done well
3. What is missing
4. Correct/improved answer
5. One follow-up interview question

Keep the feedback practical and suitable for a real technical interview.
`;

        const reply = await callGroq([
            {
                role: "system",
                content: "You are a professional technical interviewer."
            },
            {
                role: "user",
                content: prompt
            }
        ]);

        res.json({
            success: true,
            reply
        });

    } catch (error) {

        console.error("/api/interview error:", error);

        res.status(500).json({
            error: "Interview evaluation failed.",
            details: error.message
        });

    }

});

// ----------------------------------------------------
// SALARY NEGOTIATION
// ----------------------------------------------------

app.post("/api/salary-negotiate", async (req, res) => {

    try {

        const {
            role,
            experience,
            currentSalary,
            expectedSalary,
            location,
            offer
        } = req.body;

        const prompt = `
You are a professional salary negotiation coach.

Role: ${role || "Software Engineer"}
Experience: ${experience || "Not specified"}
Current Salary: ${currentSalary || "Not specified"}
Expected Salary: ${expectedSalary || "Not specified"}
Location: ${location || "India"}
Offer: ${offer || "Not specified"}

Provide:

1. Whether the expected salary is reasonable
2. Negotiation strategy
3. A realistic salary range
4. Exact sentences the candidate can say to HR
5. Mistakes to avoid

Be realistic and professional.
`;

        const reply = await callGroq([
            {
                role: "system",
                content: "You are an expert career and salary negotiation advisor."
            },
            {
                role: "user",
                content: prompt
            }
        ]);

        res.json({
            success: true,
            reply
        });

    } catch (error) {

        console.error("/api/salary-negotiate error:", error);

        res.status(500).json({
            error: "Salary negotiation request failed.",
            details: error.message
        });

    }

});

// ====================================================
// MY PATH AI
// ====================================================

app.post("/api/ai-path", async (req, res) => {

    try {

        const {
            interest,
            level = "beginner"
        } = req.body;

        if (!interest || !interest.trim()) {

            return res.status(400).json({
                error: "Interest or skill is required."
            });

        }

        const prompt = `
Create a practical 30-day learning roadmap.

Skill / Career Interest:
${interest}

Current Level:
${level}

Return ONLY valid JSON.

Required structure:

{
  "title": "string",
  "summary": "string",
  "goal": "string",
  "skills": ["string"],
  "days": [
    {
      "day": 1,
      "title": "string",
      "topic": "string",
      "tasks": ["string"],
      "resource": "https://example.com"
    }
  ]
}

Rules:

- Exactly 30 day objects.
- day must be from 1 to 30.
- Make the roadmap realistic.
- Start with fundamentals.
- Gradually increase difficulty.
- Include hands-on practice.
- Include projects.
- Include revision.
- Include interview preparation where appropriate.
- Resource URLs should preferably be official documentation, reputable learning websites, GitHub, or YouTube.
- Do not include markdown.
- Do not include comments outside the JSON.
`;

        const reply = await callGroq(
            [
                {
                    role: "system",
                    content:
                        "You are an expert career roadmap generator. Always return valid JSON."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            {
                temperature: 0.3,
                max_tokens: 7000,
                response_format: {
                    type: "json_object"
                }
            }
        );

        let data;

        try {
            data = JSON.parse(reply);
        } catch (parseError) {

            console.error("AI Path JSON parsing failed:", reply);

            return res.status(500).json({
                error: "AI returned invalid roadmap data."
            });

        }

        res.json({
            success: true,
            ...data
        });

    } catch (error) {

        console.error("/api/ai-path error:", error);

        res.status(500).json({
            error: "Unable to generate AI path.",
            details: error.message
        });

    }

});

// ====================================================
// COURSE CONTENT
// ====================================================

app.post("/api/course-content", async (req, res) => {

    try {

        const {
            course,
            module,
            level = "beginner"
        } = req.body;

        if (!course || !module) {

            return res.status(400).json({
                error: "Course and module are required."
            });

        }

        const prompt = `
Create a complete learning lesson.

Course:
${course}

Module:
${module}

Learner Level:
${level}

Return the lesson as clean HTML.

Include:

<h2>Lesson title</h2>

<p>Simple explanation</p>

<h3>What you will learn</h3>
<ul>...</ul>

<h3>Concept Explanation</h3>
<p>...</p>

<h3>Example</h3>
<pre><code>...</code></pre>

<h3>Important Points</h3>
<ul>...</ul>

<h3>Practice Task</h3>
<p>...</p>

<h3>Interview Questions</h3>
<ul>...</ul>

Rules:

- Make it educational.
- Explain concepts clearly.
- Use examples.
- Use code examples when appropriate.
- Do not use markdown fences.
- Return HTML only.
`;

        const reply = await callGroq(
            [
                {
                    role: "system",
                    content:
                        "You are an expert technical instructor creating high-quality course lessons."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            {
                temperature: 0.4,
                max_tokens: 6000
            }
        );

        res.json({
            success: true,
            html: reply
        });

    } catch (error) {

        console.error("/api/course-content error:", error);

        res.status(500).json({
            error: "Unable to generate course content.",
            details: error.message
        });

    }

});

// ====================================================
// LIVE JOB SEARCH
// ====================================================

function cleanText(value) {

    if (!value) return "";

    return String(value)
        .replace(/<[^>]*>/g, " ")
        .replace(/\s+/g, " ")
        .trim();

}

function matchesQuery(job, query) {

    if (!query) return true;

    const q = query.toLowerCase();

    const searchable = [
        job.title,
        job.company,
        job.location,
        job.description,
        job.category
    ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

    const words = q
        .split(/\s+/)
        .map(word => word.trim())
        .filter(Boolean);

    return words.some(word => searchable.includes(word));

}

async function getArbeitnowJobs() {

    try {

        const response = await axios.get(
            "https://www.arbeitnow.com/api/job-board-api",
            {
                timeout: 20000
            }
        );

        const jobs = response.data?.data || [];

        return jobs.map(job => ({
            title: job.title,
            company: job.company_name,
            location: job.location,
            description: cleanText(job.description),
            url: job.url,
            source: "Arbeitnow",
            remote: job.remote,
            category: job.tags?.join(", ") || ""
        }));

    } catch (error) {

        console.error(
            "Arbeitnow error:",
            error.response?.data || error.message
        );

        return [];

    }

}

async function getRemotiveJobs() {

    try {

        const response = await axios.get(
            "https://remotive.com/api/remote-jobs",
            {
                timeout: 20000
            }
        );

        const jobs = response.data?.jobs || [];

        return jobs.map(job => ({
            title: job.title,
            company: job.company_name,
            location: job.candidate_required_location,
            description: cleanText(job.description),
            url: job.url,
            source: "Remotive",
            remote: true,
            category: job.category || ""
        }));

    } catch (error) {

        console.error(
            "Remotive error:",
            error.response?.data || error.message
        );

        return [];

    }

}

app.get("/api/jobs", async (req, res) => {

    try {

        const query = String(req.query.q || "").trim();

        const [
            arbeitnowJobs,
            remotiveJobs
        ] = await Promise.all([
            getArbeitnowJobs(),
            getRemotiveJobs()
        ]);

        let jobs = [
            ...arbeitnowJobs,
            ...remotiveJobs
        ];

        if (query) {
            jobs = jobs.filter(job => matchesQuery(job, query));
        }

        // Remove duplicate URLs
        const seen = new Set();

        jobs = jobs.filter(job => {

            if (!job.url) return false;

            if (seen.has(job.url)) {
                return false;
            }

            seen.add(job.url);

            return true;

        });

        jobs = jobs.slice(0, 40);

        res.json({
            success: true,
            query,
            count: jobs.length,
            jobs
        });

    } catch (error) {

        console.error("/api/jobs error:", error);

        res.status(500).json({
            error: "Unable to fetch jobs.",
            details: error.message
        });

    }

});

// ====================================================
// TRENDING ARTICLES
// ====================================================

function decodeXml(value) {

    if (!value) return "";

    return value
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'");

}

function parseRSSItems(xml) {

    const items = [];

    const itemRegex = /<item>([\s\S]*?)<\/item>/gi;

    let match;

    while ((match = itemRegex.exec(xml)) !== null) {

        const block = match[1];

        const title =
            block.match(/<title><!\[CDATA\[([\s\S]*?)\]\]><\/title>/i)?.[1] ||
            block.match(/<title>([\s\S]*?)<\/title>/i)?.[1] ||
            "";

        const link =
            block.match(/<link>([\s\S]*?)<\/link>/i)?.[1] ||
            "";

        const pubDate =
            block.match(/<pubDate>([\s\S]*?)<\/pubDate>/i)?.[1] ||
            "";

        const source =
            block.match(
                /<source[^>]*>([\s\S]*?)<\/source>/i
            )?.[1] ||
            "Google News";

        items.push({
            title: decodeXml(title.trim()),
            link: decodeXml(link.trim()),
            pubDate: decodeXml(pubDate.trim()),
            source: decodeXml(source.trim())
        });

    }

    return items;

}

async function getGoogleNewsRSS(query) {

    const url =
        "https://news.google.com/rss/search?q=" +
        encodeURIComponent(query) +
        "&hl=en-IN&gl=IN&ceid=IN:en";

    try {

        const response = await axios.get(url, {
            timeout: 20000,
            headers: {
                "User-Agent": "SkillPath-AI/1.0"
            }
        });

        return parseRSSItems(response.data);

    } catch (error) {

        console.error(
            "Google News RSS error:",
            error.response?.data || error.message
        );

        return [];

    }

}

app.get("/api/trending", async (req, res) => {

    try {

        const [
            aiNews,
            genAINews,
            careerNews
        ] = await Promise.all([
            getGoogleNewsRSS(
                "artificial intelligence technology jobs careers"
            ),
            getGoogleNewsRSS(
                "generative AI machine learning"
            ),
            getGoogleNewsRSS(
                "technology jobs hiring software developer"
            )
        ]);

        const all = [
            ...aiNews,
            ...genAINews,
            ...careerNews
        ];

        const seen = new Set();

        const articles = all.filter(article => {

            if (!article.title || !article.link) {
                return false;
            }

            const key = article.title.toLowerCase();

            if (seen.has(key)) {
                return false;
            }

            seen.add(key);

            return true;

        });

        articles.sort((a, b) => {

            const dateA = new Date(a.pubDate || 0).getTime();
            const dateB = new Date(b.pubDate || 0).getTime();

            return dateB - dateA;

        });

        res.json({
            success: true,
            articles: articles.slice(0, 20)
        });

    } catch (error) {

        console.error("/api/trending error:", error);

        res.status(500).json({
            error: "Unable to load trending articles.",
            details: error.message
        });

    }

});

// ====================================================
// RESUME PDF UPLOAD
// ====================================================

const upload = multer({

    storage: multer.memoryStorage(),

    limits: {
        fileSize: 5 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {

        const isPDF =
            file.mimetype === "application/pdf" ||
            file.originalname.toLowerCase().endsWith(".pdf");

        if (!isPDF) {

            return cb(
                new Error("Only PDF resume files are allowed.")
            );

        }

        cb(null, true);

    }

});

// ----------------------------------------------------
// PDF TEXT EXTRACTION
// ----------------------------------------------------

app.post(
    "/api/resume-upload",
    upload.single("resume"),
    async (req, res) => {

        try {

            if (!req.file) {

                return res.status(400).json({
                    error: "Please upload a PDF resume."
                });

            }

            let PDFParse;

            try {

                const pdfModule = require("pdf-parse");

                PDFParse =
                    pdfModule.PDFParse ||
                    pdfModule.default ||
                    pdfModule;

            } catch (error) {

                return res.status(500).json({
                    error:
                        "pdf-parse package is not installed correctly.",
                    details: error.message
                });

            }

            let text = "";
            let pages = 0;

            // pdf-parse v2
            try {

                if (
                    typeof PDFParse === "function"
                ) {

                    const parser = new PDFParse({
                        data: req.file.buffer
                    });

                    const result = await parser.getText();

                    text = result?.text || "";
                    pages = result?.total || 0;

                    if (typeof parser.destroy === "function") {
                        await parser.destroy();
                    }

                } else {

                    throw new Error(
                        "Unsupported pdf-parse version."
                    );

                }

            } catch (newParserError) {

                console.error(
                    "PDF parsing error:",
                    newParserError.message
                );

                // Compatibility with older pdf-parse versions
                try {

                    const pdfParse = require("pdf-parse");

                    if (typeof pdfParse === "function") {

                        const result = await pdfParse(
                            req.file.buffer
                        );

                        text = result.text || "";
                        pages = result.numpages || 0;

                    } else {

                        throw new Error(
                            "Unable to initialize PDF parser."
                        );

                    }

                } catch (oldParserError) {

                    console.error(
                        "Fallback PDF parser error:",
                        oldParserError.message
                    );

                    return res.status(500).json({
                        error:
                            "Unable to read this PDF file.",
                        details:
                            oldParserError.message
                    });

                }

            }

            text = String(text || "")
                .replace(/\u0000/g, "")
                .replace(/\r/g, "")
                .replace(/[ \t]+\n/g, "\n")
                .replace(/\n{3,}/g, "\n\n")
                .trim();

            if (!text) {

                return res.status(422).json({
                    error:
                        "No readable text was found in this PDF. If the resume is scanned/image-based, OCR is required."
                });

            }

            res.json({
                success: true,
                filename: req.file.originalname,
                pages,
                text,
                textLength: text.length
            });

        } catch (error) {

            console.error(
                "/api/resume-upload error:",
                error
            );

            res.status(500).json({
                error: "Resume PDF processing failed.",
                details: error.message
            });

        }

    }
);

// ----------------------------------------------------
// MULTER ERROR HANDLER
// ----------------------------------------------------

app.use((error, req, res, next) => {

    if (error instanceof multer.MulterError) {

        if (error.code === "LIMIT_FILE_SIZE") {

            return res.status(413).json({
                error: "PDF is too large. Maximum size is 5 MB."
            });

        }

        return res.status(400).json({
            error: error.message
        });

    }

    if (error) {

        return res.status(400).json({
            error: error.message
        });

    }

    next();

});

// ====================================================
// START SERVER
// ====================================================

app.listen(PORT, () => {

    console.log("---------------------------------------");
    console.log("SkillPath AI server running");
    console.log(`http://localhost:${PORT}`);
    console.log("---------------------------------------");

});
