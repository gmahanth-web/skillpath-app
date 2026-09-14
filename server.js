// SkillPath AI backend - rebuilt from the last working Claude server
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const multer = require('multer');

let PDFParse = null;
try {
  ({ PDFParse } = require('pdf-parse'));
} catch (_) {}

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const GROQ_API_KEY = process.env.GROQ_API_KEY;

if (!GROQ_API_KEY) {
  console.error('❌ GROQ_API_KEY is not set.');
}

const MODEL_PRIORITY = [
  'openai/gpt-oss-120b',
  'openai/gpt-oss-20b',
  'moonshotai/kimi-k2-instruct',
  'qwen/qwen3-32b',
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant'
];

let ACTIVE_MODEL = MODEL_PRIORITY[0];

async function autoSelectBestModel() {
  if (!GROQ_API_KEY) return;

  try {
    const r = await axios.get(
      'https://api.groq.com/openai/v1/models',
      {
        headers: {
          Authorization: `Bearer ${GROQ_API_KEY}`
        },
        timeout: 10000
      }
    );

    const available = Array.isArray(r.data?.data)
      ? r.data.data.map(m => m.id)
      : [];

    const best = MODEL_PRIORITY.find(m => available.includes(m));

    if (best) {
      ACTIVE_MODEL = best;
    }

    console.log(`✅ Groq model: ${ACTIVE_MODEL}`);
  } catch (e) {
    console.warn('⚠️ Model scan failed:', e.message);
  }
}

autoSelectBestModel();

setInterval(
  autoSelectBestModel,
  6 * 60 * 60 * 1000
);

async function callGroq(messages, options = {}) {
  if (!GROQ_API_KEY) {
    throw new Error('GROQ_API_KEY is missing on the server.');
  }

  const candidates = [
    ACTIVE_MODEL,
    ...MODEL_PRIORITY.filter(m => m !== ACTIVE_MODEL)
  ];

  let lastError = null;

  for (const model of candidates) {
    try {
      const r = await axios.post(
        'https://api.groq.com/openai/v1/chat/completions',
        {
          model,
          messages,
          temperature: options.temperature ?? 0.5,
          max_tokens: options.max_tokens ?? 5000
        },
        {
          headers: {
            Authorization: `Bearer ${GROQ_API_KEY}`,
            'Content-Type': 'application/json'
          },
          timeout: 60000
        }
      );

      ACTIVE_MODEL = model;

      return (
        r.data?.choices?.[0]?.message?.content || ''
      );
    } catch (e) {
      const status = e.response?.status;

      lastError =
        e.response?.data?.error?.message ||
        e.message;

      console.warn(
        `⚠️ Groq ${model} failed (${status}): ${lastError}`
      );

      if (![400, 403, 404, 429].includes(status)) {
        break;
      }
    }
  }

  throw new Error(
    lastError || 'All AI models failed.'
  );
}

function extractJson(text) {
  if (!text) return null;

  const clean = String(text)
    .replace(/```json/gi, '')
    .replace(/```/g, '')
    .trim();

  try {
    return JSON.parse(clean);
  } catch (_) {}

  const obj = clean.match(/\{[\s\S]*\}/);

  if (obj) {
    try {
      return JSON.parse(obj[0]);
    } catch (_) {}
  }

  const arr = clean.match(/\[[\s\S]*\]/);

  if (arr) {
    try {
      return JSON.parse(arr[0]);
    } catch (_) {}
  }

  return null;
}

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    model: ACTIVE_MODEL
  });
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// ====================================================
// GENERAL AI
// ====================================================

app.post('/api/ai', async (req, res) => {
  try {
    const prompt = String(
      req.body?.prompt || ''
    ).trim();

    if (!prompt) {
      return res.status(400).json({
        error: 'Prompt is required.'
      });
    }

    const reply = await callGroq([
      {
        role: 'user',
        content: prompt
      }
    ]);

    res.json({
      reply,
      model_used: ACTIVE_MODEL
    });
  } catch (e) {
    console.error('/api/ai error:', e.message);

    res.status(500).json({
      error: 'AI request failed',
      detail: e.message
    });
  }
});

// ====================================================
// AI INTERVIEW
// ====================================================

app.post('/api/interview', async (req, res) => {
  try {
    const {
      role,
      message,
      history = []
    } = req.body || {};

    const messages = [
      {
        role: 'system',
        content:
          `You are acting as: ${
            role || 'a helpful career assistant'
          }.`
      },

      ...(Array.isArray(history)
        ? history.map(h => ({
            role:
              h.role === 'ai'
                ? 'assistant'
                : 'user',
            content: String(
              h.content || ''
            )
          }))
        : []),

      {
        role: 'user',
        content: String(message || '')
      }
    ];

    const reply = await callGroq(messages);

    res.json({
      reply,
      model_used: ACTIVE_MODEL
    });
  } catch (e) {
    console.error(
      'interview error:',
      e.message
    );

    res.status(500).json({
      error: 'AI request failed',
      detail: e.message
    });
  }
});

// ====================================================
// SALARY NEGOTIATION
// ====================================================

app.post(
  '/api/salary-negotiate',
  async (req, res) => {
    try {
      const {
        role,
        offer,
        experience
      } = req.body || {};

      const prompt = `
Write a professional and polite salary negotiation email/script.

Role: ${role || 'Not specified'}
Current offer: ${offer || 'Not specified'}
Years of experience: ${experience || 'Not specified'}

Give practical, confident and professional negotiation wording.
`;

      const script = await callGroq([
        {
          role: 'user',
          content: prompt
        }
      ]);

      res.json({
        script,
        reply: script
      });
    } catch (e) {
      console.error(
        'salary error:',
        e.message
      );

      res.status(500).json({
        error: 'AI request failed',
        detail: e.message
      });
    }
  }
);

// ====================================================
// MY PATH AI
// ====================================================

app.post('/api/ai-path', async (req, res) => {
  try {
    const interest = String(
      req.body?.interest || ''
    ).trim();

    const level = String(
      req.body?.level || 'beginner'
    );

    if (!interest) {
      return res.status(400).json({
        error: 'Interest is required.'
      });
    }

    const prompt = `
Create a practical 30-day learning roadmap for:

Skill/Career:
${interest}

Learner level:
${level}

Return ONLY valid JSON.

Required format:

{
  "title": "short title",
  "overview": "2-3 sentence overview",
  "days": [
    {
      "day": 1,
      "topic": "topic",
      "tasks": [
        "task 1",
        "task 2",
        "task 3"
      ],
      "resource": "https://..."
    }
  ]
}

Requirements:

- Exactly 30 days.
- Day numbers 1 through 30.
- Start from fundamentals.
- Gradually increase difficulty.
- Include hands-on practice.
- Include projects.
- Include revision.
- Include interview preparation.
- Give useful HTTPS resources.
- No markdown.
`;

    const raw = await callGroq(
      [
        {
          role: 'system',
          content:
            'You are an expert career roadmap generator. Return valid JSON only.'
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      {
        temperature: 0.3,
        max_tokens: 7000
      }
    );

    const plan = extractJson(raw);

    if (!plan || !Array.isArray(plan.days)) {
      throw new Error(
        'AI returned invalid roadmap JSON.'
      );
    }

    plan.days = plan.days
      .slice(0, 30)
      .map((d, index) => ({
        day: index + 1,
        topic:
          d.topic ||
          d.title ||
          `Day ${index + 1}`,
        tasks: Array.isArray(d.tasks)
          ? d.tasks
          : [String(d.tasks || 'Study and practice this topic.')],
        resource:
          d.resource || ''
      }));

    while (plan.days.length < 30) {
      const dayNumber =
        plan.days.length + 1;

      plan.days.push({
        day: dayNumber,
        topic: `Practice and revision - Day ${dayNumber}`,
        tasks: [
          'Review what you learned.',
          'Practice with a small hands-on task.',
          'Write down questions and revise weak areas.'
        ],
        resource: ''
      });
    }

    res.json(plan);
  } catch (e) {
    console.error(
      'ai-path error:',
      e.message
    );

    res.status(500).json({
      error:
        'Could not generate your AI path. Please try again.',
      detail: e.message
    });
  }
});

// ====================================================
// COURSE CONTENT
// ====================================================

app.post(
  '/api/course-content',
  async (req, res) => {
    try {
      const courseTitle = String(
        req.body?.courseTitle ||
        req.body?.course ||
        ''
      ).trim();

      const moduleTitle = String(
        req.body?.moduleTitle ||
        req.body?.module ||
        ''
      ).trim();

      if (!courseTitle || !moduleTitle) {
        return res.status(400).json({
          error:
            'Course and module are required.'
        });
      }

      const prompt = `
Create a complete beginner-friendly lesson.

Course:
${courseTitle}

Module:
${moduleTitle}

Return ONLY HTML suitable for inserting inside a div.

Include:

<h2>Lesson title</h2>

<h3>Learning Objectives</h3>
<ul>...</ul>

<h3>Concept Explanation</h3>
<p>...</p>

<h3>Examples</h3>
<p>...</p>

<pre><code>...</code></pre>

<h3>Common Mistakes</h3>
<ul>...</ul>

<h3>Practice Task</h3>
<p>...</p>

<h3>Quick Recap</h3>
<ul>
<li>...</li>
<li>...</li>
<li>...</li>
</ul>

Rules:

- Clear explanations.
- Beginner friendly.
- Practical examples.
- Code examples when relevant.
- No markdown code fences.
- No html/body/script tags.
`;

      let html = await callGroq(
        [
          {
            role: 'system',
            content:
              'You are an expert technical instructor.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        {
          temperature: 0.4,
          max_tokens: 5000
        }
      );

      html = String(html || '')
        .replace(/```html/gi, '')
        .replace(/```/g, '')
        .trim();

      if (!html) {
        throw new Error(
          'Empty lesson returned.'
        );
      }

      res.json({
        html,
        content: html
      });
    } catch (e) {
      console.error(
        'course-content error:',
        e.message
      );

      res.status(500).json({
        error:
          'Could not generate course content.',
        detail: e.message
      });
    }
  }
);

// ====================================================
// JOB SEARCH
// ====================================================

function jobMatches(job, query) {
  if (!query) return true;

  const words = query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);

  const text = `
    ${job.title || ''}
    ${job.description || ''}
    ${job.company_name || ''}
    ${job.company || ''}
    ${job.location || ''}
    ${job.category || ''}
  `.toLowerCase();

  return words.some(word =>
    text.includes(word)
  );
}

async function fetchArbeitnow(query) {
  try {
    const response = await axios.get(
      'https://www.arbeitnow.com/api/job-board-api',
      {
        timeout: 15000
      }
    );

    const jobs = Array.isArray(
      response.data?.data
    )
      ? response.data.data
      : [];

    return jobs
      .filter(job =>
        jobMatches(job, query)
      )
      .filter(job => job.url)
      .map(job => ({
        title:
          job.title ||
          'Job opening',

        company:
          job.company_name ||
          'Company',

        location:
          job.location ||
          (job.remote
            ? 'Remote'
            : 'Not specified'),

        salary:
          job.salary ||
          'Not listed',

        url: job.url,

        source: 'Arbeitnow',

        description:
          job.description || ''
      }));
  } catch (e) {
    console.warn(
      'Arbeitnow unavailable:',
      e.message
    );

    return [];
  }
}

async function fetchRemotive(query) {
  try {
    const response = await axios.get(
      'https://remotive.com/api/remote-jobs',
      {
        params: {
          search: query,
          limit: 30
        },
        timeout: 15000
      }
    );

    const jobs = Array.isArray(
      response.data?.jobs
    )
      ? response.data.jobs
      : [];

    return jobs
      .filter(job => job.url)
      .map(job => ({
        title:
          job.title ||
          'Job opening',

        company:
          job.company_name ||
          'Company',

        location:
          job.candidate_required_location ||
          'Remote',

        salary:
          job.salary ||
          'Not listed',

        url: job.url,

        source: 'Remotive',

        description:
          job.description || ''
      }));
  } catch (e) {
    console.warn(
      'Remotive unavailable:',
      e.message
    );

    return [];
  }
}

app.get('/api/jobs', async (req, res) => {
  try {
    const query = String(
      req.query.q ||
      'software developer'
    ).trim();

    const [
      arbeitnow,
      remotive
    ] = await Promise.all([
      fetchArbeitnow(query),
      fetchRemotive(query)
    ]);

    const combined = [
      ...arbeitnow,
      ...remotive
    ];

    const seen = new Set();

    const unique = combined.filter(job => {
      if (!job.url) return false;

      if (seen.has(job.url)) {
        return false;
      }

      seen.add(job.url);

      return true;
    });

    res.json(
      unique.slice(0, 30)
    );
  } catch (e) {
    console.error(
      'jobs error:',
      e.message
    );

    res.json([]);
  }
});

// ====================================================
// OLD JOB API COMPATIBILITY
// ====================================================

app.post(
  '/api/find-jobs',
  async (req, res) => {
    try {
      const role = String(
        req.body?.role ||
        req.body?.query ||
        'software developer'
      ).trim();

      const jobs =
        await fetchArbeitnow(role);

      const remotive =
        jobs.length < 5
          ? await fetchRemotive(role)
          : [];

      const combined = [
        ...jobs,
        ...remotive
      ];

      const seen = new Set();

      const unique = combined.filter(job => {
        if (!job.url) return false;

        if (seen.has(job.url)) {
          return false;
        }

        seen.add(job.url);

        return true;
      });

      res.json(
        unique.slice(0, 20)
      );
    } catch (e) {
      res.json([]);
    }
  }
);

// ====================================================
// TRENDING ARTICLES
// ====================================================

function decodeXml(value) {
  return String(value || '')
    .replace(
      /<!\[CDATA\[([\s\S]*?)\]\]>/g,
      '$1'
    )
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'");
}

function parseRSS(xml) {
  const items = [];

  const matches = String(xml || '')
    .matchAll(
      /<item>([\s\S]*?)<\/item>/gi
    );

  for (const match of matches) {
    const item = match[1];

    function getTag(tag) {
      const regex = new RegExp(
        `<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`,
        'i'
      );

      const result =
        item.match(regex);

      return result
        ? decodeXml(result[1]).trim()
        : '';
    }

    const title = getTag('title');
    const link = getTag('link');
    const source = getTag('source');
    const pubDate = getTag('pubDate');

    if (title && link) {
      items.push({
        title,
        url: link,
        src:
          source ||
          'Google News',
        published: pubDate
      });
    }
  }

  return items;
}

async function fetchNewsFeed(query) {
  const url =
    'https://news.google.com/rss/search?q=' +
    encodeURIComponent(query) +
    '&hl=en-IN&gl=IN&ceid=IN:en';

  try {
    const response = await axios.get(
      url,
      {
        timeout: 15000,
        headers: {
          'User-Agent':
            'SkillPathAI/1.0'
        }
      }
    );

    return parseRSS(
      response.data
    );
  } catch (e) {
    console.warn(
      'News feed unavailable:',
      e.message
    );

    return [];
  }
}

app.get(
  '/api/trending',
  async (req, res) => {
    try {
      const feeds = await Promise.all([
        fetchNewsFeed(
          'AI technology jobs career'
        ),

        fetchNewsFeed(
          'artificial intelligence generative AI'
        ),

        fetchNewsFeed(
          'machine learning technology careers'
        )
      ]);

      const all = feeds.flat();

      const seen = new Set();

      const unique = all.filter(article => {
        const key =
          article.url ||
          article.title;

        if (seen.has(key)) {
          return false;
        }

        seen.add(key);

        return true;
      });

      unique.sort((a, b) => {
        const dateA = new Date(
          a.published || 0
        ).getTime();

        const dateB = new Date(
          b.published || 0
        ).getTime();

        return dateB - dateA;
      });

      // IMPORTANT:
      // Return a plain array because
      // the original frontend uses articles.map()
      res.json(
        unique.slice(0, 15)
      );
    } catch (e) {
      console.error(
        'trending error:',
        e.message
      );

      res.json([]);
    }
  }
);

// ====================================================
// RESUME PDF UPLOAD
// ====================================================

const upload = multer({
  storage:
    multer.memoryStorage(),

  limits: {
    fileSize:
      5 * 1024 * 1024
  },

  fileFilter: (
    req,
    file,
    cb
  ) => {
    const isPDF =
      file.mimetype ===
        'application/pdf' ||
      file.originalname
        .toLowerCase()
        .endsWith('.pdf');

    if (!isPDF) {
      return cb(
        new Error(
          'Only PDF files are allowed.'
        ),
        false
      );
    }

    cb(null, true);
  }
});

app.post(
  '/api/resume-upload',
  upload.single('resume'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error:
            'Please upload a PDF file.'
        });
      }

      if (!PDFParse) {
        return res.status(500).json({
          error:
            'PDF parser is not installed. Run npm install.'
        });
      }

      let parser = null;

      try {
        parser = new PDFParse({
          data: req.file.buffer
        });

        const result =
          await parser.getText();

        const text = String(
          result?.text || ''
        ).trim();

        const pages =
          Number(
            result?.total ||
            result?.numpages ||
            result?.pages ||
            1
          );

        if (!text) {
          return res.status(422).json({
            error:
              'This PDF appears to be image-only or scanned. No readable text was found.'
          });
        }

        res.json({
          success: true,
          filename:
            req.file.originalname,
          pages,
          text,
          textLength:
            text.length
        });
      } finally {
        if (
          parser &&
          typeof parser.destroy ===
            'function'
        ) {
          await parser
            .destroy()
            .catch(() => {});
        }
      }
    } catch (e) {
      console.error(
        'resume-upload error:',
        e.message
      );

      res.status(500).json({
        error:
          'Could not read the PDF.',
        detail: e.message
      });
    }
  }
);

// ====================================================
// MULTER ERROR HANDLER
// ====================================================

app.use(
  (err, req, res, next) => {
    if (
      err instanceof multer.MulterError
    ) {
      return res.status(400).json({
        error:
          err.code ===
          'LIMIT_FILE_SIZE'
            ? 'PDF must be 5 MB or smaller.'
            : err.message
      });
    }

    if (err) {
      return res.status(400).json({
        error: err.message
      });
    }

    next();
  }
);

// ====================================================
// START SERVER
// ====================================================

app.listen(
  port,
  () => {
    console.log(
      `🚀 SkillPath server running on port ${port}`
    );
  }
);
