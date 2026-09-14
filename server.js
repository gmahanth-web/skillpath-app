// server.js - SkillPath AI backend
require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const multer = require('multer');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(__dirname));

const GROQ_API_KEY = process.env.GROQ_API_KEY;

if (!GROQ_API_KEY) {
  console.error("❌ GROQ_API_KEY is not set.");
}

const MODEL_PRIORITY = [
  "openai/gpt-oss-120b",
  "openai/gpt-oss-20b",
  "moonshotai/kimi-k2-instruct",
  "qwen/qwen3-32b",
  "llama-3.3-70b-versatile",
  "llama-3.1-8b-instant"
];

let ACTIVE_MODEL = MODEL_PRIORITY[0];


/* =========================================================
   CACHE
========================================================= */

const trendCache = {
  at: 0,
  articles: []
};

const courseCache = new Map();

const TREND_CACHE_MS = 5 * 60 * 1000;


/* =========================================================
   GROQ MODEL SELECTION
========================================================= */

async function autoSelectBestModel() {
  if (!GROQ_API_KEY) return;

  try {
    const r = await axios.get(
      "https://api.groq.com/openai/v1/models",
      {
        headers: {
          Authorization: `Bearer ${GROQ_API_KEY}`
        }
      }
    );

    const available = (r.data.data || []).map(m => m.id);

    const best = MODEL_PRIORITY.find(
      m => available.includes(m)
    );

    if (best) {
      ACTIVE_MODEL = best;
    }

    console.log(`✅ Groq model: ${ACTIVE_MODEL}`);

  } catch (e) {
    console.warn(
      "⚠️ Model scan failed:",
      e.message
    );
  }
}

autoSelectBestModel();

setInterval(
  autoSelectBestModel,
  6 * 60 * 60 * 1000
);


/* =========================================================
   GROQ REQUEST
========================================================= */

async function callGroq(messages, options = {}) {

  if (!GROQ_API_KEY) {
    throw new Error(
      "GROQ_API_KEY is missing on the server."
    );
  }

  const candidates = [
    ACTIVE_MODEL,
    ...MODEL_PRIORITY.filter(
      m => m !== ACTIVE_MODEL
    )
  ];

  let lastError = null;

  for (const model of candidates) {

    try {

      const response = await axios.post(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          model,
          messages,
          temperature:
            options.temperature ?? 0.5,
          max_tokens:
            options.max_tokens ?? 5000
        },
        {
          headers: {
            Authorization:
              `Bearer ${GROQ_API_KEY}`,
            "Content-Type":
              "application/json"
          }
        }
      );

      ACTIVE_MODEL = model;

      return response.data.choices[0]
        .message.content;

    } catch (e) {

      lastError =
        e.response?.data?.error?.message ||
        e.message;

      const status =
        e.response?.status;

      console.warn(
        `⚠️ Groq ${model} failed (${status}): ${lastError}`
      );

      if (
        ![400, 403, 404, 429]
          .includes(status)
      ) {
        break;
      }
    }
  }

  throw new Error(
    lastError ||
    "All AI models failed."
  );
}


/* =========================================================
   JSON EXTRACTION
========================================================= */

function extractJson(
  text,
  fallback = null
) {

  if (!text) return fallback;

  let clean = String(text)
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .trim();

  try {
    return JSON.parse(clean);
  } catch (_) {}

  const object =
    clean.match(/\{[\s\S]*\}/);

  if (object) {
    try {
      return JSON.parse(object[0]);
    } catch (_) {}
  }

  const array =
    clean.match(/\[[\s\S]*\]/);

  if (array) {
    try {
      return JSON.parse(array[0]);
    } catch (_) {}
  }

  return fallback;
}


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get('/api/health', (req, res) => {

  res.json({
    ok: true,
    aiConfigured:
      Boolean(GROQ_API_KEY),
    model: ACTIVE_MODEL
  });

});


/* =========================================================
   GENERAL AI
========================================================= */

app.post('/api/ai', async (req, res) => {

  try {

    const reply =
      await callGroq([
        {
          role: "user",
          content:
            req.body.prompt || ""
        }
      ]);

    res.json({
      reply,
      model_used: ACTIVE_MODEL
    });

  } catch (e) {

    res.status(500).json({
      error: e.message
    });

  }

});


/* =========================================================
   AI INTERVIEW
========================================================= */

app.post(
  '/api/interview',
  async (req, res) => {

    try {

      const {
        role,
        message,
        history = []
      } = req.body;

      const messages = [

        {
          role: "system",
          content:
            `You are acting as: ${
              role ||
              "a helpful career assistant"
            }.`
        },

        ...history.map(h => ({
          role:
            h.role === 'ai'
              ? 'assistant'
              : 'user',

          content:
            h.content
        })),

        {
          role: "user",
          content:
            message || ""
        }

      ];

      const reply =
        await callGroq(messages);

      res.json({
        reply
      });

    } catch (e) {

      console.error(
        "interview error:",
        e.message
      );

      res.status(500).json({
        error: "AI request failed",
        detail: e.message
      });

    }

  }
);


/* =========================================================
   SALARY NEGOTIATION
========================================================= */

app.post(
  '/api/salary-negotiate',
  async (req, res) => {

    try {

      const {
        role,
        offer,
        experience
      } = req.body;

      const reply =
        await callGroq([
          {
            role: "user",
            content:
              `Write a professional, polite salary negotiation email script.

Role: ${role}
Current offer: ${offer}
Experience: ${experience}

Keep it concise and confident.`
          }
        ]);

      res.json({
        script: reply
      });

    } catch (e) {

      res.status(500).json({
        error: "AI request failed",
        detail: e.message
      });

    }

  }
);


/* =========================================================
   AI CAREER PATH
   REALISTIC 30-DAY ROADMAP
========================================================= */

app.post(
  '/api/ai-path',
  async (req, res) => {

    try {

      const interest =
        String(
          req.body.interest || ''
        ).trim();

      const level =
        String(
          req.body.level ||
          'beginner'
        ).trim();

      const hoursPerDay =
        Math.min(
          Math.max(
            Number(
              req.body.hoursPerDay
            ) || 1.5,
            0.5
          ),
          3
        );

      if (!interest) {

        return res.status(400).json({
          error:
            "Interest is required."
        });

      }


      const prompt = `Create a REALISTIC 30-day learning roadmap for "${interest}" for a ${level} learner.

Assume about ${hoursPerDay} hours per day and 6 learning days + 1 lighter review day per week.

The plan must be practical for a person who also has college/work.

Do not overload each day.

Progression:

foundations
-> guided practice
-> small exercises
-> mini project
-> debugging/review
-> capstone
-> portfolio/interview readiness.

Every day must have a concrete outcome.

Include deliberate practice and review, not just watching videos.

Use realistic time estimates and one small deliverable/checkpoint where appropriate.

Avoid pretending that someone can master an entire professional field in 30 days.

Frame the result as a foundation and portfolio-ready starter path.

Prefer stable, reputable resources such as:

- official documentation
- freeCodeCamp
- MDN
- Python documentation
- Kaggle
- Google
- Microsoft Learn
- AWS Skill Builder

If you are not confident a specific URL is correct, leave resource as an empty string rather than inventing a URL.


Return ONLY valid JSON with EXACTLY this shape:

{
  "title": "short title",
  "overview": "2-3 sentences explaining what can realistically be achieved in 30 days",
  "time_per_day": "1.5 hours/day",
  "days": [
    {
      "day": 1,
      "topic": "...",
      "type": "Learn + Practice",
      "time": "60-90 min",
      "tasks": [
        "...",
        "...",
        "..."
      ],
      "deliverable": "...",
      "resource": "https://..."
    }
  ]
}

Exactly 30 day objects.

Days must be numbered 1 through 30.

Do not include markdown or commentary.`;


      const reply =
        await callGroq(
          [
            {
              role: "user",
              content: prompt
            }
          ],
          {
            temperature: 0.25,
            max_tokens: 6000
          }
        );


      const plan =
        extractJson(reply);


      if (
        !plan ||
        !Array.isArray(plan.days) ||
        plan.days.length < 30
      ) {

        throw new Error(
          "AI returned an incomplete roadmap."
        );

      }


      plan.days =
        plan.days
          .slice(0, 30)
          .map((d, i) => ({

            day: i + 1,

            topic:
              String(
                d.topic ||
                d.title ||
                `Day ${i + 1}`
              ),

            type:
              String(
                d.type ||
                (
                  i % 7 === 6
                    ? 'Review + Reflection'
                    : 'Learn + Practice'
                )
              ),

            time:
              String(
                d.time ||
                `${Math.round(
                  hoursPerDay * 60
                )} min`
              ),

            tasks:
              Array.isArray(d.tasks)
                ? d.tasks
                    .slice(0, 4)
                    .map(String)
                : [],

            deliverable:
              String(
                d.deliverable || ''
              ),

            resource:
              /^https?:\/\//i.test(
                String(
                  d.resource || ''
                )
              )
                ? String(d.resource)
                : ''

          }));


      res.json({

        title:
          plan.title ||
          `${interest} — 30-Day Starter Path`,

        overview:
          plan.overview ||
          `A practical foundation in ${interest} with daily practice and a small portfolio project.`,

        time_per_day:
          plan.time_per_day ||
          `${hoursPerDay} hours/day`,

        days:
          plan.days

      });


    } catch (e) {

      console.error(
        "ai-path error:",
        e.message
      );

      res.status(500).json({
        error: e.message
      });

    }

  }
);


/* =========================================================
   AI COURSE CONTENT
========================================================= */

app.post(
  '/api/course-content',
  async (req, res) => {

    try {

      const courseTitle =
        String(
          req.body.courseTitle ||
          ''
        ).trim();

      const moduleTitle =
        String(
          req.body.moduleTitle ||
          ''
        ).trim();


      if (
        !courseTitle ||
        !moduleTitle
      ) {

        return res.status(400).json({
          error:
            "Course and module are required."
        });

      }


      const key =
        `${courseTitle}::${moduleTitle}`
          .toLowerCase();


      if (
        courseCache.has(key)
      ) {

        return res.json({
          html:
            courseCache.get(key),
          cached: true
        });

      }


      const reply =
        await callGroq(
          [
            {
              role: "user",
              content:
                `Create a concise but complete beginner-friendly lesson for "${moduleTitle}" in "${courseTitle}".

Return ONLY HTML suitable for inserting inside a div.

Include:

- learning objectives
- explanation
- one small example or code block if relevant
- common mistakes
- a 3-question quick recap

Keep it useful but not excessively long.

Roughly 500-900 words.

Do not include:

html
body
script

tags.`
            }
          ],
          {
            temperature: 0.35,
            max_tokens: 2800
          }
        );


      const html =
        reply
          .replace(
            /```html/gi,
            ''
          )
          .replace(
            /```/g,
            ''
          )
          .trim();


      if (!html) {

        throw new Error(
          'AI returned empty lesson content.'
        );

      }


      courseCache.set(
        key,
        html
      );


      res.json({
        html,
        cached: false
      });


    } catch (e) {

      console.error(
        "course-content error:",
        e.message
      );

      res.status(500).json({
        error:
          "Lesson generation failed. A built-in lesson will be shown instead."
      });

    }

  }
);


/* =========================================================
   JOBS
   REAL PUBLIC JOB SOURCES
========================================================= */

app.get(
  '/api/jobs',
  async (req, res) => {

    const q =
      String(
        req.query.q ||
        'software developer'
      )
        .trim()
        .toLowerCase();


    if (!q) {

      return res.json({
        jobs: []
      });

    }


    try {

      const results = [];


      /* -----------------------------------------------------
         ARBEITNOW
      ----------------------------------------------------- */

      try {

        const r =
          await axios.get(
            'https://www.arbeitnow.com/api/job-board-api',
            {
              timeout: 12000
            }
          );


        const jobs =
          Array.isArray(
            r.data?.data
          )
            ? r.data.data
            : [];


        for (const j of jobs) {

          const hay =
            `${j.title || ''} ${
              j.description || ''
            } ${
              j.company_name || ''
            }`
              .toLowerCase();


          const terms =
            q
              .split(/\s+/)
              .filter(Boolean);


          if (
            !terms.some(
              term =>
                hay.includes(term)
            )
          ) {
            continue;
          }


          results.push({

            title:
              j.title,

            company:
              j.company_name ||
              'Company',

            location:
              j.location ||
              (
                j.remote
                  ? 'Remote'
                  : 'Not specified'
              ),

            salary:
              j.salary ||
              'Not listed',

            url:
              j.url,

            source:
              'Arbeitnow'

          });


          if (
            results.length >= 15
          ) {
            break;
          }

        }

      } catch (e) {

        console.warn(
          'Arbeitnow jobs unavailable:',
          e.message
        );

      }


      /* -----------------------------------------------------
         REMOTIVE
      ----------------------------------------------------- */

      if (
        results.length < 10
      ) {

        try {

          const r =
            await axios.get(
              'https://remotive.com/api/remote-jobs',
              {
                params: {
                  search: q,
                  limit: 20
                },
                timeout: 12000
              }
            );


          const jobs =
            Array.isArray(
              r.data?.jobs
            )
              ? r.data.jobs
              : [];


          for (const j of jobs) {

            if (!j.url) {
              continue;
            }


            if (
              results.some(
                x =>
                  x.url === j.url
              )
            ) {
              continue;
            }


            results.push({

              title:
                j.title,

              company:
                j.company_name ||
                'Company',

              location:
                j.candidate_required_location ||
                'Remote',

              salary:
                j.salary ||
                'Not listed',

              url:
                j.url,

              source:
                'Remotive'

            });


            if (
              results.length >= 20
            ) {
              break;
            }

          }

        } catch (e) {

          console.warn(
            'Remotive jobs unavailable:',
            e.message
          );

        }

      }


      res.json({

        query: q,

        jobs:
          results.slice(0, 20)

      });


    } catch (e) {

      console.error(
        "jobs error:",
        e.message
      );

      res.status(500).json({
        error:
          "Live job sources are temporarily unavailable."
      });

    }

  }
);


/* =========================================================
   TRENDING ARTICLES
   GOOGLE NEWS RSS
========================================================= */

function decodeXml(s) {

  return String(s || '')
    .replace(
      /<!\[CDATA\[([\s\S]*?)\]\]>/g,
      '$1'
    )
    .replace(
      /&amp;/g,
      '&'
    )
    .replace(
      /&lt;/g,
      '<'
    )
    .replace(
      /&gt;/g,
      '>'
    )
    .replace(
      /&quot;/g,
      '"'
    )
    .replace(
      /&#39;/g,
      "'"
    )
    .replace(
      /&#x27;/g,
      "'"
    );

}


function parseRss(xml) {

  return [
    ...xml.matchAll(
      /<item>([\s\S]*?)<\/item>/gi
    )
  ]

    .map(m => {

      const item =
        m[1];


      const get =
        tag => {

          const x =
            item.match(
              new RegExp(
                `<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`,
                'i'
              )
            );


          return x
            ? decodeXml(
                x[1]
              ).trim()
            : '';

        };


      return {

        title:
          get('title'),

        url:
          get('link'),

        src:
          get('source'),

        published:
          get('pubDate')

      };

    })

    .filter(
      x =>
        x.title &&
        x.url
    );

}


app.get(
  '/api/trending',
  async (req, res) => {

    const now =
      Date.now();


    /* -----------------------------------------------------
       RETURN CACHE
    ----------------------------------------------------- */

    if (
      trendCache.articles.length &&
      now - trendCache.at <
        TREND_CACHE_MS
    ) {

      return res.json({
        articles:
          trendCache.articles,
        cached: true
      });

    }


    const feeds = [

      'https://news.google.com/rss/search?q=AI+technology+jobs+career&hl=en-IN&gl=IN&ceid=IN:en',

      'https://news.google.com/rss/search?q=artificial+intelligence+generative+AI&hl=en-IN&gl=IN&ceid=IN:en'

    ];


    try {

      const settled =
        await Promise.allSettled(

          feeds.map(
            url =>
              axios.get(
                url,
                {
                  timeout: 7000,

                  headers: {
                    'User-Agent':
                      'SkillPathAI/1.0'
                  }
                }
              )
          )

        );


      const all = [];


      for (
        const item
        of settled
      ) {

        if (
          item.status ===
          'fulfilled'
        ) {

          all.push(
            ...parseRss(
              item.value.data
            )
          );

        } else {

          console.warn(
            'RSS feed unavailable:',
            item.reason?.message ||
            item.reason
          );

        }

      }


      /* -----------------------------------------------------
         REMOVE DUPLICATES
      ----------------------------------------------------- */

      const unique = [];

      const seen =
        new Set();


      for (
        const a
        of all
      ) {

        const key =
          a.url;


        if (
          !seen.has(key)
        ) {

          seen.add(key);

          unique.push(a);

        }

      }


      /* -----------------------------------------------------
         NEWEST FIRST
      ----------------------------------------------------- */

      unique.sort(
        (a, b) =>
          new Date(
            b.published || 0
          ) -
          new Date(
            a.published || 0
          )
      );


      const articles =
        unique.slice(0, 12);


      trendCache.at =
        Date.now();

      trendCache.articles =
        articles;


      res.set(
        'Cache-Control',
        'public, max-age=300'
      );


      res.json({

        articles,

        cached: false

      });


    } catch (e) {

      console.error(
        "trending error:",
        e.message
      );

      res.status(500).json({
        error:
          "Articles temporarily unavailable."
      });

    }

  }
);


/* =========================================================
   PDF RESUME UPLOAD
========================================================= */

const upload =
  multer({

    storage:
      multer.memoryStorage(),

    limits: {
      fileSize:
        5 * 1024 * 1024
    },

    fileFilter:
      (req, file, cb) => {

        const ok =
          file.mimetype ===
            'application/pdf' ||
          file.originalname
            .toLowerCase()
            .endsWith('.pdf');


        cb(
          ok
            ? null
            : new Error(
                'Only PDF files are allowed.'
              ),
          ok
        );

      }

  });


app.post(
  '/api/resume-upload',
  upload.single('resume'),
  async (req, res) => {

    if (!req.file) {

      return res.status(400).json({
        error:
          "No PDF uploaded."
      });

    }


    try {

      const pdfModule =
        require('pdf-parse');

      let text = '';

      let pages = 0;


      /* -----------------------------------------------------
         PDF-PARSE 2.x
      ----------------------------------------------------- */

      if (
        pdfModule.PDFParse
      ) {

        const parser =
          new pdfModule.PDFParse({
            data:
              req.file.buffer
          });


        const result =
          await parser.getText();


        text =
          result.text || '';


        pages =
          result.total ||
          result.pages?.length ||
          0;


        await parser.destroy();


      } else {

        /* ---------------------------------------------------
           OLD PDF-PARSE COMPATIBILITY
        --------------------------------------------------- */

        const parser =
          pdfModule.default ||
          pdfModule;


        const result =
          await parser(
            req.file.buffer
          );


        text =
          result.text || '';


        pages =
          result.numpages || 0;

      }


      /* -----------------------------------------------------
         CLEAN TEXT
      ----------------------------------------------------- */

      text =
        text
          .replace(
            /\u0000/g,
            ' '
          )
          .replace(
            /[ \t]+\n/g,
            '\n'
          )
          .replace(
            /\n{3,}/g,
            '\n\n'
          )
          .trim();


      if (!text) {

        return res.status(422).json({
          error:
            "The PDF contains no selectable text. A scanned/image-only PDF needs OCR."
        });

      }


      res.json({

        filename:
          req.file.originalname,

        pages,

        text,

        textLength:
          text.length

      });


    } catch (e) {

      console.error(
        "resume-upload error:",
        e
      );

      res.status(500).json({
        error:
          "Could not read this PDF. Try another PDF with selectable text."
      });

    }

  }
);


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {

    if (
      err instanceof
        multer.MulterError ||
      err.message?.includes(
        'Only PDF'
      )
    ) {

      return res.status(400).json({
        error:
          err.message
      });

    }


    console.error(err);


    res.status(500).json({
      error:
        "Server error."
    });

  }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
  port,
  () =>
    console.log(
      `🚀 SkillPath AI running on port ${port}`
    )
);
