/**
 * FourSight 2.0 — Application Logic
 * Gemini-powered thinking profile assessment
 */

// ── Questions ────────────────────────────────────────────────────────────────
// Each question maps to a FourSight thinking dimension.
// Dimension key: C = Clarifier, I = Ideator, D = Developer, M = iMplementer
const QUESTIONS = [
  {
    text: "When starting a new project, your first instinct is to:",
    options: [
      { label: "Gather as much background information as possible before proceeding.", dim: "C" },
      { label: "Brainstorm a wide range of possibilities and novel directions.", dim: "I" },
      { label: "Map out a detailed plan and identify potential obstacles.", dim: "D" },
      { label: "Jump in and start doing — learning as you go.", dim: "M" },
    ],
  },
  {
    text: "Which working style resonates most with you?",
    options: [
      { label: "I like to deeply understand the problem before proposing solutions.", dim: "C" },
      { label: "I enjoy generating ideas without worrying too much about constraints.", dim: "I" },
      { label: "I prefer refining and improving existing ideas until they are solid.", dim: "D" },
      { label: "I feel most energised when making tangible progress on deliverables.", dim: "M" },
    ],
  },
  {
    text: "In a brainstorming session you are most likely to:",
    options: [
      { label: "Ask probing questions to make sure everyone understands the real problem.", dim: "C" },
      { label: "Offer many creative, unconventional suggestions.", dim: "I" },
      { label: "Evaluate and build on others' ideas to make them workable.", dim: "D" },
      { label: "Push the group towards concrete next steps and action items.", dim: "M" },
    ],
  },
  {
    text: "What is your biggest strength in a team?",
    options: [
      { label: "I spot gaps, inconsistencies, and unstated assumptions.", dim: "C" },
      { label: "I inspire others with imaginative thinking and new perspectives.", dim: "I" },
      { label: "I turn rough ideas into well-structured, realistic plans.", dim: "D" },
      { label: "I get things done and keep the project moving forward.", dim: "M" },
    ],
  },
  {
    text: "When a problem is unclear, you prefer to:",
    options: [
      { label: "Research and analyse until you have a thorough understanding.", dim: "C" },
      { label: "Speculate freely about possible causes and creative interpretations.", dim: "I" },
      { label: "Create frameworks or models to make sense of the complexity.", dim: "D" },
      { label: "Try a quick solution and adjust based on the results.", dim: "M" },
    ],
  },
  {
    text: "Your colleagues are most likely to describe you as:",
    options: [
      { label: "Thorough, precise, and insightful.", dim: "C" },
      { label: "Imaginative, spontaneous, and full of ideas.", dim: "I" },
      { label: "Analytical, systematic, and detail-oriented.", dim: "D" },
      { label: "Decisive, results-focused, and action-oriented.", dim: "M" },
    ],
  },
  {
    text: "When reviewing someone else's proposal, you focus on:",
    options: [
      { label: "Whether the underlying assumptions and data are sound.", dim: "C" },
      { label: "Whether there are fresh angles or ideas that haven't been explored.", dim: "I" },
      { label: "Whether the logic, structure, and feasibility hold up.", dim: "D" },
      { label: "Whether it leads to clear, achievable outcomes.", dim: "M" },
    ],
  },
  {
    text: "Your ideal work environment is one where:",
    options: [
      { label: "You have time and resources to investigate problems deeply.", dim: "C" },
      { label: "Creativity and experimentation are actively encouraged.", dim: "I" },
      { label: "There are clear processes and opportunities for continuous improvement.", dim: "D" },
      { label: "Results and efficiency are the primary measures of success.", dim: "M" },
    ],
  },
  {
    text: "When a project encounters an unexpected setback, you tend to:",
    options: [
      { label: "Step back to diagnose what went wrong and why.", dim: "C" },
      { label: "Look for creative alternative paths forward.", dim: "I" },
      { label: "Revisit the plan and adjust the approach methodically.", dim: "D" },
      { label: "Keep momentum by tackling the most urgent obstacle first.", dim: "M" },
    ],
  },
  {
    text: "Which of these best describes how you like to communicate ideas?",
    options: [
      { label: "With well-researched evidence and careful, precise language.", dim: "C" },
      { label: "With stories, metaphors, and vivid conceptual illustrations.", dim: "I" },
      { label: "With structured documents, diagrams, and logical arguments.", dim: "D" },
      { label: "With concise, action-oriented messages focused on outcomes.", dim: "M" },
    ],
  },
];

const DIMENSION_META = {
  C: {
    name: "Clarifier",
    color: "#4A90D9",
    emoji: "🔍",
    tagline: "You understand before you act.",
    description: "Clarifiers are analytical thinkers who love to gather facts, examine assumptions, and fully understand a challenge before moving forward. They are the team's knowledge foundation.",
  },
  I: {
    name: "Ideator",
    color: "#F5A623",
    emoji: "💡",
    tagline: "You imagine what others haven't.",
    description: "Ideators are visionary and creative. They thrive on generating novel concepts, challenging the status quo, and inspiring others with imaginative possibilities.",
  },
  D: {
    name: "Developer",
    color: "#7ED321",
    emoji: "⚙️",
    tagline: "You turn rough ideas into reality.",
    description: "Developers are strategic and systematic. They excel at taking raw ideas and building them into coherent, workable plans through careful analysis and structured thinking.",
  },
  M: {
    name: "Implementer",
    color: "#D0021B",
    emoji: "🚀",
    tagline: "You make things happen.",
    description: "Implementers are action-oriented and results-driven. They are motivated by tangible progress, deadlines, and getting things done efficiently.",
  },
};

// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  apiKey: "",
  currentQuestion: 0,
  answers: [],    // array of dimension chars, one per question
  scores: { C: 0, I: 0, D: 0, M: 0 },
  selectedOption: null,
};

// ── DOM refs ──────────────────────────────────────────────────────────────────
const sections = {
  home: document.getElementById("section-home"),
  setup: document.getElementById("section-setup"),
  assessment: document.getElementById("section-assessment"),
  loading: document.getElementById("section-loading"),
  results: document.getElementById("section-results"),
};

// ── Navigation helpers ────────────────────────────────────────────────────────
function showSection(name) {
  Object.values(sections).forEach((el) => el.classList.remove("active"));
  sections[name].classList.add("active");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ── Assessment logic ──────────────────────────────────────────────────────────
function renderQuestion() {
  const q = QUESTIONS[state.currentQuestion];
  const total = QUESTIONS.length;
  const idx = state.currentQuestion;

  // Progress
  document.getElementById("progress-text").textContent = `Question ${idx + 1} of ${total}`;
  document.getElementById("progress-fill").style.width = `${((idx) / total) * 100}%`;

  // Question
  document.getElementById("question-number").textContent = `Question ${idx + 1}`;
  document.getElementById("question-text").textContent = q.text;

  // Options
  const optionsEl = document.getElementById("options");
  optionsEl.innerHTML = "";
  const letters = ["A", "B", "C", "D"];
  q.options.forEach((opt, i) => {
    const btn = document.createElement("button");
    btn.className = "option-btn";
    btn.dataset.dim = opt.dim;
    btn.dataset.index = i;
    btn.innerHTML = `<span class="option-letter">${letters[i]}</span><span>${opt.label}</span>`;
    if (state.answers[idx] === opt.dim) {
      btn.classList.add("selected");
    }
    btn.addEventListener("click", () => selectOption(btn, opt.dim));
    optionsEl.appendChild(btn);
  });

  // Nav buttons
  document.getElementById("btn-prev").disabled = idx === 0;
  const nextBtn = document.getElementById("btn-next");
  nextBtn.textContent = idx === total - 1 ? "See My Results →" : "Next →";
  nextBtn.disabled = !state.answers[idx];
}

function selectOption(btn, dim) {
  document.querySelectorAll(".option-btn").forEach((b) => b.classList.remove("selected"));
  btn.classList.add("selected");
  state.answers[state.currentQuestion] = dim;
  document.getElementById("btn-next").disabled = false;
}

function nextQuestion() {
  if (!state.answers[state.currentQuestion]) return;
  if (state.currentQuestion < QUESTIONS.length - 1) {
    state.currentQuestion++;
    renderQuestion();
  } else {
    finishAssessment();
  }
}

function prevQuestion() {
  if (state.currentQuestion > 0) {
    state.currentQuestion--;
    renderQuestion();
  }
}

function finishAssessment() {
  // Tally scores
  state.scores = { C: 0, I: 0, D: 0, M: 0 };
  state.answers.forEach((dim) => {
    if (dim) state.scores[dim]++;
  });
  showSection("loading");
  fetchGeminiInsights();
}

// ── Gemini API ────────────────────────────────────────────────────────────────
async function fetchGeminiInsights() {
  const total = QUESTIONS.length;
  const { C, I, D, M } = state.scores;

  // Determine dominant profile
  const sorted = Object.entries(state.scores).sort((a, b) => b[1] - a[1]);
  const dominant = sorted[0][0];
  const meta = DIMENSION_META[dominant];

  const prompt = `You are an expert in creative thinking and problem-solving assessments. A user has completed the FourSight thinking profile questionnaire and their results are:

- Clarifier: ${C}/${total} (${Math.round((C / total) * 100)}%)
- Ideator: ${I}/${total} (${Math.round((I / total) * 100)}%)
- Developer: ${D}/${total} (${Math.round((D / total) * 100)}%)
- Implementer: ${M}/${total} (${Math.round((M / total) * 100)}%)

Their dominant thinking preference is: **${meta.name}** — "${meta.tagline}"

Please provide a personalised, insightful, and encouraging analysis of approximately 250–300 words. Structure your response in three short paragraphs:

1. **Your Primary Strength** — Describe what being a ${meta.name} means in practice, including their key strengths and what makes them valuable in a team.
2. **Your Growth Edge** — Discuss the dimension with the lowest score and how the user can develop that thinking style to become more well-rounded.
3. **Practical Tips** — Offer 3 practical, actionable suggestions for how this person can leverage their profile in their daily work and collaboration.

Keep the tone warm, professional, and empowering. Use "you" to address the user directly.`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(state.apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: 600,
          },
        }),
      }
    );

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err?.error?.message || `API error ${response.status}`);
    }

    const data = await response.json();
    const insightText = data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    renderResults(dominant, insightText);
  } catch (err) {
    renderResults(dominant, null, err.message);
  }
}

// ── Results rendering ─────────────────────────────────────────────────────────
function renderResults(dominant, insightText, errorMsg) {
  const meta = DIMENSION_META[dominant];
  const total = QUESTIONS.length;
  const { C, I, D, M } = state.scores;

  // Profile badge
  const badge = document.getElementById("profile-badge");
  const dimToClass = { C: "clarifier", I: "ideator", D: "developer", M: "implementer" };
  badge.className = `profile-badge ${dimToClass[dominant]}`;
  badge.innerHTML = `<span>${meta.emoji}</span><span>${meta.name}</span>`;

  document.getElementById("result-title").textContent = meta.tagline;
  document.getElementById("result-subtitle").textContent = meta.description;

  // Score bars
  const scoreMap = { C, I, D, M };
  ["C", "I", "D", "M"].forEach((key) => {
    const pct = Math.round((scoreMap[key] / total) * 100);
    const pctEl = document.getElementById(`pct-${key.toLowerCase()}`);
    if (pctEl) pctEl.textContent = `${pct}%`;
  });

  // AI insights
  const insightsEl = document.getElementById("insights-text");
  const errorEl = document.getElementById("insights-error");

  if (errorMsg) {
    errorEl.textContent = `⚠️ Couldn't load AI insights: ${errorMsg}. Please check your API key.`;
    errorEl.classList.add("visible");
    insightsEl.textContent = "";
  } else {
    errorEl.classList.remove("visible");
    // Render simple markdown (bold + paragraphs)
    insightsEl.innerHTML = renderMarkdown(insightText);
  }

  showSection("results");

  // Animate bars after section is visible
  setTimeout(() => {
    ["C", "I", "D", "M"].forEach((key) => {
      const pct = Math.round((scoreMap[key] / total) * 100);
      const bar = document.getElementById(`bar-${key.toLowerCase()}`);
      if (bar) bar.style.width = `${pct}%`;
    });
  }, 200);
}

// Very simple markdown renderer (bold + paragraphs only)
function renderMarkdown(text) {
  if (!text) return "";
  // Bold: **text**
  const withBold = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  // Split into paragraphs
  const paragraphs = withBold
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter(Boolean);
  return paragraphs.map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
}

// ── Event wiring ──────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Home → Setup (or assessment if key already in memory for this session)
  document.getElementById("btn-start").addEventListener("click", () => {
    if (state.apiKey) {
      startAssessment();
    } else {
      showSection("setup");
    }
  });

  // Setup → Assessment
  document.getElementById("btn-begin").addEventListener("click", () => {
    const key = document.getElementById("api-key-input").value.trim();
    if (!key) {
      document.getElementById("setup-error").textContent = "Please enter a valid Gemini API key.";
      document.getElementById("setup-error").classList.add("visible");
      return;
    }
    document.getElementById("setup-error").classList.remove("visible");
    state.apiKey = key;
    startAssessment();
  });

  // Assessment navigation
  document.getElementById("btn-next").addEventListener("click", nextQuestion);
  document.getElementById("btn-prev").addEventListener("click", prevQuestion);

  // Results actions
  document.getElementById("btn-restart").addEventListener("click", () => {
    state.currentQuestion = 0;
    state.answers = [];
    state.scores = { C: 0, I: 0, D: 0, M: 0 };
    startAssessment();
  });

  document.getElementById("btn-change-key").addEventListener("click", () => {
    state.apiKey = "";
    showSection("setup");
  });

  // Allow Enter key on API input
  document.getElementById("api-key-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("btn-begin").click();
  });
});

function startAssessment() {
  state.currentQuestion = 0;
  state.answers = new Array(QUESTIONS.length).fill(null);
  showSection("assessment");
  renderQuestion();
}
