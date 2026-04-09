<div align="center">

<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />

  <h1>FourSight 2.0</h1>

  <p><strong>Discover your creative thinking profile — powered by Gemini AI.</strong></p>

  <p>Built with <a href="https://aistudio.google.com/apps">Google AI Studio</a> &nbsp;|&nbsp; The fastest path from prompt to production with Gemini.</p>

</div>

---

## About

**FourSight 2.0** is a web-based thinking-profile assessment application powered by the [Gemini API](https://ai.google.dev/). It helps users discover their dominant creative thinking style across four dimensions:

| Profile | Description |
|---|---|
| 🔍 **Clarifier** | Fact-finder and analyst — deeply understands the problem before acting |
| 💡 **Ideator** | Creative visionary — generates novel ideas and sees new possibilities |
| ⚙️ **Developer** | Strategic planner — turns rough ideas into structured, workable plans |
| 🚀 **Implementer** | Action-oriented doer — drives results and keeps projects moving forward |

After completing a 10-question assessment, Gemini generates a personalised insight report highlighting your strengths, growth edges, and practical tips.

---

## Getting Started

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge)
- A free **Gemini API key** — [get one at Google AI Studio](https://aistudio.google.com/app/apikey)

### Running Locally

1. Clone or download this repository.
2. Open `index.html` in your browser — no build step or server required.
3. Enter your Gemini API key when prompted (kept in memory for the current page session only — never written to disk).
4. Complete the 10-question assessment and receive your personalised FourSight profile.

---

## Project Structure

```
FourSight2.0/
├── index.html    # Main HTML page — assessment UI and layout
├── styles.css    # CSS — dark-mode design with FourSight brand colours
├── app.js        # Application logic — questions, scoring, Gemini integration
└── README.md     # This file
```

---

## Technical Context

| Area | Detail |
|---|---|
| **Framework** | Vanilla HTML / CSS / JavaScript — no build tools or dependencies |
| **AI Integration** | [Gemini 2.0 Flash](https://ai.google.dev/gemini-api/docs/models/gemini) via the REST API (`generateContent`) |
| **Auth / Keys** | User-supplied Gemini API key kept in JS memory only (never written to disk or storage) |
| **State Management** | Plain JS module-level state object |
| **Styling** | CSS custom properties, responsive grid, CSS animations |
| **Deployment** | Any static host (GitHub Pages, Netlify, Vercel, etc.) |

---

## Deployment (GitHub Pages)

1. Go to **Settings → Pages** in this repository.
2. Set source to **Deploy from a branch**, select `main` and `/ (root)`.
3. Save — your app will be live at `https://<username>.github.io/FourSight2.0/`.

---

<div align="center">
  <sub>FourSight 2.0 &mdash; Built with Google AI Studio &amp; Gemini &nbsp;|&nbsp; <a href="https://www.foursightonline.com/">Learn about FourSight</a></sub>
</div>
