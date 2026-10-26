# Phish-Catch

Check a suspicious message **before** you click a link, share a code or send money.

Pick where the message arrived (SMS, WhatsApp, LinkedIn, Instagram, X/Twitter or Other), paste it — or upload a voice note and review the transcript — and Phish-Catch returns:

- a **0–100 scam-likelihood score** with a Safe / Caution / Scam indicator
- the **red flags** it found, each explained in plain language with the quoted text
- the estimated **impact** on your device, finances, social accounts and physical safety
- practical next steps, and **India-specific help** (1930, 112, CERT-In) when relevant — never called or submitted automatically

> Results are automated estimates, not proof. Phish-Catch can’t verify the sender, scan a device, access accounts, confirm transactions or contact authorities, and it can miss scams or flag genuine messages.

## How it works

```
public/            static site (served as-is, no build step)
  index.html       layout
  styles.css       light/dark design tokens, platform + risk colours
  app.js           UI logic
  lib/analyzer.js  rule-based engine, shared by the browser and the API
api/               Vercel serverless functions
  analyze.js       POST /api/analyze    { text, source }
  transcribe.js    POST /api/transcribe { audio (base64), mimeType, filename }
  _lib/            provider adapters + HTTP helpers (not routes)
scripts/
  dev.mjs          zero-dependency local server (static + API + vercel.json headers)
  selftest.mjs     regression checks for the rules
```

**Analysis.** `/api/analyze` sends the message to an AI model, which scores it and explains the red flags and impact. Provider order in `auto` mode:

1. Google Gemini, if `GEMINI_API_KEY` is set
2. Any OpenAI-compatible API, if `OPENAI_API_KEY` is set
3. **Vercel AI Gateway** — on Vercel, no key is needed: the function authenticates with the OIDC token Vercel attaches to each request, and uses a free-tier model (`nvidia/nemotron-3.5-lightning-free` by default; set `AI_GATEWAY_MODEL` to change it). AI Gateway requires a credit card on the Vercel account, even for free credits.

If no provider is available, the provider fails, or `PHISH_PROVIDER=rules`, it uses the local rule-based engine, and the result card says so. If the API can’t be reached at all, the browser runs the same rules locally.

Some requests always rate as likely scams regardless of the model: asking you to share an OTP, linking your phone number to a code, entering a UPI PIN or approving a collect request, giving passwords or card details, installing APKs or remote-access apps, and “digital arrest” threats.

**Voice notes.** Transcription is a separate step that needs Gemini or an OpenAI-compatible speech model. The transcript goes into the message box for the user to check and correct before analysis.

**Privacy.** Messages and recordings are processed for one request and not stored or logged. With an AI provider configured, the text is sent to that provider for the check.

## Run locally

Requires Node.js 18+. No `npm install` needed.

```bash
npm run dev
```

Open http://localhost:3000. Run the rule checks with `npm test`.

To try AI analysis locally, copy `.env.example` to `.env` and add a key.

## Deploy on Vercel

1. Import this GitHub repository at [vercel.com/new](https://vercel.com/new). The defaults work — `vercel.json` sets the output directory to `public` and there is no build step.
2. That’s it — AI analysis runs through Vercel AI Gateway automatically. Optional: under **Settings → Environment Variables**, add `GEMINI_API_KEY` (also enables voice transcription) or `OPENAI_API_KEY` + `OPENAI_MODEL` (and `OPENAI_BASE_URL` for other compatible providers), then redeploy.

Every push to `main` redeploys automatically.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PHISH_PROVIDER` | `auto` | `auto`, `gemini`, `openai`, `gateway`, or `rules` (never call a model) |
| `AI_GATEWAY_MODEL` | `nvidia/nemotron-3.5-lightning-free` | Vercel AI Gateway model (OIDC auth on Vercel, or `AI_GATEWAY_API_KEY` elsewhere) |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | — / `gemini-3.8-flash` | Gemini analysis and transcription (free key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey)). `GOOGLE_API_KEY`, or `API_KEY` holding an `AIza…` key, also work |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | — / `gpt-4o-mini` | OpenAI-compatible analysis |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Point at any compatible API |
| `OPENAI_TRANSCRIBE_MODEL` | `whisper-1` | Speech-to-text model |
| `SPEECH_PROVIDER` | `auto` | `auto`, `gemini`, `openai`, or `none` |

## Getting help in India

- **1930** — National Cyber Crime Helpline, or report at [cybercrime.gov.in](https://cybercrime.gov.in/)
- **112** — Emergency response if you’re in immediate danger
- **CERT-In** — report cyber-security incidents at [cert-in.org.in](https://www.cert-in.org.in/)

## License

MIT
