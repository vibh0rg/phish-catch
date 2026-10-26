import { analyzeWithRules, IMPACTS, MAX_MESSAGE_LENGTH, SOURCES } from './lib/analyzer.js';

const MAX_AUDIO_BYTES = 3 * 1024 * 1024;
const VERDICT_LABEL = { safe: 'Likely safe', suspicious: 'Be cautious', scam: 'Likely scam' };
const LEVEL_LABEL = { none: 'None', low: 'Low', medium: 'Medium', high: 'High' };
const SEVERITY_LABEL = { high: 'High', medium: 'Med', low: 'Low' };

const SAMPLES = [
  {
    label: 'OTP request',
    source: 'whatsapp',
    text: 'Hi, sorry to bother you! I sent my OTP to your number by mistake 🙏 Can you please forward the 6-digit code you just got? It’s urgent.',
  },
  {
    label: 'KYC alert',
    source: 'sms',
    text: 'Dear Customer, your SBI YONO account will be blocked today. Update your PAN KYC immediately: http://sbi-kyc-update.xyz/verify',
  },
  {
    label: 'Job offer',
    source: 'linkedin',
    text: 'Hello! We are hiring for a remote part-time role. Earn ₹5,000 per day by rating hotels on Google. No interview needed. Pay a refundable registration fee of ₹1,999 to start. Message me on Telegram @hr_priya_jobs',
  },
  {
    label: 'Digital arrest',
    source: 'whatsapp',
    text: 'This is Inspector Sharma from the CBI cyber cell. Drugs were found in a parcel booked on your Aadhaar. You are under digital arrest. Do not tell your family. Join the video call now and transfer ₹49,000 for verification.',
  },
  {
    label: 'Copyright DM',
    source: 'instagram',
    text: 'Instagram Support: your account will be disabled for copyright violation within 24 hours. Verify your account to appeal: bit.ly/ig-appeal-form',
  },
  {
    label: 'Crypto giveaway',
    source: 'x',
    text: '🚨 GIVEAWAY 🚨 Send 0.05 BTC and receive 0.1 BTC back instantly! Guaranteed returns, only for the next 30 minutes!!!',
  },
  {
    label: 'Genuine OTP',
    source: 'sms',
    text: '483920 is your OTP to log in to your account. It is valid for 10 minutes. Do not share this OTP with anyone. - XYZ Bank',
  },
];

const ICONS = {
  device: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18h2"/>',
  financial: '<path d="M7 5h10M7 9h10"/><path d="M7 5h3a4 4 0 0 1 0 8H7l7 6"/>',
  social: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  physical: '<path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>',
};

const $ = (sel) => document.querySelector(sel);
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

const els = {
  tabs: [...document.querySelectorAll('.ptab')],
  radios: [...document.querySelectorAll('input[name="source"]')],
  sourceChipLabel: $('#source-chip-label'),
  sampleChips: $('#sample-chips'),
  textarea: $('#message'),
  charCount: $('#char-count'),
  analyzeBtn: $('#analyze-btn'),
  clearBtn: $('#clear-btn'),
  formError: $('#form-error'),
  audioInput: $('#audio-input'),
  audioName: $('#audio-name'),
  audioPreview: $('#audio-preview'),
  transcribeBtn: $('#transcribe-btn'),
  voiceStatus: $('#voice-status'),
  results: $('#results'),
  resultsEmpty: $('#results-empty'),
  resultsLoading: $('#results-loading'),
  resultsBody: $('#results-body'),
  engineChip: $('#engine-chip'),
  scoreValue: $('#score-value'),
  verdictLabel: $('#verdict-label'),
  verdictSummary: $('#verdict-summary'),
  meter: $('#meter'),
  meterMarker: $('#meter-marker'),
  impacts: $('#impacts'),
  flags: $('#flags'),
  flagCount: $('#flag-count'),
  positivesWrap: $('#positives-wrap'),
  positives: $('#positives'),
  advice: $('#advice'),
  engineNote: $('#engine-note'),
  copyBtn: $('#copy-btn'),
  copyStatus: $('#copy-status'),
  againBtn: $('#again-btn'),
  support: $('#support'),
  supportItems: [...document.querySelectorAll('[data-support]')],
  trySample: $('#try-sample'),
  themeToggle: $('#theme-toggle'),
};

const state = { source: 'sms', result: null, checkedAt: null, audioFile: null, audioUrl: null, sampleIndex: -1, busy: false };

// Screen-reader announcement for finished checks.
const announcer = Object.assign(document.createElement('p'), { className: 'visually-hidden' });
announcer.setAttribute('role', 'status');
document.body.append(announcer);

/* ---------- Helpers ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function icon(paths) {
  const span = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  span.setAttribute('viewBox', '0 0 24 24');
  span.setAttribute('class', 'icon');
  span.setAttribute('aria-hidden', 'true');
  span.innerHTML = paths;
  return span;
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const formatBytes = (n) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

/* ---------- Source ---------- */

function setSource(src) {
  if (!Object.hasOwn(SOURCES, src)) return;
  state.source = src;
  document.body.dataset.source = src;
  for (const tab of els.tabs) tab.setAttribute('aria-pressed', String(tab.dataset.source === src));
  for (const radio of els.radios) radio.checked = radio.value === src;
  els.sourceChipLabel.textContent = SOURCES[src];
}

for (const tab of els.tabs) tab.addEventListener('click', () => setSource(tab.dataset.source));
for (const radio of els.radios) radio.addEventListener('change', () => radio.checked && setSource(radio.value));

/* ---------- Message input ---------- */

function updateCount() {
  const n = els.textarea.value.length;
  els.charCount.textContent = `${n.toLocaleString('en-IN')} / ${MAX_MESSAGE_LENGTH.toLocaleString('en-IN')}`;
  els.charCount.classList.toggle('near', n > MAX_MESSAGE_LENGTH * 0.9);
}

function showError(message) {
  els.formError.textContent = message;
}

els.textarea.addEventListener('input', () => {
  updateCount();
  if (els.formError.textContent) showError('');
});
els.textarea.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    runCheck();
  }
});

els.clearBtn.addEventListener('click', () => {
  els.textarea.value = '';
  updateCount();
  showError('');
  els.textarea.focus();
});

function loadSample(sample) {
  setSource(sample.source);
  els.textarea.value = sample.text;
  updateCount();
  showError('');
}

for (const sample of SAMPLES) {
  const chip = el('button', 'chip');
  chip.type = 'button';
  chip.dataset.source = sample.source;
  chip.append(el('span', 'pdot'), sample.label);
  chip.setAttribute('aria-label', `Load sample: ${sample.label} (${SOURCES[sample.source]})`);
  chip.addEventListener('click', () => {
    loadSample(sample);
    els.textarea.focus();
  });
  els.sampleChips.append(chip);
}

els.trySample.addEventListener('click', () => {
  state.sampleIndex = (state.sampleIndex + 1) % SAMPLES.length;
  loadSample(SAMPLES[state.sampleIndex]);
  $('#checker').scrollIntoView({ behavior: reduceMotion.matches ? 'auto' : 'smooth', block: 'start' });
  runCheck();
});

/* ---------- Analysis ---------- */

function showResults(view) {
  els.resultsEmpty.hidden = view !== 'empty';
  els.resultsLoading.hidden = view !== 'loading';
  els.resultsBody.hidden = view !== 'body';
}

function setBusy(busy) {
  state.busy = busy;
  els.analyzeBtn.disabled = busy;
  els.analyzeBtn.querySelector('span').textContent = busy ? 'Checking…' : 'Check for red flags';
  if (busy) showResults('loading');
}

async function runCheck() {
  if (state.busy) return;
  const text = els.textarea.value.trim();
  if (text.length < 4) {
    showError('Paste the message you want to check first.');
    els.textarea.focus();
    return;
  }
  showError('');
  setBusy(true);
  const started = performance.now();
  let result;
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, source: state.source }),
      signal: AbortSignal.timeout(35000),
    });
    if (res.status === 400) {
      const data = await res.json().catch(() => ({}));
      const err = new Error(data.error || 'That message couldn’t be checked.');
      err.userFacing = true;
      throw err;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    result = await res.json();
    if (typeof result?.score !== 'number') throw new Error('Unexpected response');
  } catch (err) {
    if (err.userFacing) {
      setBusy(false);
      showResults(state.result ? 'body' : 'empty');
      showError(err.message);
      return;
    }
    // Server unreachable (offline, static hosting, provider outage): run the same rules locally.
    result = analyzeWithRules(text, state.source);
    result.engine.note = 'The analysis server couldn’t be reached, so this check ran in your browser with the local rules.';
  }
  await delay(Math.max(0, 450 - (performance.now() - started)));
  setBusy(false);
  render(result);
}

els.analyzeBtn.addEventListener('click', runCheck);

function engineText(engine) {
  if (engine.kind === 'model') {
    const cross = engine.crossChecked ? ' Score raised by the rule check because the message makes a high-risk request.' : '';
    return { chip: `AI · ${engine.label}`, note: `Analysed by ${engine.label} (${engine.model}) with a rule-based cross-check.${cross}` };
  }
  return { chip: 'Local rules', note: `Local rule-based engine (${engine.version}).${engine.note ? ` ${engine.note}` : ''}` };
}

function render(result) {
  state.result = result;
  state.checkedAt = new Date();
  const { score, verdict } = result;

  els.results.dataset.verdict = verdict;
  showResults('body');
  els.scoreValue.textContent = String(score);
  els.verdictLabel.textContent = VERDICT_LABEL[verdict];
  els.verdictSummary.textContent = result.summary;

  // Leave the marker a whisker inside the track at 0 and 100.
  els.meterMarker.style.left = `${Math.min(98.5, Math.max(1.5, score))}%`;
  els.meter.setAttribute('role', 'img');
  els.meter.setAttribute('aria-label', `Risk meter: ${score} out of 100, ${VERDICT_LABEL[verdict].toLowerCase()}`);

  const engine = engineText(result.engine);
  els.engineChip.hidden = false;
  els.engineChip.textContent = engine.chip;
  els.engineNote.textContent = engine.note;

  els.impacts.replaceChildren(
    ...Object.entries(IMPACTS).map(([key, meta]) => {
      const impact = result.impacts[key] || { level: 'none', reason: '' };
      const li = el('li', 'impact');
      li.dataset.level = impact.level;
      const top = el('div', 'impact-top');
      top.append(icon(ICONS[key]), el('span', 'impact-name', meta.label), el('span', 'impact-level', LEVEL_LABEL[impact.level]));
      const bars = el('div', 'impact-bars');
      bars.setAttribute('aria-hidden', 'true');
      bars.append(el('span'), el('span'), el('span'));
      li.append(top, bars, el('p', 'impact-reason', impact.reason));
      return li;
    }),
  );

  const flags = result.redFlags || [];
  els.flagCount.textContent = String(flags.length);
  if (flags.length) {
    els.flags.replaceChildren(
      ...flags.map((flag) => {
        const li = el('li', 'flag');
        li.dataset.sev = flag.severity;
        const body = el('div');
        body.append(el('p', 'flag-title', flag.title));
        if (flag.detail) body.append(el('p', 'flag-detail', flag.detail));
        if (flag.evidence) body.append(el('q', 'flag-evidence', flag.evidence));
        const sev = el('span', 'flag-sev', SEVERITY_LABEL[flag.severity] || 'Med');
        sev.setAttribute('aria-label', `${flag.severity} severity`);
        li.append(sev, body);
        return li;
      }),
    );
  } else {
    els.flags.replaceChildren(el('li', 'flags-none', 'No red flags found in this text.'));
  }

  const positives = result.positives || [];
  els.positivesWrap.hidden = !positives.length;
  els.positives.replaceChildren(...positives.map((p) => el('li', '', p)));
  els.advice.replaceChildren(...(result.advice || []).map((a) => el('li', '', a)));

  const support = new Set(result.support || []);
  els.support.hidden = !support.size;
  for (const item of els.supportItems) item.hidden = !support.has(item.dataset.support);

  els.copyStatus.textContent = '';
  announcer.textContent = `Result: ${score} out of 100, ${VERDICT_LABEL[verdict].toLowerCase()}. ${flags.length} red flag${flags.length === 1 ? '' : 's'}.`;

  if (window.matchMedia('(max-width: 900px)').matches) {
    els.results.scrollIntoView({ behavior: reduceMotion.matches ? 'auto' : 'smooth', block: 'start' });
  }
}

/* ---------- Result actions ---------- */

function findingsText(result) {
  const lines = [
    'Phish-Catch findings (automated estimate, not proof)',
    `Source: ${SOURCES[result.meta?.source] || SOURCES[state.source]}`,
    `Score: ${result.score}/100 — ${VERDICT_LABEL[result.verdict]}`,
    `Summary: ${result.summary}`,
    '',
    'Red flags:',
    ...(result.redFlags.length ? result.redFlags.map((f) => `- [${f.severity}] ${f.title}${f.evidence ? ` — “${f.evidence}”` : ''}`) : ['- None found']),
    '',
    `Possible impact: ${Object.entries(IMPACTS).map(([k, m]) => `${m.label}: ${LEVEL_LABEL[result.impacts[k]?.level || 'none']}`).join(' · ')}`,
    '',
    'What to do:',
    ...result.advice.map((a) => `- ${a}`),
    '',
    `Engine: ${engineText(result.engine).note}`,
    `Checked: ${state.checkedAt.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })}`,
    'Message text not included.',
  ];
  if (result.support?.length) {
    lines.push('', 'Help in India: 1930 / cybercrime.gov.in (cyber financial fraud) · 112 (emergency) · cert-in.org.in (cyber incidents)');
  }
  return lines.join('\n');
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    ta.setAttribute('readonly', '');
    ta.className = 'visually-hidden';
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

els.copyBtn.addEventListener('click', async () => {
  if (!state.result) return;
  const ok = await copyText(findingsText(state.result));
  els.copyStatus.textContent = ok ? 'Copied to clipboard' : 'Couldn’t copy — select and copy manually';
});

els.againBtn.addEventListener('click', () => {
  state.result = null;
  els.textarea.value = '';
  updateCount();
  els.results.removeAttribute('data-verdict');
  els.engineChip.hidden = true;
  els.support.hidden = true;
  showResults('empty');
  resetAudio();
  $('#checker').scrollIntoView({ behavior: reduceMotion.matches ? 'auto' : 'smooth', block: 'start' });
  els.textarea.focus({ preventScroll: true });
});

/* ---------- Voice notes ---------- */

function setVoiceStatus(message, kind = '') {
  els.voiceStatus.textContent = message;
  els.voiceStatus.className = `voice-status ${kind}`.trim();
}

function resetAudio() {
  if (state.audioUrl) URL.revokeObjectURL(state.audioUrl);
  state.audioFile = null;
  state.audioUrl = null;
  els.audioInput.value = '';
  els.audioPreview.hidden = true;
  els.audioPreview.removeAttribute('src');
  els.audioName.textContent = 'No file chosen · max 3 MB';
  els.transcribeBtn.disabled = true;
  setVoiceStatus('');
}

els.audioInput.addEventListener('change', () => {
  const file = els.audioInput.files?.[0];
  if (!file) return;
  const looksAudio = file.type.startsWith('audio/') || /\.(opus|ogg|m4a|mp3|wav|aac|flac|webm)$/i.test(file.name);
  if (!looksAudio) {
    resetAudio();
    setVoiceStatus('That doesn’t look like an audio file. Choose a voice note (.opus, .ogg, .m4a, .mp3, .wav).', 'error');
    return;
  }
  if (file.size > MAX_AUDIO_BYTES) {
    resetAudio();
    setVoiceStatus(`That file is ${formatBytes(file.size)}. The limit is 3 MB — trim the recording and try again.`, 'error');
    return;
  }
  if (state.audioUrl) URL.revokeObjectURL(state.audioUrl);
  state.audioFile = file;
  state.audioUrl = URL.createObjectURL(file);
  els.audioPreview.src = state.audioUrl;
  els.audioPreview.hidden = false;
  els.audioName.textContent = `${file.name} · ${formatBytes(file.size)}`;
  els.transcribeBtn.disabled = false;
  setVoiceStatus('');
});

function readBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '');
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

function guessAudioType(file) {
  if (file.type) return file.type;
  const ext = file.name.split('.').pop().toLowerCase();
  return { opus: 'audio/ogg', ogg: 'audio/ogg', m4a: 'audio/mp4', mp3: 'audio/mpeg', wav: 'audio/wav', aac: 'audio/aac', flac: 'audio/flac', webm: 'audio/webm' }[ext] || 'audio/ogg';
}

els.transcribeBtn.addEventListener('click', async () => {
  const file = state.audioFile;
  if (!file) return;
  els.transcribeBtn.disabled = true;
  els.transcribeBtn.textContent = 'Transcribing…';
  setVoiceStatus('Sending the recording to the speech service…');
  try {
    const res = await fetch('/api/transcribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ audio: await readBase64(file), mimeType: guessAudioType(file), filename: file.name }),
      signal: AbortSignal.timeout(60000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Voice transcription isn’t available right now. Play the recording and type what it says instead.');
    const existing = els.textarea.value.trim();
    els.textarea.value = existing ? `${existing}\n\n${data.text}` : data.text;
    updateCount();
    setVoiceStatus('Transcript added to the message box. Listen back and fix any misheard words before checking.', 'ok');
    els.textarea.focus();
  } catch (err) {
    const offline = err.name === 'TypeError' || err.name === 'TimeoutError' || err.name === 'AbortError';
    setVoiceStatus(offline ? 'Couldn’t reach the transcription service. Play the recording and type what it says instead.' : err.message, 'error');
  } finally {
    els.transcribeBtn.textContent = 'Transcribe';
    els.transcribeBtn.disabled = !state.audioFile;
  }
});

/* ---------- Theme ---------- */

function applyThemeLabel() {
  const dark = document.documentElement.dataset.theme === 'dark';
  els.themeToggle.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
}

els.themeToggle.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem('phishcatch-theme', next);
  } catch {}
  applyThemeLabel();
});

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
  let saved = null;
  try {
    saved = localStorage.getItem('phishcatch-theme');
  } catch {}
  if (saved) return;
  document.documentElement.dataset.theme = e.matches ? 'dark' : 'light';
  applyThemeLabel();
});

/* ---------- Init ---------- */

setSource(document.querySelector('input[name="source"]:checked')?.value || 'sms');
updateCount();
applyThemeLabel();
