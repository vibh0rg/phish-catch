import { speechConfig, transcribe } from './_lib/providers.js';
import { rateLimited, readJson, sendJson } from './_lib/http.js';

// Vercel caps request bodies at ~4.5 MB; 3 MB of audio is ~4 MB once base64-encoded.
const MAX_AUDIO_BYTES = 3 * 1024 * 1024;

// POST /api/transcribe  { audio: base64, mimeType, filename } → { text }
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendJson(res, 405, { error: 'Use POST.' });
  }
  if (rateLimited(req, 'transcribe', 10)) {
    return sendJson(res, 429, { error: 'Too many transcriptions in a short time. Wait a minute and try again.' });
  }

  const config = speechConfig();
  if (!config) {
    return sendJson(res, 501, { error: 'Voice transcription isn’t set up on this site. Play the recording and type what it says instead.' });
  }

  const body = await readJson(req, 4.5 * 1024 * 1024);
  const audio = typeof body?.audio === 'string' ? body.audio : '';
  if (!audio) return sendJson(res, 400, { error: 'Choose an audio file first.' });
  const bytes = Buffer.from(audio, 'base64');
  if (bytes.length > MAX_AUDIO_BYTES) return sendJson(res, 413, { error: 'That file is over 3 MB. Trim the recording and try again.' });

  const mimeType = /^audio\/[\w.+-]+$/i.test(String(body.mimeType || '').split(';')[0]) ? body.mimeType.split(';')[0] : 'audio/ogg';
  const filename = String(body.filename || 'voice-note').replace(/[^\w.\-]/g, '_').slice(0, 80);

  try {
    const text = await transcribe(config, bytes, mimeType, filename);
    if (!text) return sendJson(res, 422, { error: 'No clear speech was found in that recording. Type the message instead.' });
    return sendJson(res, 200, { text, provider: config.label, model: config.model });
  } catch (err) {
    console.error(`[transcribe] ${config.kind} failed: ${err.message}`);
    return sendJson(res, 502, { error: 'The speech service couldn’t transcribe this file. Try a shorter clip, or type the message instead.' });
  }
}
