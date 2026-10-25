import { analyzeWithRules, normalizeModelResult, MAX_MESSAGE_LENGTH, SOURCES } from '../public/lib/analyzer.js';
import { analyzeWithModel, modelConfig } from './_lib/providers.js';
import { rateLimited, readJson, sendJson } from './_lib/http.js';

// POST /api/analyze  { text, source } → risk estimate
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendJson(res, 405, { error: 'Use POST.' });
  }
  if (rateLimited(req, 'analyze', 30)) {
    return sendJson(res, 429, { error: 'Too many checks in a short time. Wait a minute and try again.' });
  }

  const body = await readJson(req);
  const text = typeof body?.text === 'string' ? body.text.trim() : '';
  const source = Object.hasOwn(SOURCES, body?.source) ? body.source : 'other';
  if (!text) return sendJson(res, 400, { error: 'Paste the message text first.' });
  if (text.length > MAX_MESSAGE_LENGTH) {
    return sendJson(res, 400, { error: `Messages are limited to ${MAX_MESSAGE_LENGTH.toLocaleString('en-IN')} characters.` });
  }

  const rules = analyzeWithRules(text, source);
  const config = modelConfig(req);
  if (config.kind === 'rules') {
    rules.engine.note = config.reason;
    return sendJson(res, 200, rules);
  }

  try {
    const raw = await analyzeWithModel(config, text, source);
    const engine = { kind: 'model', provider: config.kind, label: config.label, model: config.model, version: rules.engine.version };
    return sendJson(res, 200, normalizeModelResult(raw, rules, engine));
  } catch (err) {
    // Log the failure only; never the message.
    console.error(`[analyze] ${config.kind} failed: ${err.message}`);
    rules.engine.note = `${config.label} couldn’t analyse this message just now, so local rules were used instead.`;
    return sendJson(res, 200, rules);
  }
}
