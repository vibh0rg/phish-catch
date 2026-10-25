// Small helpers shared by the API functions. Files under api/_lib are not deployed as routes.

export function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

export async function readJson(req, maxBytes = 5 * 1024 * 1024) {
  // Vercel pre-parses JSON bodies; a plain Node server (scripts/dev.mjs) doesn't.
  try {
    if (req.body !== undefined && req.body !== null) {
      if (typeof req.body === 'string') return JSON.parse(req.body);
      if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString('utf8'));
      return req.body;
    }
  } catch {
    return null;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) return null;
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return null;
  }
}

// Best-effort per-instance limiter; it only blunts bursts, it is not a security boundary.
const hits = new Map();
export function rateLimited(req, bucket, limitPerMinute) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'local').split(',')[0].trim();
  const key = `${bucket}:${ip}`;
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < 60_000);
  recent.push(now);
  hits.set(key, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > limitPerMinute;
}
