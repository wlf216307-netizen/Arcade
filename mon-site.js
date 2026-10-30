/*
 * ARCADE DISCORD — site de jeux connecté à Discord (fichier unique)
 *
 * Jeux : Snake, 2048, Memory, Morpion (classiques, sans droits d’auteur).
 * Discord : connexion OAuth2, classements par jeu, et annonce des records dans un salon via webhook.
 *
 * Installation :
 *   1. npm init -y && npm install express dotenv
 *   2. https://discord.com/developers/applications → ton application → OAuth2 :
 *        - copie Client ID et Client Secret
 *        - ajoute dans « Redirects » : http://localhost:3000/callback (ou ton URL publique + /callback)
 *   3. (Optionnel) Salon Discord → Intégrations → Webhooks → copie l’URL.
 *   4. Crée un fichier .env à côté de ce fichier :
 *        DISCORD_CLIENT_ID=...
 *        DISCORD_CLIENT_SECRET=...
 *        BASE_URL=http://localhost:3000
 *        SESSION_SECRET=une_longue_phrase_aleatoire
 *        WEBHOOK_URL=https://discord.com/api/webhooks/...   (optionnel)
 *        PORT=3000
 *   5. node mon-site.js   →   http://localhost:3000
 *
 * Node 18+ requis. Les scores sont calculés dans le navigateur : ils peuvent être trichés.
 * Les scores sont enregistrés dans scores.json (peut être effacé sur certains hébergeurs gratuits).
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');

const {
  DISCORD_CLIENT_ID: CID, DISCORD_CLIENT_SECRET: SECRET,
  BASE_URL = 'http://localhost:3000', SESSION_SECRET = 'change-me',
  WEBHOOK_URL, PORT = 3000,
} = process.env;
const REDIRECT = BASE_URL.replace(/\/$/, '') + '/callback';
const SECURE = BASE_URL.startsWith('https');

// ---------- Données ----------
const FILE = path.join(__dirname, 'scores.json');
let db = {};
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
const save = () => fs.writeFile(FILE, JSON.stringify(db), () => {});

const GAMES = { snake: { name: 'Snake', max: 323 }, '2048': { name: '2048', max: 3000000 }, memory: { name: 'Memory', max: 1000 } };

// ---------- Session (cookie signé) ----------
const hmac = s => crypto.createHmac('sha256', SESSION_SECRET).update(s).digest('base64url');
const makeSession = u => { const p = Buffer.from(JSON.stringify({ ...u, exp: Date.now() + 7 * 864e5 })).toString('base64url'); return p + '.' + hmac(p); };
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map(c => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
const getUser = req => {
  const raw = cookies(req).sid; if (!raw) return null;
  const [p, sig] = raw.split('.');
  if (!p || !sig || hmac(p) !== sig) return null;
  try { const u = JSON.parse(Buffer.from(p, 'base64url').toString()); return u.exp > Date.now() ? u : null; } catch { return null; }
};
const setCookie = (res, name, val, age) =>
  res.append('Set-Cookie', `${name}=${val}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${age}${SECURE ? '; Secure' : ''}`);

const avatarUrl = (id, hash) => hash
  ? `https://cdn.discordapp.com/avatars/${id}/${hash}.png?size=64`
  : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(id) >> 22n) % 6}.png`;

// ---------- Serveur ----------
const app = express();
app.use(express.json());

app.get('/', (_, res) => res.type('html').send(PAGE));

app.get('/login', (req, res) => {
  if (!CID || !SECRET) return res.status(500).send('DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET manquants dans .env');
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'st', state, 600);
  res.redirect('https://discord.com/oauth2/authorize?' + new URLSearchParams({
    client_id: CID, response_type: 'code', scope: 'identify', redirect_uri: REDIRECT, state, prompt: 'none',
  }));
});

app.get('/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || cookies(req).st !== state) return res.status(400).send('Connexion invalide, réessaie.');
    const tok = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CID, client_secret: SECRET, grant_type: 'authorization_code', code, redirect_uri: REDIRECT }),
    }).then(r => r.json());
    if (!tok.access_token) return res.status(400).send('Discord a refusé la connexion.');
    const u = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + tok.access_token } }).then(r => r.json());
    setCookie(res, 'sid', makeSession({ id: u.id, name: u.global_name || u.username, avatar: avatarUrl(u.id, u.avatar) }), 604800);
    setCookie(res, 'st', '', 0);
    res.redirect('/');
  } catch (e) { console.error(e); res.status(500).send('Erreur de connexion.'); }
});

app.get('/logout', (_, res) => { setCookie(res, 'sid', '', 0); res.redirect('/'); });

app.get('/api/me', (req, res) => { const u = getUser(req); res.json(u ? { id: u.id, name: u.name, avatar: u.avatar } : null); });

app.get('/api/leaderboard/:game', (req, res) => {
  const t = db[req.params.game] || {};
  res.json(Object.values(t).sort((a, b) => b.score - a.score).slice(0, 10));
});

const lastPost = new Map();
app.post('/api/score', (req, res) => {
  const u = getUser(req);
  if (!u) return res.status(401).json({ error: 'auth' });
  const { game } = req.body, score = Math.floor(Number(req.body.score));
  const g = GAMES[game];
  if (!g || !Number.isFinite(score) || score < 1 || score > g.max) return res.status(400).json({ error: 'score' });
  const t = (db[game] ??= {});
  const old = t[u.id];
  const best = !old || score > old.score;
  if (best) { t[u.id] = { name: u.name, avatar: u.avatar, score }; save(); }
  if (best && WEBHOOK_URL && Date.now() - (lastPost.get(u.id) || 0) > 20000) {
    lastPost.set(u.id, Date.now());
    fetch(WEBHOOK_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [{ color: 0x5865f2, title: '🏆 Nouveau record', description: `**${u.name}** a fait **${score}** à **${g.name}**`, thumbnail: { url: u.avatar } }] }),
    }).catch(() => {});
  }
  res.json({ best, record: t[u.id].score });
});

app.listen(PORT, () => console.log(`🎮 Arcade : ${BASE_URL} (port ${PORT})`));

// ---------- Page (HTML + jeux, tout est ici) ----------
const PAGE = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Arcade</title>
<style>
  :root { --bg:#0e1018; --panel:#171a26; --line:#272b3d; --text:#e9ebf6; --mute:#8c91a9; --blurple:#5865f2; --ok:#3ecf8e; --pink:#ff5d73; color-scheme: dark; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; padding:max(14px,env(safe-area-inset-top)) 14px 40px; }
  main { max-width:880px; margin:0 auto; }
  header { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:16px; }
  h1 { margin:0; font:900 1.7rem "Arial Black",Impact,sans-serif; letter-spacing:-.02em; }
  .who { display:flex; align-items:center; gap:8px; font-weight:600; }
  .who img { width:32px; height:32px; border-radius:50%; }
  .who a.out { color:var(--mute); font-weight:400; font-size:.85rem; }
  a.login { background:var(--blurple); color:#fff; text-decoration:none; padding:9px 14px; border-radius:8px; font-weight:600; white-space:nowrap; }
  nav { display:flex; gap:8px; overflow-x:auto; padding-bottom:4px; margin-bottom:14px; }
  nav button { background:var(--panel); color:var(--text); border:1px solid var(--line); border-radius:8px; padding:9px 16px; font:inherit; cursor:pointer; flex:none; }
  nav button.on { background:var(--blurple); border-color:var(--blurple); }
  .grid { display:grid; gap:14px; }
  @media (min-width:760px) { .grid { grid-template-columns:1fr 280px; align-items:start; } }
  .box { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px; }
  .bar { display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; gap:8px; }
  #score { font-weight:700; }
  .bar button, .fin { background:var(--line); color:var(--text); border:0; border-radius:8px; padding:7px 12px; font:inherit; cursor:pointer; }
  #stage { display:flex; justify-content:center; }
  .cv { width:100%; max-width:380px; aspect-ratio:1; border-radius:8px; touch-action:none; image-rendering:pixelated; }
  .b2048 { width:100%; max-width:380px; display:grid; grid-template-columns:repeat(4,1fr); gap:8px; touch-action:none; }
  .t { aspect-ratio:1; border-radius:8px; display:grid; place-items:center; font-weight:800; font-size:clamp(1.1rem,6vw,1.8rem); color:#fff; }
  .bmem { width:100%; max-width:380px; display:grid; grid-template-columns:repeat(4,1fr); gap:8px; }
  .card { aspect-ratio:1; border:0; border-radius:8px; background:var(--line); font-size:clamp(1.4rem,8vw,2.2rem); cursor:pointer; color:var(--text); }
  .card.up { background:#2c3354; }
  .card.ok { background:#1f5a3f; }
  .bttt { width:100%; max-width:320px; display:grid; grid-template-columns:repeat(3,1fr); gap:8px; }
  .cell { aspect-ratio:1; border:0; border-radius:8px; background:var(--line); font:800 clamp(2rem,12vw,3rem) system-ui; cursor:pointer; }
  .cell.X { color:var(--blurple); } .cell.O { color:var(--pink); }
  #msg { min-height:1.5em; margin:10px 0 0; color:var(--mute); text-align:center; }
  h2 { font-size:1rem; margin:0 0 10px; }
  ol { list-style:none; margin:0; padding:0; }
  li { display:flex; align-items:center; gap:10px; padding:7px 0; border-top:1px solid var(--line); }
  li:first-child { border-top:0; }
  li .rk { width:1.4em; color:var(--mute); text-align:right; }
  li img { width:26px; height:26px; border-radius:50%; }
  li .nm { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  li b { color:var(--ok); }
  .empty { color:var(--mute); margin:0; }
  button:focus-visible, a:focus-visible { outline:2px solid var(--blurple); outline-offset:2px; }
</style>
</head>
<body>
<main>
  <header>
    <h1>Arcade</h1>
    <div id="user"></div>
  </header>
  <nav id="tabs">
    <button data-g="snake">Snake</button>
    <button data-g="2048">2048</button>
    <button data-g="memory">Memory</button>
    <button data-g="morpion">Morpion</button>
  </nav>
  <div class="grid">
    <section class="box">
      <div class="bar"><span id="score"></span><span><button id="fin" hidden>Envoyer mon score</button> <button id="again">Rejouer</button></span></div>
      <div id="stage"></div>
      <p id="msg"></p>
    </section>
    <aside class="box">
      <h2 id="boardtitle">Classement</h2>
      <ol id="board"></ol>
    </aside>
  </div>
</main>

<script>
var $ = function (s) { return document.querySelector(s); };
var stage = $('#stage'), cur = null, game = 'snake', me = null;
var NAMES = { snake: 'Snake', '2048': '2048', memory: 'Memory', morpion: 'Morpion' };

function setScore(v) { $('#score').textContent = typeof v === 'number' ? 'Score : ' + v : v; }
function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }

// ---------- Connexion Discord ----------
function renderUser() {
  var u = $('#user'); u.innerHTML = '';
  if (me) {
    var w = el('div', 'who'), img = el('img'); img.src = me.avatar; img.alt = '';
    var out = el('a', 'out', 'Déconnexion'); out.href = '/logout';
    w.appendChild(img); w.appendChild(el('span', null, me.name)); w.appendChild(out); u.appendChild(w);
  } else {
    var a = el('a', 'login', 'Se connecter avec Discord'); a.href = '/login'; u.appendChild(a);
  }
}

// ---------- Classement ----------
function loadBoard() {
  var ol = $('#board'); ol.innerHTML = '';
  $('#boardtitle').textContent = 'Classement ' + NAMES[game];
  if (game === 'morpion') { ol.appendChild(el('p', 'empty', 'Pas de classement pour ce jeu.')); return; }
  fetch('/api/leaderboard/' + game).then(function (r) { return r.json(); }).then(function (rows) {
    ol.innerHTML = '';
    if (!rows.length) { ol.appendChild(el('p', 'empty', 'Aucun score pour l’instant. Sois le premier !')); return; }
    rows.forEach(function (r, i) {
      var li = el('li'), img = el('img'); img.src = r.avatar; img.alt = '';
      li.appendChild(el('span', 'rk', i + 1)); li.appendChild(img);
      li.appendChild(el('span', 'nm', r.name)); li.appendChild(el('b', null, r.score));
      ol.appendChild(li);
    });
  });
}

function finish(s) {
  var m = $('#msg');
  if (!me) { m.textContent = 'Partie finie : ' + s + '. Connecte-toi avec Discord pour enregistrer ton score.'; return; }
  fetch('/api/score', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ game: game, score: s }) })
    .then(function (r) { return r.json(); })
    .then(function (r) {
      m.textContent = r.best ? 'Nouveau record : ' + s + ' !' : 'Score : ' + s + ' (record : ' + r.record + ')';
      loadBoard();
    }).catch(function () { m.textContent = 'Impossible d’envoyer le score.'; });
}

// ---------- Jeux ----------
var games = {};

games.snake = function (stage, end) {
  var N = 18, S = 20, c = el('canvas', 'cv'); c.width = c.height = N * S; stage.appendChild(c);
  var x = c.getContext('2d'), snake = [{ x: 9, y: 9 }], d = { x: 1, y: 0 }, nd = d, score = 0, t = null, food;
  function free(p) { return !snake.some(function (s) { return s.x === p.x && s.y === p.y; }); }
  function rnd() { var p; do { p = { x: Math.floor(Math.random() * N), y: Math.floor(Math.random() * N) }; } while (!free(p)); return p; }
  function draw() {
    x.fillStyle = '#10131c'; x.fillRect(0, 0, c.width, c.height);
    x.fillStyle = '#ff5d73'; x.fillRect(food.x * S + 2, food.y * S + 2, S - 4, S - 4);
    x.fillStyle = '#3ecf8e'; snake.forEach(function (s) { x.fillRect(s.x * S + 1, s.y * S + 1, S - 2, S - 2); });
  }
  function stop() { clearInterval(t); }
  function tick() {
    d = nd; var h = { x: snake[0].x + d.x, y: snake[0].y + d.y };
    if (h.x < 0 || h.y < 0 || h.x >= N || h.y >= N || !free(h)) { stop(); end(score); return; }
    snake.unshift(h);
    if (h.x === food.x && h.y === food.y) { score++; food = rnd(); setScore(score); } else snake.pop();
    draw();
  }
  food = rnd(); setScore(score); draw();
  $('#msg').textContent = 'Flèches, ZQSD ou glisse le doigt pour démarrer.';
  return { stop: stop, dir: function (k) {
    var m = { U: [0, -1], D: [0, 1], L: [-1, 0], R: [1, 0] }[k];
    if (snake.length > 1 && m[0] === -d.x && m[1] === -d.y) return;
    nd = { x: m[0], y: m[1] };
    if (!t) t = setInterval(tick, 110);
  } };
};

games['2048'] = function (stage, end) {
  var g = [], score = 0, over = false, box = el('div', 'b2048'); stage.appendChild(box);
  for (var i = 0; i < 16; i++) g.push(0);
  function add() {
    var e = []; g.forEach(function (v, i) { if (!v) e.push(i); });
    if (e.length) g[e[Math.floor(Math.random() * e.length)]] = Math.random() < 0.9 ? 2 : 4;
  }
  function render() {
    box.innerHTML = '';
    g.forEach(function (v) {
      var d = el('div', 't', v || '');
      d.style.background = v ? 'hsl(' + (Math.log(v) / Math.LN2 * 32) + ',55%,42%)' : '#1d2130';
      if (v > 999) d.style.fontSize = '1.1rem';
      box.appendChild(d);
    });
    setScore(score);
  }
  function line(a) {
    var r = a.filter(Boolean), o = [];
    for (var i = 0; i < r.length; i++) {
      if (r[i] === r[i + 1]) { o.push(r[i] * 2); score += r[i] * 2; i++; } else o.push(r[i]);
    }
    while (o.length < 4) o.push(0);
    return o;
  }
  function can() {
    if (g.indexOf(0) > -1) return true;
    for (var i = 0; i < 16; i++) {
      if (i % 4 < 3 && g[i] === g[i + 1]) return true;
      if (i < 12 && g[i] === g[i + 4]) return true;
    }
    return false;
  }
  function move(k) {
    var before = g.join(','), n = g.slice();
    for (var i = 0; i < 4; i++) {
      var idx = [0, 1, 2, 3].map(function (j) { return (k === 'L' || k === 'R') ? i * 4 + j : j * 4 + i; });
      if (k === 'R' || k === 'D') idx.reverse();
      var res = line(idx.map(function (p) { return g[p]; }));
      idx.forEach(function (p, j) { n[p] = res[j]; });
    }
    g = n;
    if (g.join(',') === before) return;
    add(); render();
    if (!can()) { over = true; end(score); }
  }
  add(); add(); render();
  $('#fin').hidden = false;
  $('#msg').textContent = 'Flèches, ZQSD ou glisse le doigt.';
  return { stop: function () {}, dir: function (k) { if (!over) move(k); }, finish: function () { over = true; end(score); } };
};

games.memory = function (stage, end) {
  var em = ['🎮', '👾', '🕹️', '🏆', '🎲', '🎯', '🧩', '🚀'];
  var cards = em.concat(em).sort(function () { return Math.random() - 0.5; });
  var box = el('div', 'bmem'), open = [], found = 0, moves = 0, t0 = null, lock = false;
  stage.appendChild(box); setScore('Coups : 0');
  cards.forEach(function (e, i) {
    var b = el('button', 'card'); b.setAttribute('aria-label', 'Carte ' + (i + 1));
    b.onclick = function () { flip(b, i); }; box.appendChild(b);
  });
  function flip(b, i) {
    if (lock || b.classList.contains('up')) return;
    if (!t0) t0 = Date.now();
    b.classList.add('up'); b.textContent = cards[i]; open.push([b, i]);
    if (open.length < 2) return;
    moves++; setScore('Coups : ' + moves);
    var a = open[0], c = open[1]; open = [];
    if (cards[a[1]] === cards[c[1]]) {
      found++; a[0].classList.add('ok'); c[0].classList.add('ok');
      if (found === 8) end(Math.max(10, 1000 - moves * 15 - Math.round((Date.now() - t0) / 1000) * 3));
    } else {
      lock = true;
      setTimeout(function () { a[0].classList.remove('up'); c[0].classList.remove('up'); a[0].textContent = ''; c[0].textContent = ''; lock = false; }, 700);
    }
  }
  $('#msg').textContent = 'Trouve toutes les paires le plus vite possible.';
  return { stop: function () {} };
};

games.morpion = function (stage) {
  var b = ['', '', '', '', '', '', '', '', ''], done = false, box = el('div', 'bttt'); stage.appendChild(box);
  var L = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  function win(p) { return L.some(function (l) { return l.every(function (i) { return b[i] === p; }); }); }
  function find(p) {
    for (var k = 0; k < L.length; k++) {
      var l = L[k], m = l.filter(function (i) { return b[i] === p; }), e = l.filter(function (i) { return !b[i]; });
      if (m.length === 2 && e.length === 1) return e[0];
    }
    return -1;
  }
  function ai() {
    var m = find('O'); if (m < 0) m = find('X'); if (m < 0 && !b[4]) m = 4;
    if (m < 0) { var e = []; b.forEach(function (v, i) { if (!v) e.push(i); }); m = e[Math.floor(Math.random() * e.length)]; }
    b[m] = 'O';
  }
  function check() {
    if (win('X')) { setScore('Tu as gagné !'); done = true; }
    else if (win('O')) { setScore('Perdu…'); done = true; }
    else if (b.indexOf('') < 0) { setScore('Égalité'); done = true; }
    return done;
  }
  function render() {
    box.innerHTML = '';
    b.forEach(function (v, i) {
      var c = el('button', 'cell ' + v, v); c.setAttribute('aria-label', 'Case ' + (i + 1));
      c.onclick = function () { if (done || b[i]) return; b[i] = 'X'; if (!check()) { ai(); check(); } render(); };
      box.appendChild(c);
    });
  }
  setScore('À toi de jouer (X)'); render();
  $('#msg').textContent = 'Contre l’ordinateur.';
  return { stop: function () {} };
};

// ---------- Navigation et contrôles ----------
function start(g) {
  if (cur && cur.stop) cur.stop();
  game = g; stage.innerHTML = ''; $('#msg').textContent = ''; $('#fin').hidden = true;
  document.querySelectorAll('#tabs button').forEach(function (b) { b.classList.toggle('on', b.dataset.g === g); });
  cur = games[g](stage, finish);
  loadBoard();
}
$('#tabs').addEventListener('click', function (e) { if (e.target.dataset.g) start(e.target.dataset.g); });
$('#again').onclick = function () { start(game); };
$('#fin').onclick = function () { if (cur && cur.finish) cur.finish(); };

document.addEventListener('keydown', function (e) {
  var m = { ArrowUp: 'U', ArrowDown: 'D', ArrowLeft: 'L', ArrowRight: 'R', w: 'U', z: 'U', s: 'D', a: 'L', q: 'L', d: 'R' }[e.key];
  if (m && cur && cur.dir) { e.preventDefault(); cur.dir(m); }
});
var sx = 0, sy = 0;
stage.addEventListener('touchstart', function (e) { sx = e.touches[0].clientX; sy = e.touches[0].clientY; }, { passive: true });
stage.addEventListener('touchend', function (e) {
  var t = e.changedTouches[0], dx = t.clientX - sx, dy = t.clientY - sy;
  if (Math.max(Math.abs(dx), Math.abs(dy)) < 24 || !cur || !cur.dir) return;
  cur.dir(Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? 'R' : 'L') : (dy > 0 ? 'D' : 'U'));
}, { passive: true });

fetch('/api/me').then(function (r) { return r.json(); }).then(function (u) { me = u; renderUser(); }).catch(renderUser);
start('snake');
</script>
</body>
</html>`;
