const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const serveStatic = require('serve-static');
const bare = require('@titaniumnetwork-dev/bare-server-node');
const { uvPath } = require('@titaniumnetwork-dev/ultraviolet-static');
const http = require('http');

const APP_DIR = __dirname;
const DATA_DIR = path.join(APP_DIR, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const USERS_FILE = path.join(DATA_DIR, 'users.txt');
const GAMES_FILE = path.join(DATA_DIR, 'games.txt');

const PORT = process.env.PORT || 3000;
const ULTRAVIOLET_BASE = '/uv/service/';

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(APP_DIR, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/public', serveStatic(path.join(APP_DIR, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace_this_long_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

// ---------------- TXT STORAGE ----------------
function readLines(filepath) {
  if (!fs.existsSync(filepath)) return [];
  return fs.readFileSync(filepath, 'utf8').split(/\r?\n/).filter(Boolean);
}
function writeLinesAtomic(filepath, lines) {
  const tmp = filepath + '.tmp';
  fs.writeFileSync(tmp, lines.join('\n') + '\n', 'utf8');
  fs.renameSync(tmp, filepath);
}

// user: username|hash|role
function seedAdmin() {
  if (!fs.existsSync(USERS_FILE) || fs.statSync(USERS_FILE).size === 0) {
    const hash = bcrypt.hashSync('admin123', 10);
    writeLinesAtomic(USERS_FILE, [`admin|${hash}|admin`]);
    console.log('Seeded admin: admin / admin123');
  }
}
function parseUsers() {
  return readLines(USERS_FILE).map(line => {
    const [username, hash, role] = line.split('|');
    return { username, hash, role };
  });
}
function writeUsers(users) {
  const lines = users.map(u => `${u.username}|${u.hash}|${u.role}`);
  writeLinesAtomic(USERS_FILE, lines);
}
function findUser(username) {
  return parseUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
}

// games: title|url
function parseGames() {
  return readLines(GAMES_FILE).map(line => {
    const [title, url] = line.split('|', 2);
    return { title, url };
  });
}
function writeGames(games) {
  const lines = games.map(g => `${g.title}|${g.url}`);
  writeLinesAtomic(GAMES_FILE, lines);
}

// seed
seedAdmin();
if (!fs.existsSync(GAMES_FILE)) writeLinesAtomic(GAMES_FILE, []);

// ---------------- MIDDLEWARE ----------------
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/login');
  next();
}

// ---------------- ROUTES ----------------
app.get('/', (req, res) => {
  const games = parseGames();
  const gamesWithProxy = games.map(g => {
    const encoded = encodeURIComponent(g.url);
    return { title: g.title, url: g.url, proxy: ULTRAVIOLET_BASE + encoded };
  });
  res.render('index', { user: req.session.user || null, games: gamesWithProxy, msg: req.session.msg, err: req.session.err });
  req.session.msg = null; req.session.err = null;
});

app.get('/login', (req, res) => res.render('login', { err: req.session.err }));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  if (!user) { req.session.err='Invalid credentials'; return res.redirect('/login'); }
  const ok = await bcrypt.compare(password, user.hash);
  if (!ok) { req.session.err='Invalid credentials'; return res.redirect('/login'); }
  req.session.user = { username: user.username, role: user.role };
  res.redirect('/');
});
app.get('/logout', (req,res)=> { req.session.destroy(()=>res.redirect('/')); });

// Admin console
app.get('/admin', requireAdmin, (req, res) => {
  res.render('admin', { 
    user: req.session.user, 
    users: parseUsers(), 
    games: parseGames(), 
    csrf: req.session.csrf || (req.session.csrf = Math.random().toString(36).slice(2)),
    msg: req.session.msg,
    err: req.session.err
  });
  req.session.msg = null; req.session.err = null;
});

function checkCsrf(req) { return req.body.csrf && req.body.csrf === req.session.csrf; }

app.post('/admin/create-user', requireAdmin, async (req, res) => {
  if (!checkCsrf(req)) { req.session.err='Invalid CSRF'; return res.redirect('/admin'); }
  const { username, password } = req.body;
  if (!username || !password) { req.session.err='username+password required'; return res.redirect('/admin'); }
  if (findUser(username)) { req.session.err='user exists'; return res.redirect('/admin'); }
  const hash = await bcrypt.hash(password,10);
  const users = parseUsers(); users.push({username, hash, role:'user'}); writeUsers(users);
  req.session.msg='User created'; res.redirect('/admin');
});
app.post('/admin/change-password', requireAdmin, async (req,res)=>{
  if (!checkCsrf(req)) { req.session.err='Invalid CSRF'; return res.redirect('/admin'); }
  const { username, new_password } = req.body;
  if (!username || !new_password) { req.session.err='username+new password required'; return res.redirect('/admin'); }
  const users = parseUsers(); 
  const idx = users.findIndex(u => u.username.toLowerCase()===username.toLowerCase());
  if (idx===-1){ req.session.err='user not found'; return res.redirect('/admin'); }
  users[idx].hash = await bcrypt.hash(new_password,10);
  writeUsers(users);
  req.session.msg='Password changed'; res.redirect('/admin');
});
app.post('/admin/remove-user', requireAdmin, (req,res)=>{
  if (!checkCsrf(req)) { req.session.err='Invalid CSRF'; return res.redirect('/admin'); }
  const { username } = req.body;
  if (!username) { req.session.err='username required'; return res.redirect('/admin'); }
  if (req.session.user.username.toLowerCase() === username.toLowerCase()) { req.session.err='Cannot remove yourself'; return res.redirect('/admin'); }
  const users = parseUsers().filter(u=>u.username.toLowerCase()!==username.toLowerCase());
  writeUsers(users); req.session.msg='User removed'; res.redirect('/admin');
});
app.post('/admin/add-game', requireAdmin, (req,res)=>{
  if (!checkCsrf(req)) { req.session.err='Invalid CSRF'; return res.redirect('/admin'); }
  const { title, url } = req.body;
  if (!title || !url) { req.session.err='title + url required'; return res.redirect('/admin'); }
  const games = parseGames(); games.push({title,url}); writeGames(games);
  req.session.msg='Game added'; res.redirect('/admin');
});
app.post('/admin/remove-game', requireAdmin, (req,res)=>{
  if (!checkCsrf(req)) { req.session.err='Invalid CSRF'; return res.redirect('/admin'); }
  const { title } = req.body;
  if (!title) { req.session.err='title required'; return res.redirect('/admin'); }
  const games = parseGames().filter(g=>g.title!==title);
  writeGames(games); req.session.msg='Game removed'; res.redirect('/admin');
});

// ---------------- ULTRAVIOLET ----------------
app.use('/uv/', serveStatic(uvPath));
const server = http.createServer(app);
const bareServer = bare();
server.on('request',(req,res)=>{ 
  if (bareServer.shouldRoute(req)) bareServer.routeRequest(req,res); 
  else app(req,res); 
});
server.on('upgrade',(req,socket,head)=>{ if(bareServer.shouldRoute(req)) bareServer.routeUpgrade(req,socket,head); });

server.listen(PORT, ()=>{ console.log(`3kh0-node-uv with UV on http://localhost:${PORT}`); });
