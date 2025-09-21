<?php
// index.php - 3kh0-like frontend (login + games grid). Uses users.txt and games.txt
session_start();
define('USERS_FILE', __DIR__ . '/users.txt');
define('GAMES_FILE', __DIR__ . '/games.txt');

// ---- utilities ----
function safe($s){ return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function read_lines($path){
    if (!file_exists($path)) return [];
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return $lines ?: [];
}
function write_lines_atomic($path, $lines){
    $tmp = $path . '.tmp';
    file_put_contents($tmp, implode(PHP_EOL, $lines) . PHP_EOL, LOCK_EX);
    rename($tmp, $path);
}
function ensure_seed_admin(){
    $lines = read_lines(USERS_FILE);
    if (count($lines) === 0){
        $pw = password_hash('admin123', PASSWORD_DEFAULT);
        // format: username|hash|role
        $lines[] = "admin|$pw|admin";
        write_lines_atomic(USERS_FILE, $lines);
    }
}
function find_user($username){
    $username = strtolower($username);
    $lines = read_lines(USERS_FILE);
    foreach ($lines as $ln){
        [$u, $h, $r] = array_pad(explode('|', $ln, 3), 3, '');
        if (strtolower($u) === $username) return ['username'=>$u,'hash'=>$h,'role'=>$r];
    }
    return null;
}
function csrf_token(){
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
    return $_SESSION['csrf'];
}
function check_csrf($t){
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t);
}

// ---- ensure admin seeded ----
ensure_seed_admin();

// ---- actions ----
$errors = [];
$msg = '';
if (isset($_POST['action']) && $_POST['action'] === 'login'){
    $user = trim($_POST['username'] ?? '');
    $pass = $_POST['password'] ?? '';
    $found = find_user($user);
    if ($found && password_verify($pass, $found['hash'])){
        $_SESSION['user'] = ['username'=>$found['username'],'role'=>$found['role']];
        session_regenerate_id(true);
        header('Location: '.$_SERVER['PHP_SELF']); exit;
    } else {
        $errors[] = 'Invalid username or password.';
    }
}
if (isset($_GET['action']) && $_GET['action'] === 'logout'){
    session_unset(); session_destroy();
    header('Location: '.$_SERVER['PHP_SELF']); exit;
}

// load games
$games = [];
foreach (read_lines(GAMES_FILE) as $ln){
    [$title, $url] = array_pad(explode('|', $ln, 2), 2, '#');
    $games[] = ['title'=>$title,'url'=>$url];
}

// current user
$current = $_SESSION['user'] ?? null;
$is_admin = $current && ($current['role'] === 'admin');

// ---- HTML output ----
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>3kh0 - Games</title>
<style>
/* Minimal 3kh0-ish dark theme / grid */
:root{--bg:#0b1220;--card:#0f1724;--muted:#94a3b8;--accent:#00b4d8}
body{margin:0;font-family:Inter,ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial;background:linear-gradient(180deg,#071226 0%, #071826 100%);color:#e6eef8}
.header{display:flex;align-items:center:justify-content:space-between;padding:18px 28px;background:rgba(0,0,0,0.18);backdrop-filter:blur(4px)}
.brand{display:flex;gap:12px;align-items:center}
.logo{width:42px;height:42px;background:linear-gradient(135deg,#06b6d4,#3b82f6);border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;color:#021124}
.nav a{color:var(--muted);text-decoration:none;margin-left:12px}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
.card{background:var(--card);padding:12px;border-radius:10px;box-shadow:0 6px 18px rgba(2,6,23,0.6);border:1px solid rgba(255,255,255,0.02)}
.card h3{margin:0 0 8px 0;font-size:16px}
.btn{display:inline-block;padding:8px 12px;border-radius:8px;background:var(--accent);color:#00121a;text-decoration:none;font-weight:600}
.login-box{max-width:760px;margin:18px auto;background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));padding:16px;border-radius:10px;display:flex;gap:12px;align-items:center}
.form input{display:block;width:100%;padding:10px;margin:6px 0;border-radius:8px;border:1px solid rgba(255,255,255,0.06);background:rgba(255,255,255,0.02);color:#eaf6ff}
.small{color:var(--muted);font-size:13px}
.footer{color:var(--muted);text-align:center;margin-top:30px;font-size:13px}
</style>
</head>
<body>
<div class="header">
    <div class="brand">
        <div class="logo">3K</div>
        <div>
            <div style="font-weight:700">3kh0</div>
            <div class="small">v4 — games shell</div>
        </div>
    </div>
    <div class="nav">
        <a href="<?= $_SERVER['PHP_SELF'] ?>" class="small">Home</a>
        <?php if($is_admin): ?>
            <a href="admin.php" class="small">Admin Console</a>
        <?php endif; ?>
        <?php if($current): ?>
            <a href="?action=logout" class="small">Logout (<?= safe($current['username']) ?>)</a>
        <?php endif; ?>
    </div>
</div>

<div class="container">
    <?php if(!$current): ?>
        <div class="login-box card">
            <div style="flex:1">
                <h2>Sign in</h2>
                <div class="small">Admins create accounts via the admin console. Use seeded admin if first run: <strong>admin / admin123</strong></div>
            </div>
            <div style="min-width:320px">
                <?php if(!empty($errors)): foreach($errors as $e): ?>
                    <div style="color:#ffb4b4;padding:6px;border-radius:6px;margin-bottom:6px"><?= safe($e) ?></div>
                <?php endforeach; endif; ?>
                <form method="post" class="form" action="">
                    <input name="username" placeholder="username" required>
                    <input name="password" placeholder="password" type="password" required>
                    <input type="hidden" name="action" value="login">
                    <div style="margin-top:8px"><button class="btn" type="submit">Log in</button></div>
                </form>
            </div>
        </div>
    <?php endif; ?>

    <h2 style="margin-bottom:10px">Play — Games</h2>
    <?php if(count($games) === 0): ?>
        <div class="card small">No games available yet. Admin can add games in the admin console.</div>
    <?php else: ?>
        <div class="grid" aria-live="polite">
            <?php foreach($games as $g): ?>
                <div class="card">
                    <h3><?= safe($g['title']) ?></h3>
                    <div class="small" style="margin-bottom:10px"><?= safe($g['url']) ?></div>
                    <a class="btn" href="<?= safe($g['url']) ?>" target="_blank" rel="noopener noreferrer">Play</a>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <div class="footer">Files: <code><?= safe(realpath(USERS_FILE) ?: USERS_FILE) ?></code> • <code><?= safe(realpath(GAMES_FILE) ?: GAMES_FILE) ?></code></div>
</div>
</body>
</html>
