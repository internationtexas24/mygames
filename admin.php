<?php
// admin.php - admin console for user and game management (TXT storage).
session_start();
define('USERS_FILE', __DIR__ . '/users.txt');
define('GAMES_FILE', __DIR__ . '/games.txt');

// ----------------------------------------------------------------
// helpers
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
function safe($s){ return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function csrf_token(){ if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16)); return $_SESSION['csrf']; }
function check_csrf($t){ return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t); }

// seed admin if empty
function ensure_seed_admin(){
    if (!file_exists(USERS_FILE) || filesize(USERS_FILE) === 0){
        $pw = password_hash('admin123', PASSWORD_DEFAULT);
        write_lines_atomic(USERS_FILE, ["admin|$pw|admin"]);
    }
}
ensure_seed_admin();

// find user entry index & fields
function read_users(){
    $out = [];
    foreach (read_lines(USERS_FILE) as $ln){
        [$u,$h,$r] = array_pad(explode('|', $ln, 3), 3, '');
        $out[] = ['username'=>$u,'hash'=>$h,'role'=>$r];
    }
    return $out;
}
function write_users($users){
    $lines = [];
    foreach ($users as $u) $lines[] = "{$u['username']}|{$u['hash']}|{$u['role']}";
    write_lines_atomic(USERS_FILE, $lines);
}
function find_user($username){
    foreach (read_users() as $u) if (strcasecmp($u['username'],$username)===0) return $u;
    return null;
}
function find_user_index($username){
    $idx=0;
    foreach (read_users() as $u){ if (strcasecmp($u['username'],$username)===0) return $idx; $idx++; }
    return -1;
}

// games
function read_games(){
    $out = [];
    foreach (read_lines(GAMES_FILE) as $ln){
        [$title,$url] = array_pad(explode('|', $ln, 2), 2, '');
        $out[] = ['title'=>$title,'url'=>$url];
    }
    return $out;
}
function write_games($games){
    $lines = [];
    foreach ($games as $g) $lines[] = "{$g['title']}|{$g['url']}";
    write_lines_atomic(GAMES_FILE, $lines);
}

// auth & role
$current = $_SESSION['user'] ?? null;
function require_admin(){
    global $current;
    if (!$current || ($current['role'] ?? '') !== 'admin'){
        header('Location: index.php'); exit;
    }
}

// login handling (admin console includes login shortcut)
$errors=[]; $msg='';
if (isset($_POST['action']) && $_POST['action']==='login'){
    $user = trim($_POST['username'] ?? '');
    $pw = $_POST['password'] ?? '';
    $found = find_user($user);
    if ($found && password_verify($pw, $found['hash'])){
        $_SESSION['user'] = ['username'=>$found['username'],'role'=>$found['role']];
        session_regenerate_id(true);
        header('Location: '.$_SERVER['PHP_SELF']); exit;
    } else {
        $errors[] = 'Invalid credentials.';
    }
}

// protect subsequent actions to admin
$current = $_SESSION['user'] ?? null;
if (!$current || ($current['role'] ?? '') !== 'admin'){
    // not admin: show login form only
    ?><!doctype html><html><head><meta charset="utf-8"><title>Admin - login</title>
    <style>body{font-family:system-ui;padding:20px;background:#071226;color:#e6eef8}.card{background:#0f1724;padding:14px;border-radius:8px;max-width:520px;margin:auto}</style>
    </head><body><div class="card"><h2>Admin login</h2>
    <?php if($errors) foreach($errors as $e) echo "<div style='color:#ffb4b4;'>".safe($e)."</div>"; ?>
    <form method="post"><input name="username" placeholder="username" required style="width:100%;padding:8px;margin:6px 0"><input name="password" placeholder="password" type="password" required style="width:100%;padding:8px;margin:6px 0">
    <input type="hidden" name="action" value="login"><div><button style="padding:8px 12px;border-radius:6px;background:#06b6d4;border:0">Sign in</button></div></form>
    <div class="small" style="margin-top:8px;color:#94a3b8">Seed admin: admin / admin123</div></div></body></html><?php
    exit;
}

// now admin is authenticated: handle actions (CSRF required)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['action'] ?? '';
    $token = $_POST['csrf'] ?? '';
    if (!check_csrf($token)) { $errors[] = 'Invalid CSRF token.'; }
    else {
        if ($act === 'create_user'){
            $uname = trim($_POST['username'] ?? '');
            $pw = $_POST['password'] ?? '';
            if ($uname === '' || $pw === '') $errors[] = 'Provide username and password.';
            else if (find_user($uname)) $errors[] = 'User exists.';
            else {
                $u = ['username'=>$uname,'hash'=>password_hash($pw,PASSWORD_DEFAULT),'role'=>'user'];
                $users = read_users(); $users[] = $u; write_users($users);
                $msg = 'User created.';
            }
        } elseif ($act === 'change_password'){
            $uname = trim($_POST['username'] ?? '');
            $pw = $_POST['new_password'] ?? '';
            if ($pw === '') $errors[] = 'Provide new password.';
            else {
                $idx = find_user_index($uname);
                if ($idx < 0) $errors[] = 'User not found.';
                else {
                    $users = read_users();
                    $users[$idx]['hash'] = password_hash($pw, PASSWORD_DEFAULT);
                    write_users($users);
                    $msg = 'Password changed for ' . $uname;
                }
            }
        } elseif ($act === 'remove_user'){
            $uname = trim($_POST['username'] ?? '');
            if (strcasecmp($uname, ($_SESSION['user']['username'] ?? '')) === 0) $errors[] = 'Cannot remove yourself while logged in.';
            else {
                $users = read_users();
                $new = array_filter($users, function($u) use($uname){ return strcasecmp($u['username'],$uname)!==0; });
                write_users(array_values($new));
                $msg = 'User removed.';
            }
        } elseif ($act === 'add_game'){
            $title = trim($_POST['title'] ?? '');
            $url = trim($_POST['url'] ?? '');
            if ($title === '' || $url === '') $errors[] = 'Provide title and URL.';
            else {
                $games = read_games();
                $games[] = ['title'=>$title,'url'=>$url];
                write_games($games);
                $msg = 'Game added.';
            }
        } elseif ($act === 'remove_game'){
            $title = trim($_POST['title'] ?? '');
            $games = read_games();
            $new = array_filter($games, function($g) use($title){ return !(strcmp($g['title'],$title)===0); });
            write_games(array_values($new));
            $msg = 'Game removed (by title).';
        }
    }
    // refresh current lists after action
}

// reload lists
$users = read_users();
$games = read_games();
$token = csrf_token();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Console — 3kh0</title>
<style>
body{font-family:Inter,system-ui,Segoe UI,Roboto,Helvetica,Arial;background:#071226;color:#e6eef8;margin:0;padding:18px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.logo{background:linear-gradient(135deg,#06b6d4,#3b82f6);width:44px;height:44px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;color:#021124}
.container{max-width:1100px;margin:0 auto}
.card{background:#0f1724;padding:14px;border-radius:10px;margin-bottom:12px;box-shadow:0 8px 24px rgba(2,6,23,0.6)}
.row{display:flex;gap:12px;flex-wrap:wrap}
.col{flex:1;min-width:260px}
.form input, .form select{width:100%;padding:8px;margin:6px 0;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:transparent;color:#e6eef8}
.btn{padding:8px 12px;border-radius:8px;background:#06b6d4;color:#021124;border:0;font-weight:700}
.small{color:#94a3b8;font-size:13px}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
.notice{color:#94a3b8;font-size:13px}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div style="display:flex;gap:12px;align-items:center">
            <div class="logo">3K</div>
            <div>
                <div style="font-weight:800">3kh0 — Admin Console</div>
                <div class="small">Signed in as <strong><?= safe($_SESSION['user']['username']) ?></strong></div>
            </div>
        </div>
        <div>
            <a href="index.php" class="btn" style="background:#94a3b8;color:#021124">Go to site</a>
            <a href="index.php?action=logout" class="btn" style="background:#ef4444;margin-left:8px">Log out</a>
        </div>
    </div>

    <?php if($msg) echo '<div class="card notice">'.$msg.'</div>'; ?>
    <?php if($errors) foreach($errors as $e) echo '<div class="card" style="border-left:4px solid #ef4444;color:#ffb4b4">'.$e.'</div>'; ?>

    <div class="card">
        <h3>Users — Admin only</h3>
        <div class="row">
            <div class="col">
                <form method="post" class="form">
                    <input type="hidden" name="csrf" value="<?= $token ?>">
                    <input type="hidden" name="action" value="create_user">
                    <label class="small">Create user (admin creates accounts)</label>
                    <input name="username" placeholder="username" required>
                    <input name="password" placeholder="password" type="password" required>
                    <div style="margin-top:6px"><button class="btn" type="submit">Create user</button></div>
                </form>
            </div>

            <div class="col">
                <form method="post" class="form">
                    <input type="hidden" name="csrf" value="<?= $token ?>">
                    <input type="hidden" name="action" value="change_password">
                    <label class="small">Change password for an existing user</label>
                    <select name="username" required>
                        <?php foreach($users as $u) echo '<option>'.safe($u['username']).'</option>'; ?>
                    </select>
                    <input name="new_password" placeholder="new password" type="password" required>
                    <div style="margin-top:6px"><button class="btn" type="submit">Change password</button></div>
                </form>
            </div>

            <div class="col">
                <form method="post" class="form" onsubmit="return confirm('Remove user? This cannot be undone');">
                    <input type="hidden" name="csrf" value="<?= $token ?>">
                    <input type="hidden" name="action" value="remove_user">
                    <label class="small">Remove user</label>
                    <select name="username" required>
                        <?php foreach($users as $u) {
                            if (strcasecmp($u['username'], $_SESSION['user']['username'])===0) {
                                echo '<option value="'.safe($u['username']).'">'.safe($u['username']).' (you)</option>';
                            } else {
                                echo '<option>'.safe($u['username']).'</option>';
                            }
                        } ?>
                    </select>
                    <div style="margin-top:6px"><button class="btn" type="submit" style="background:#ef4444">Remove user</button></div>
                </form>
            </div>
        </div>

        <div style="margin-top:12px">
            <table class="table">
                <thead><tr><th>Username</th><th>Role</th></tr></thead>
                <tbody>
                    <?php foreach($users as $u): ?>
                        <tr><td><?= safe($u['username']) ?></td><td class="small"><?= safe($u['role']) ?></td></tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h3>Games</h3>
        <div class="row">
            <div class="col">
                <form method="post" class="form">
                    <input type="hidden" name="csrf" value="<?= $token ?>">
                    <input type="hidden" name="action" value="add_game">
                    <label class="small">Add game (title + URL required)</label>
                    <input name="title" placeholder="Game title" required>
                    <input name="url" placeholder="https://example.com/game" required>
                    <div style="margin-top:6px"><button class="btn" type="submit">Add game</button></div>
                </form>
            </div>

            <div class="col">
                <form method="post" class="form" onsubmit="return confirm('Remove game?');">
                    <input type="hidden" name="csrf" value="<?= $token ?>">
                    <input type="hidden" name="action" value="remove_game">
                    <label class="small">Remove game (select by title)</label>
                    <select name="title" required>
                        <?php foreach($games as $g) echo '<option>'.safe($g['title']).'</option>'; ?>
                    </select>
                    <div style="margin-top:6px"><button class="btn" type="submit" style="background:#ef4444">Remove game</button></div>
                </form>
            </div>
        </div>

        <div style="margin-top:12px">
            <table class="table">
                <thead><tr><th>Title</th><th>URL</th></tr></thead>
                <tbody>
                    <?php foreach($games as $g): ?>
                        <tr><td><?= safe($g['title']) ?></td><td><a href="<?= safe($g['url']) ?>" target="_blank"><?= safe($g['url']) ?></a></td></tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="small">Data files: <code><?= safe(realpath(USERS_FILE) ?: USERS_FILE) ?></code>, <code><?= safe(realpath(GAMES_FILE) ?: GAMES_FILE) ?></code></div>
    <div class="small" style="margin-top:8px;color:#fbbf24">Security note: Seed admin is <strong>admin / admin123</strong>. Change it immediately.</div>
</div>
</body>
</html>
