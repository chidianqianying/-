<?php
/**
 * 管理后台
 */

session_start();

require __DIR__ . '/../config.php';

function sha256(string $data): string {
    return hash('sha256', $data);
}

function formatSize(int $bytes): string {
    $units = ['B', 'KB', 'MB', 'GB'];
    $unitIndex = 0;
    while ($bytes >= 1024 && $unitIndex < count($units) - 1) {
        $bytes /= 1024;
        $unitIndex++;
    }
    return round($bytes, 2) . ' ' . $units[$unitIndex];
}

function getDB() {
    global $CONFIG;
    try {
        $dsn = "mysql:host={$CONFIG['db_host']};port={$CONFIG['db_port']};dbname={$CONFIG['db_name']};charset=utf8mb4";
        $pdo = new PDO($dsn, $CONFIG['db_user'], $CONFIG['db_pass']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        return null;
    }
}

$pdo = getDB();
$admin = $pdo->query("SELECT * FROM admin LIMIT 1")->fetch(PDO::FETCH_ASSOC);
$mode = $admin['mode'] ?? 'loose';

$isLoggedIn = false;
if (isset($_SESSION['admin_token']) && isset($_SESSION['admin_ip'])) {
    $currentIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    // 验证 token 和 IP 是否匹配
    if ($admin['session_token'] === $_SESSION['admin_token'] && $admin['login_ip'] === $currentIp) {
        $isLoggedIn = true;
    } else {
        // token 或 IP 不匹配，清除 session
        unset($_SESSION['admin_token']);
        unset($_SESSION['admin_ip']);
        unset($_SESSION['admin_verified']);
    }
}

if ($mode === 'strict' && $isLoggedIn) {
    if (!isset($_SESSION['admin_verified']) || $_SESSION['admin_verified'] !== true) {
        $isLoggedIn = false;
        unset($_SESSION['admin_token']);
        unset($_SESSION['admin_ip']);
        unset($_SESSION['admin_verified']);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    header('Content-Type: application/json');

    if ($mode === 'loose') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        if ($username !== $admin['admin_username'] || sha256($password) !== $admin['admin_password_hash']) {
            echo json_encode(['success' => false, 'message' => '账号或口令错误']);
            exit;
        }
        $token = bin2hex(random_bytes(32));
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $pdo->prepare("UPDATE admin SET session_token = ?, login_ip = ? WHERE id = 1")
            ->execute([$token, $ip]);
        $_SESSION['admin_token'] = $token;
        $_SESSION['admin_ip'] = $ip;
        echo json_encode(['success' => true]);
        exit;
    }

    if ($mode === 'strict') {
        $email = trim($_POST['email'] ?? '');
        $code = trim($_POST['code'] ?? '');

        if ($email !== $admin['admin_email']) {
            echo json_encode(['success' => false, 'message' => '邮箱不正确']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT * FROM email_codes WHERE email = ? AND code = ? AND used = 0 AND expires_at > NOW() ORDER BY id DESC LIMIT 1");
        $stmt->execute([$email, $code]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$record) {
            echo json_encode(['success' => false, 'message' => '验证码无效或已过期']);
            exit;
        }

        $pdo->prepare("UPDATE email_codes SET used = 1 WHERE id = ?")->execute([$record['id']]);
        $token = bin2hex(random_bytes(32));
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $pdo->prepare("UPDATE admin SET session_token = ?, login_ip = ? WHERE id = 1")
            ->execute([$token, $ip]);
        $_SESSION['admin_token'] = $token;
        $_SESSION['admin_ip'] = $ip;
        $_SESSION['admin_verified'] = true;
        echo json_encode(['success' => true]);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_login_code'])) {
    header('Content-Type: application/json');

    if ($mode !== 'strict') {
        echo json_encode(['success' => false, 'message' => '当前不是严格模式']);
        exit;
    }

    $last = $_SESSION['last_login_send'] ?? 0;
    $wait = 60 - (time() - $last);
    if ($wait > 0) {
        echo json_encode(['success' => false, 'message' => '请等待 ' . $wait . ' 秒后再发送']);
        exit;
    }

    $phpmailerPath = __DIR__ . '/../PHPMailer/src/';
    require $phpmailerPath . 'Exception.php';
    require $phpmailerPath . 'PHPMailer.php';
    require $phpmailerPath . 'SMTP.php';

    $code = str_pad(strval(random_int(0, 999999)), 6, '0', STR_PAD_LEFT);
    $expires = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    $pdo->prepare("INSERT INTO email_codes (email, code, expires_at) VALUES (?, ?, ?)")
        ->execute([$admin['admin_email'], $code, $expires]);

    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $admin['smtp_host'];
        $mail->SMTPAuth = true;
        $mail->Username = $admin['smtp_user'];
        $mail->Password = $admin['smtp_pass'];
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = $admin['smtp_port'];
        $mail->CharSet = 'UTF-8';
        $mail->setFrom($admin['smtp_user'], '私密加密盘');
        $mail->addAddress($admin['admin_email']);
        $mail->Subject = '私密加密盘 - 登录验证码';
        $mail->Body = "您的登录验证码是: {$code}\n有效期10分钟。";
        $mail->send();

        $_SESSION['last_login_send'] = time();
        echo json_encode(['success' => true, 'message' => '验证码已发送']);
    } catch (\Exception $e) {
        $errorMsg = (isset($mail) && $mail instanceof PHPMailer\PHPMailer\PHPMailer) ? $mail->ErrorInfo : $e->getMessage();
        echo json_encode(['success' => false, 'message' => '发送失败: ' . $errorMsg]);
    }
    exit;
}

if ($isLoggedIn && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_action'])) {
    header('Content-Type: application/json');
    $adminAction = $_POST['admin_action'];

    if ($adminAction === 'toggle_upload_password') {
        $enabled = intval($_POST['enabled'] ?? 0);
        $pdo->prepare("UPDATE admin SET upload_password_enabled = ? WHERE id = 1")
            ->execute([$enabled]);
        echo json_encode(['success' => true, 'message' => $enabled ? '已开启上传口令' : '已关闭上传口令']);
        exit;
    }

    if ($adminAction === 'set_upload_password') {
        $password = trim($_POST['password'] ?? '');
        if (empty($password)) {
            echo json_encode(['success' => false, 'message' => '口令不能为空']);
            exit;
        }
        $pdo->prepare("UPDATE admin SET upload_password_hash = ? WHERE id = 1")
            ->execute([sha256($password)]);
        echo json_encode(['success' => true, 'message' => '上传口令已设置']);
        exit;
    }

    if ($adminAction === 'change_admin_password' && $mode === 'loose') {
        $oldPass = $_POST['old_password'] ?? '';
        $newPass = trim($_POST['new_password'] ?? '');

        if (sha256($oldPass) !== $admin['admin_password_hash']) {
            echo json_encode(['success' => false, 'message' => '原口令错误']);
            exit;
        }
        if (empty($newPass)) {
            echo json_encode(['success' => false, 'message' => '新口令不能为空']);
            exit;
        }

        $pdo->prepare("UPDATE admin SET admin_password_hash = ? WHERE id = 1")
            ->execute([sha256($newPass)]);
        echo json_encode(['success' => true, 'message' => 'admin口令已更改']);
        exit;
    }

    if ($adminAction === 'change_admin_username' && $mode === 'loose') {
        $newUsername = trim($_POST['new_username'] ?? '');
        if (empty($newUsername)) {
            echo json_encode(['success' => false, 'message' => '管理账号不能为空']);
            exit;
        }
        $pdo->prepare("UPDATE admin SET admin_username = ? WHERE id = 1")
            ->execute([$newUsername]);
        echo json_encode(['success' => true, 'message' => '管理账号已更改']);
        exit;
    }

    if ($adminAction === 'list_files') {
        $stmt = $pdo->query("SELECT hash_name, is_secret, upload_time FROM files ORDER BY upload_time DESC");
        $files = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $path = dirname(__DIR__) . '/uploads/' . $row['hash_name'];
            $size = file_exists($path) ? filesize($path) : 0;
            $files[] = [
                'hash_name' => $row['hash_name'],
                'is_secret' => (bool)$row['is_secret'],
                'upload_time' => $row['upload_time'],
                'size' => $size,
                'size_formatted' => formatSize($size)
            ];
        }
        echo json_encode(['success' => true, 'files' => $files]);
        exit;
    }

    if ($adminAction === 'delete_file') {
        $hashName = preg_replace('/[^a-f0-9]/', '', $_POST['hash_name'] ?? '');
        if (empty($hashName) || strlen($hashName) !== 32) {
            echo json_encode(['success' => false, 'message' => '文件名无效']);
            exit;
        }
        $path = dirname(__DIR__) . '/uploads/' . $hashName;
        if (file_exists($path)) {
            @unlink($path);
        }
        $pdo->prepare("DELETE FROM files WHERE hash_name = ?")->execute([$hashName]);
        echo json_encode(['success' => true, 'message' => '文件已删除']);
        exit;
    }

    if ($adminAction === 'clear_temp') {
        $tempDir = dirname(__DIR__) . '/temp/';
        $count = 0;
        if (is_dir($tempDir)) {
            foreach (glob($tempDir . '*') as $file) {
                if (is_file($file)) {
                    @unlink($file);
                    $count++;
                }
            }
        }
        echo json_encode(['success' => true, 'message' => '已清空 ' . $count . ' 个临时文件']);
        exit;
    }

    echo json_encode(['success' => false, 'message' => '未知操作']);
    exit;
}

if (isset($_GET['logout'])) {
    // 清除数据库 token
    $pdo->prepare("UPDATE admin SET session_token = NULL, login_ip = NULL WHERE id = 1")->execute();
    session_destroy();
    header('Location: ./');
    exit;
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理后台 - 私密加密盘</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d1b2a 100%);
            min-height: 100vh;
            color: #e0e0e0;
        }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 30px 0; }
        .header h1 {
            font-size: 2em;
            background: linear-gradient(90deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .card {
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
        }
        .card h2 { color: #e94560; margin-bottom: 15px; font-size: 1.2em; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 6px; color: #999; font-size: 0.9em; }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 8px;
            background: rgba(0,0,0,0.4);
            color: #fff;
            font-size: 1em;
        }
        .btn {
            display: inline-block;
            padding: 10px 25px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #e94560, #c73e54);
            color: #fff;
            font-size: 0.95em;
            cursor: pointer;
            margin-right: 10px;
        }
        .btn-secondary {
            background: linear-gradient(135deg, #533483, #7b2cbf);
        }
        .switch {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 26px;
        }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background-color: #333;
            transition: .4s;
            border-radius: 26px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        input:checked + .slider { background-color: #e94560; }
        input:checked + .slider:before { transform: translateX(24px); }
        .status { color: #888; font-size: 0.9em; margin-left: 10px; }
        .logout-btn {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 8px 16px;
            background: rgba(231, 76, 60, 0.3);
            border: 1px solid rgba(231, 76, 60, 0.5);
            color: #ff9999;
            border-radius: 8px;
            text-decoration: none;
            font-size: 0.85em;
        }
        .mode-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75em;
            margin-left: 10px;
        }
        .mode-loose { background: rgba(243, 156, 18, 0.2); color: #f39c12; border: 1px solid rgba(243, 156, 18, 0.3); }
        .mode-strict { background: rgba(231, 76, 60, 0.2); color: #e74c3c; border: 1px solid rgba(231, 76, 60, 0.3); }
        .back-link {
            position: fixed;
            top: 20px;
            left: 20px;
            padding: 8px 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            color: #888;
            border-radius: 8px;
            text-decoration: none;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>管理后台 <span class="mode-badge mode-<?php echo $mode; ?>"><?php echo $mode === 'loose' ? '宽容模式' : '严格模式'; ?></span></h1>
        </div>

        <?php if ($isLoggedIn): ?>
        <a href="../index.php" class="back-link">返回首页</a>
        <a href="?logout=1" class="logout-btn">退出登录</a>

        <div class="card">
            <h2>文件管理 <button class="btn btn-secondary" style="float:right; padding:6px 14px; font-size:0.8em;" onclick="loadFileList()">刷新</button></h2>
            <div style="margin-bottom:10px;">
                <button class="btn" style="background:linear-gradient(135deg,#e74c3c,#c0392b);" onclick="clearTemp()">🗑 一键清空临时文件</button>
            </div>
            <div id="fileListBox" style="max-height:400px; overflow-y:auto;">
                <p style="color:#666; text-align:center; padding:20px;">点击刷新加载文件列表</p>
            </div>
        </div>

        <div class="card">
            <h2>上传口令控制</h2>
            <div style="display:flex; align-items:center; margin-bottom:15px;">
                <label class="switch">
                    <input type="checkbox" id="uploadPassToggle" <?php echo $admin['upload_password_enabled'] ? 'checked' : ''; ?> onchange="toggleUploadPassword(this)">
                    <span class="slider"></span>
                </label>
                <span class="status" id="uploadPassStatus"><?php echo $admin['upload_password_enabled'] ? '已开启' : '已关闭'; ?></span>
            </div>
            <div class="form-group">
                <label>设置/更改上传口令</label>
                <input type="password" id="uploadPassword" placeholder="输入上传口令">
            </div>
            <button class="btn" onclick="setUploadPassword()">保存上传口令</button>
        </div>

        <?php if ($mode === 'loose'): ?>
        <div class="card">
            <h2>更改管理账号</h2>
            <div class="form-group">
                <label>当前账号：<?php echo htmlspecialchars($admin['admin_username'] ?? 'admin'); ?></label>
                <input type="text" id="newAdminUsername" placeholder="输入新管理账号">
            </div>
            <button class="btn" onclick="changeAdminUsername()">更改管理账号</button>
        </div>

        <div class="card">
            <h2>更改admin口令</h2>
            <div class="form-group">
                <label>原口令</label>
                <input type="password" id="oldAdminPass" placeholder="输入原口令">
            </div>
            <div class="form-group">
                <label>新口令</label>
                <input type="password" id="newAdminPass" placeholder="输入新口令">
            </div>
            <button class="btn" onclick="changeAdminPassword()">更改口令</button>
        </div>
        <?php else: ?>
        <div class="card">
            <h2>严格模式信息</h2>
            <p style="color:#888; font-size:0.9em;">
                admin邮箱: <?php echo htmlspecialchars($admin['admin_email'] ?? '未设置'); ?><br>
                登录方式: 验证码邮件登录（不可更改口令）
            </p>
        </div>
        <?php endif; ?>

        <?php else: ?>
        <a href="../index.php" class="back-link">返回首页</a>
        <div class="card">
            <h2>管理员登录</h2>
            <?php if ($mode === 'loose'): ?>
            <form id="loginForm">
                <div class="form-group">
                    <label>管理账号</label>
                    <input type="text" name="username" placeholder="输入管理账号" required>
                </div>
                <div class="form-group">
                    <label>admin口令</label>
                    <input type="password" name="password" placeholder="输入admin口令" required>
                </div>
                <button type="submit" class="btn">登录</button>
            </form>
            <?php else: ?>
            <form id="strictLoginForm">
                <input type="hidden" name="email" value="<?php echo htmlspecialchars($admin['admin_email'] ?? ''); ?>">
                <div class="form-group">
                    <label>验证码</label>
                    <div style="display:flex; gap:10px;">
                        <input type="text" name="code" placeholder="6位验证码" style="flex:1;">
                        <button type="button" class="btn btn-secondary" onclick="sendLoginCode()">获取验证码</button>
                    </div>
                </div>
                <button type="submit" class="btn">登录</button>
            </form>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <script>
        <?php if (!$isLoggedIn): ?>
        <?php if ($mode === 'loose'): ?>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('login', '1');

            const res = await fetch('', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (data.success) {
                location.reload();
            } else {
                alert(data.message);
            }
        });
        <?php else: ?>
        let loginCooldownTimer = null;
        async function sendLoginCode() {
            const btn = event.target;
            const formData = new FormData();
            formData.append('send_login_code', '1');

            btn.disabled = true;
            const res = await fetch('', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            alert(data.message);

            if (data.success) {
                let sec = 60;
                btn.textContent = sec + 's';
                loginCooldownTimer = setInterval(() => {
                    sec--;
                    if (sec <= 0) {
                        clearInterval(loginCooldownTimer);
                        btn.disabled = false;
                        btn.textContent = '获取验证码';
                    } else {
                        btn.textContent = sec + 's';
                    }
                }, 1000);
            } else {
                btn.disabled = false;
            }
        }

        document.getElementById('strictLoginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('login', '1');

            const res = await fetch('', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (data.success) {
                location.reload();
            } else {
                alert(data.message);
            }
        });
        <?php endif; ?>
        <?php else: ?>
        async function toggleUploadPassword(el) {
            const formData = new FormData();
            formData.append('admin_action', 'toggle_upload_password');
            formData.append('enabled', el.checked ? 1 : 0);

            const res = await fetch('', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            document.getElementById('uploadPassStatus').textContent = el.checked ? '已开启' : '已关闭';
            alert(data.message);
        }

        async function setUploadPassword() {
            const pass = document.getElementById('uploadPassword').value;
            if (!pass) { alert('请输入口令'); return; }

            const formData = new FormData();
            formData.append('admin_action', 'set_upload_password');
            formData.append('password', pass);

            const res = await fetch('', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            alert(data.message);
            if (data.success) document.getElementById('uploadPassword').value = '';
        }

        <?php if ($mode === 'loose'): ?>
        async function changeAdminUsername() {
            const username = document.getElementById('newAdminUsername').value;
            if (!username) { alert('请输入新管理账号'); return; }

            const formData = new FormData();
            formData.append('admin_action', 'change_admin_username');
            formData.append('new_username', username);

            const res = await fetch('', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            alert(data.message);
            if (data.success) location.reload();
        }

        async function changeAdminPassword() {
            const oldPass = document.getElementById('oldAdminPass').value;
            const newPass = document.getElementById('newAdminPass').value;
            if (!oldPass || !newPass) { alert('请填写完整'); return; }

            const formData = new FormData();
            formData.append('admin_action', 'change_admin_password');
            formData.append('old_password', oldPass);
            formData.append('new_password', newPass);

            const res = await fetch('', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            alert(data.message);
            if (data.success) {
                document.getElementById('oldAdminPass').value = '';
                document.getElementById('newAdminPass').value = '';
            }
        }
        <?php endif; ?>
        <?php endif; ?>

        async function loadFileList() {
            const box = document.getElementById('fileListBox');
            box.innerHTML = '<p style="color:#666; text-align:center; padding:20px;">加载中...</p>';
            try {
                const formData = new FormData();
                formData.append('admin_action', 'list_files');
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                if (!data.success || data.files.length === 0) {
                    box.innerHTML = '<p style="color:#666; text-align:center; padding:20px;">暂无文件</p>';
                    return;
                }
                box.innerHTML = data.files.map(f => `
                    <div style="display:flex; align-items:center; justify-content:space-between; padding:12px; margin-bottom:8px; background:rgba(0,0,0,0.25); border-radius:8px; border:1px solid rgba(255,255,255,0.05);">
                        <div style="flex:1; min-width:0;">
                            <div style="font-family:monospace; color:#e94560; font-size:0.85em; word-break:break-all;">${f.hash_name}</div>
                            <div style="color:#666; font-size:0.8em; margin-top:4px;">
                                ${f.is_secret ? '<span style="color:#9b59b6;">[保密]</span> ' : ''}
                                ${f.size_formatted} | ${f.upload_time}
                            </div>
                        </div>
                        <button onclick="deleteFile('${f.hash_name}')" style="padding:6px 14px; border:none; border-radius:6px; background:#e74c3c; color:#fff; font-size:0.85em; cursor:pointer; margin-left:10px;">删除</button>
                    </div>
                `).join('');
            } catch (err) {
                box.innerHTML = '<p style="color:#e74c3c; text-align:center; padding:20px;">加载失败</p>';
            }
        }

        async function deleteFile(hashName) {
            if (!confirm('确定删除文件 ' + hashName + ' 吗？此操作不可恢复！')) return;
            try {
                const formData = new FormData();
                formData.append('admin_action', 'delete_file');
                formData.append('hash_name', hashName);
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                alert(data.message);
                if (data.success) loadFileList();
            } catch (err) {
                alert('删除失败');
            }
        }

        async function clearTemp() {
            if (!confirm('确定清空所有临时文件吗？')) return;
            try {
                const formData = new FormData();
                formData.append('admin_action', 'clear_temp');
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                alert(data.message);
            } catch (err) {
                alert('清空失败');
            }
        }
    </script>
</body>
</html>