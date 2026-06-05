<?php
/**
 * 安装向导 - 私密加密盘
 */

ob_start();
register_shutdown_function(function() {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        ob_end_clean();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => false, 'message' => '致命错误: ' . $err['message']]);
    }
});

$lockFile = __DIR__ . '/../install.lock';
if (file_exists($lockFile)) {
    header('Content-Type: text/html; charset=utf-8');
    $lockContent = htmlspecialchars(file_get_contents($lockFile));
    echo '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>已安装</title><style>
    *{margin:0;padding:0;box-sizing:border-box;}
    body{background:#0f0f23;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:20px;}
    .box{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:16px;padding:30px 20px;width:100%;max-width:420px;text-align:center;}
    h1{background:linear-gradient(90deg,#e94560,#ff6b6b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:15px;font-size:1.5em;}
    p{color:#888;font-size:0.9em;margin:8px 0;}
    .lock-info{background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.05);border-radius:8px;padding:12px;margin:15px 0;font-family:monospace;color:#aaa;font-size:0.85em;word-break:break-all;}
    .btn{display:inline-block;padding:10px 24px;border:none;border-radius:8px;background:linear-gradient(135deg,#e94560,#c73e54);color:#fff;font-size:0.95em;cursor:pointer;text-decoration:none;margin-top:10px;}
    .btn:hover{opacity:0.9;}
    .footer{color:#555;font-size:0.75em;margin-top:20px;}
    @media(max-width:480px){.box{padding:25px 15px;}h1{font-size:1.3em;}}
    </style></head><body><div class="box"><h1>私密加密盘 已安装</h1>
    <p>安装时间</p><div class="lock-info">' . $lockContent . '</div>
    <a href="../index.php" class="btn">进入主页</a>
    <p class="footer">如需重装，请删除 install.lock 文件后刷新页面</p></div></body></html>';
    exit;
}

error_reporting(0);
ini_set('display_errors', 0);
session_start();

function jsonError($msg) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['success' => false, 'message' => $msg]);
    exit;
}

function checkSendCooldown($email) {
    $last = $_SESSION['last_send_code'][$email] ?? 0;
    $wait = 60 - (time() - $last);
    if ($wait > 0) {
        jsonError('请等待 ' . $wait . ' 秒后再发送');
    }
}

// GET 请求显示安装页面，POST 请求处理 AJAX
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // 继续执行到 HTML 输出
    goto show_html;
}

$step = $_POST['step'] ?? '';

// ========== 步骤1：数据库配置 ==========
if ($step === '1') {
    $dbHost = trim($_POST['db_host'] ?? '');
    $dbPort = trim($_POST['db_port'] ?? '3306');
    $dbName = trim($_POST['db_name'] ?? '');
    $dbUser = trim($_POST['db_user'] ?? '');
    $dbPass = $_POST['db_pass'] ?? '';

    if (empty($dbHost) || empty($dbName) || empty($dbUser)) {
        jsonError('数据库信息不完整');
    }

    try {
        $dsn = "mysql:host={$dbHost};port={$dbPort};charset=utf8mb4";
        $pdo = new PDO($dsn, $dbUser, $dbPass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("USE `{$dbName}`");

        $pdo->exec("DROP TABLE IF EXISTS files");
        $pdo->exec("DROP TABLE IF EXISTS admin");
        $pdo->exec("DROP TABLE IF EXISTS email_codes");

        $pdo->exec("CREATE TABLE files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hash_name VARCHAR(32) NOT NULL UNIQUE,
            is_secret TINYINT(1) DEFAULT 0,
            secret_password_hash VARCHAR(64) DEFAULT NULL,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_secret (is_secret)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE admin (
            id INT PRIMARY KEY DEFAULT 1,
            admin_username VARCHAR(64) NOT NULL DEFAULT 'admin',
            admin_password_hash VARCHAR(64) NOT NULL,
            upload_password_hash VARCHAR(64) DEFAULT NULL,
            upload_password_enabled TINYINT(1) DEFAULT 0,
            mode VARCHAR(10) DEFAULT 'loose',
            admin_email VARCHAR(255) DEFAULT NULL,
            smtp_host VARCHAR(255) DEFAULT NULL,
            smtp_port INT DEFAULT NULL,
            smtp_user VARCHAR(255) DEFAULT NULL,
            smtp_pass VARCHAR(255) DEFAULT NULL,
            admin_dir VARCHAR(64) DEFAULT 'admin',
            session_token VARCHAR(64) DEFAULT NULL,
            login_ip VARCHAR(45) DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE email_codes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            code VARCHAR(10) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            used TINYINT(1) DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $config = [
            'db_host' => $dbHost,
            'db_port' => $dbPort,
            'db_name' => $dbName,
            'db_user' => $dbUser,
            'db_pass' => $dbPass,
        ];
        file_put_contents(__DIR__ . '/../config.php', "<?php\n\$CONFIG = " . var_export($config, true) . ";\n");

        echo json_encode(['success' => true, 'message' => '数据库连接成功，表已创建']);
        exit;
    } catch (PDOException $e) {
        jsonError('数据库连接失败: ' . $e->getMessage());
    }
}

// ========== 步骤1b：跳过 ==========
if ($step === 'skip') {
    if (!file_exists(__DIR__ . '/../config.php')) {
        jsonError('未找到已有配置，无法跳过');
    }
    require __DIR__ . '/../config.php';

    try {
        $dsn = "mysql:host={$CONFIG['db_host']};port={$CONFIG['db_port']};dbname={$CONFIG['db_name']};charset=utf8mb4";
        $pdo = new PDO($dsn, $CONFIG['db_user'], $CONFIG['db_pass']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec("USE `{$CONFIG['db_name']}`");

        $pdo->exec("DROP TABLE IF EXISTS files");
        $pdo->exec("DROP TABLE IF EXISTS admin");
        $pdo->exec("DROP TABLE IF EXISTS email_codes");

        $pdo->exec("CREATE TABLE files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hash_name VARCHAR(32) NOT NULL UNIQUE,
            is_secret TINYINT(1) DEFAULT 0,
            secret_password_hash VARCHAR(64) DEFAULT NULL,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_secret (is_secret)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE admin (
            id INT PRIMARY KEY DEFAULT 1,
            admin_username VARCHAR(64) NOT NULL DEFAULT 'admin',
            admin_password_hash VARCHAR(64) NOT NULL,
            upload_password_hash VARCHAR(64) DEFAULT NULL,
            upload_password_enabled TINYINT(1) DEFAULT 0,
            mode VARCHAR(10) DEFAULT 'loose',
            admin_email VARCHAR(255) DEFAULT NULL,
            smtp_host VARCHAR(255) DEFAULT NULL,
            smtp_port INT DEFAULT NULL,
            smtp_user VARCHAR(255) DEFAULT NULL,
            smtp_pass VARCHAR(255) DEFAULT NULL,
            admin_dir VARCHAR(64) DEFAULT 'admin',
            session_token VARCHAR(64) DEFAULT NULL,
            login_ip VARCHAR(45) DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE email_codes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            code VARCHAR(10) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            used TINYINT(1) DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        echo json_encode(['success' => true, 'message' => '使用已有配置，表已重建']);
        exit;
    } catch (PDOException $e) {
        jsonError('已有配置连接失败: ' . $e->getMessage());
    }
}

// ========== 步骤2：完成安装 ==========
if ($step === '2') {
    $mode = $_POST['mode'] ?? 'loose';
    $adminDir = preg_replace('/[^a-zA-Z0-9_-]/', '', trim($_POST['admin_dir'] ?? 'admin'));
    if (empty($adminDir)) $adminDir = 'admin';

    if (!file_exists(__DIR__ . '/../config.php')) {
        jsonError('配置未就绪，请先完成第一步');
    }
    require __DIR__ . '/../config.php';

    try {
        $dsn = "mysql:host={$CONFIG['db_host']};port={$CONFIG['db_port']};dbname={$CONFIG['db_name']};charset=utf8mb4";
        $pdo = new PDO($dsn, $CONFIG['db_user'], $CONFIG['db_pass']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
        jsonError('数据库连接失败: ' . $e->getMessage());
    }

    // 重命名同级 admin 目录
    $parentDir = dirname(__DIR__);
    $adminDirPath = $parentDir . '/admin';
    $targetDirPath = $parentDir . '/' . $adminDir;

    if ($adminDir === 'admin') {
        // 目标名就是 admin，不需要重命名
    } elseif (file_exists($targetDirPath) && is_dir($targetDirPath)) {
        // 目标目录已存在且不是 admin
        jsonError('目标目录名已存在，请换一个名称');
    } elseif (!file_exists($adminDirPath) || !is_dir($adminDirPath)) {
        // admin 目录不存在（已被重命名过或不存在）
        jsonError('admin 目录不存在，无法重命名');
    } elseif (!rename($adminDirPath, $targetDirPath)) {
        jsonError('目录重命名失败，请检查权限');
    }

    if ($mode === 'loose') {
        $adminUser = trim($_POST['admin_username'] ?? '');
        $adminPass = trim($_POST['admin_password'] ?? '');
        if (empty($adminUser)) {
            jsonError('管理账号不能为空');
        }
        if (empty($adminPass)) {
            jsonError('admin口令不能为空');
        }

        $stmt = $pdo->prepare("INSERT INTO admin (id, admin_username, admin_password_hash, mode, admin_dir) VALUES (1, ?, ?, 'loose', ?)");
        $stmt->execute([$adminUser, hash('sha256', $adminPass), $adminDir]);

        file_put_contents(__DIR__ . '/../install.lock', date('Y-m-d H:i:s'));

        echo json_encode(['success' => true, 'message' => '宽容模式安装成功', 'admin_dir' => $adminDir]);
        exit;
    }

    if ($mode === 'strict') {
        $adminDir = preg_replace('/[^a-zA-Z0-9_-]/', '', trim($_POST['admin_dir'] ?? 'admin'));
        if (empty($adminDir)) $adminDir = 'admin';

        $smtpHost = trim($_POST['smtp_host'] ?? '');
        $smtpPort = intval($_POST['smtp_port'] ?? 587);
        $smtpUser = trim($_POST['smtp_user'] ?? '');
        $smtpPass = $_POST['smtp_pass'] ?? '';
        $adminEmail = trim($_POST['admin_email'] ?? '');
        $verifyCode = trim($_POST['verify_code'] ?? '');

        if (empty($smtpHost) || empty($smtpUser) || empty($smtpPass) || empty($adminEmail)) {
            jsonError('SMTP信息不完整');
        }

        $stmt = $pdo->prepare("SELECT * FROM email_codes WHERE email = ? AND code = ? AND used = 0 AND expires_at > NOW() ORDER BY id DESC LIMIT 1");
        $stmt->execute([$adminEmail, $verifyCode]);
        $codeRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$codeRecord) {
            jsonError('验证码无效或已过期');
        }

        $pdo->prepare("UPDATE email_codes SET used = 1 WHERE id = ?")->execute([$codeRecord['id']]);

        $stmt = $pdo->prepare("INSERT INTO admin (id, admin_username, admin_password_hash, mode, admin_email, smtp_host, smtp_port, smtp_user, smtp_pass, admin_dir) VALUES (1, ?, ?, 'strict', ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$adminEmail, hash('sha256', $adminEmail), $adminEmail, $smtpHost, $smtpPort, $smtpUser, $smtpPass, $adminDir]);

        file_put_contents(__DIR__ . '/../install.lock', date('Y-m-d H:i:s'));

        echo json_encode(['success' => true, 'message' => '严格模式安装成功', 'admin_dir' => $adminDir]);
        exit;
    }
}

// ========== 发送验证码 ==========
if ($step === 'send_code') {
    $smtpHost = trim($_POST['smtp_host'] ?? '');
    $smtpPort = intval($_POST['smtp_port'] ?? 587);
    $smtpUser = trim($_POST['smtp_user'] ?? '');
    $smtpPass = $_POST['smtp_pass'] ?? '';
    $adminEmail = trim($_POST['admin_email'] ?? '');

    if (empty($smtpHost) || empty($smtpUser) || empty($smtpPass) || empty($adminEmail)) {
        jsonError('SMTP信息不完整');
    }

    checkSendCooldown($adminEmail);

    $code = str_pad(strval(random_int(0, 999999)), 6, '0', STR_PAD_LEFT);

    if (!file_exists(__DIR__ . '/../config.php')) {
        jsonError('配置未就绪，请先完成第一步');
    }
    require __DIR__ . '/../config.php';

    try {
        $dsn = "mysql:host={$CONFIG['db_host']};port={$CONFIG['db_port']};dbname={$CONFIG['db_name']};charset=utf8mb4";
        $pdo = new PDO($dsn, $CONFIG['db_user'], $CONFIG['db_pass']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
        jsonError('数据库连接失败: ' . $e->getMessage());
    }

    $expires = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    try {
        $pdo->prepare("INSERT INTO email_codes (email, code, expires_at) VALUES (?, ?, ?)")
            ->execute([$adminEmail, $code, $expires]);
    } catch (PDOException $e) {
        jsonError('验证码保存失败: ' . $e->getMessage());
    }

    $phpmailerPath = __DIR__ . '/../PHPMailer/src/';
    if (!file_exists($phpmailerPath . 'PHPMailer.php')) {
        jsonError('PHPMailer未找到，请将PHPMailer/src/文件夹放置到正确位置');
    }

    require $phpmailerPath . 'Exception.php';
    require $phpmailerPath . 'PHPMailer.php';
    require $phpmailerPath . 'SMTP.php';

    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $smtpHost;
        $mail->SMTPAuth = true;
        $mail->Username = $smtpUser;
        $mail->Password = $smtpPass;

        if ($smtpPort == 465) {
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        } elseif ($smtpPort == 587) {
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        } else {
            $mail->SMTPSecure = false;
            $mail->SMTPAutoTLS = false;
        }

        $mail->Port = $smtpPort;
        $mail->CharSet = 'UTF-8';
        $mail->setFrom($smtpUser, '私密加密盘');
        $mail->addAddress($adminEmail);
        $mail->Subject = '私密加密盘 - 安装验证码';
        $mail->Body = "您的验证码是: {$code}\n有效期10分钟。\n如非本人操作请忽略。";
        $mail->send();

        $_SESSION['last_send_code'][$adminEmail] = time();

        echo json_encode(['success' => true, 'message' => '验证码已发送']);
    } catch (\Exception $e) {
        $errorMsg = (isset($mail) && $mail instanceof PHPMailer\PHPMailer\PHPMailer) ? $mail->ErrorInfo : $e->getMessage();
        jsonError('邮件发送失败: ' . $errorMsg);
    }
    exit;
}

jsonError('未知步骤');

show_html:
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安装 - 私密加密盘</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d1b2a 100%);
            min-height: 100vh;
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .install-box {
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
        }
        .install-box h1 {
            text-align: center;
            background: linear-gradient(90deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 30px;
        }
        .step { display: none; }
        .step.active { display: block; }
        .form-group { margin-bottom: 15px; }
        .form-group label {
            display: block;
            margin-bottom: 6px;
            color: #999;
            font-size: 0.9em;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 8px;
            background: rgba(0,0,0,0.4);
            color: #fff;
            font-size: 1em;
        }
        .form-group input:focus { outline: none; border-color: #e94560; }
        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #e94560, #c73e54);
            color: #fff;
            font-size: 1em;
            cursor: pointer;
            margin-top: 10px;
        }
        .btn-secondary {
            background: linear-gradient(135deg, #533483, #7b2cbf);
        }
        .btn-skip {
            background: transparent;
            border: 1px solid rgba(255,255,255,0.15);
            color: #888;
        }
        .btn-skip:hover { color: #e94560; border-color: rgba(233,69,96,0.3); }
        .mode-select {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        .mode-btn {
            flex: 1;
            padding: 15px;
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            background: rgba(0,0,0,0.3);
            color: #ccc;
            cursor: pointer;
            text-align: center;
            transition: all 0.3s;
        }
        .mode-btn:hover { border-color: #e94560; }
        .mode-btn.active {
            border-color: #e94560;
            background: rgba(233, 69, 96, 0.15);
            color: #e94560;
        }
        .mode-desc {
            font-size: 0.8em;
            color: #888;
            margin-top: 5px;
        }
        .info-box {
            background: rgba(52, 152, 219, 0.1);
            border-left: 3px solid #3498db;
            padding: 10px 15px;
            border-radius: 0 8px 8px 0;
            margin: 15px 0;
            font-size: 0.85em;
            color: #85c1e9;
        }
        .warning-box {
            background: rgba(231, 76, 60, 0.1);
            border-left: 3px solid #e74c3c;
            padding: 10px 15px;
            border-radius: 0 8px 8px 0;
            margin: 15px 0;
            font-size: 0.85em;
            color: #ff9999;
        }
        .code-input-group {
            display: flex;
            gap: 10px;
        }
        .code-input-group input { flex: 1; }
        .code-input-group button {
            padding: 12px 20px;
            white-space: nowrap;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #533483, #7b2cbf);
            color: #fff;
            cursor: pointer;
        }
        .code-input-group button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
    </style>
</head>
<body>
    <div class="install-box">
        <h1>安装私密加密盘</h1>

        <div class="step active" id="step1">
            <div class="info-box">第一步：配置数据库连接</div>
            <form id="dbForm">
                <div class="form-group">
                    <label>数据库地址</label>
                    <input type="text" name="db_host" placeholder="localhost" value="localhost" required>
                </div>
                <div class="form-group">
                    <label>端口</label>
                    <input type="text" name="db_port" placeholder="3306" value="3306" required>
                </div>
                <div class="form-group">
                    <label>数据库名</label>
                    <input type="text" name="db_name" placeholder="encrypt_pan" required>
                </div>
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" name="db_user" placeholder="root" required>
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <input type="password" name="db_pass" placeholder="数据库密码">
                </div>
                <button type="submit" class="btn">下一步</button>
                <button type="button" class="btn btn-skip" id="skipBtn" onclick="skipStep1()">使用已有配置（跳过）</button>
            </form>
        </div>

        <div class="step" id="step2">
            <div class="info-box">第二步：选择安装模式并设置管理目录</div>
            <div class="form-group">
                <label>管理后台目录名（默认admin，支持重命名）</label>
                <input type="text" id="adminDirInput" value="admin" placeholder="admin">
            </div>
            <div class="mode-select">
                <div class="mode-btn active" onclick="selectMode('loose')">
                    <div>宽容模式</div>
                    <div class="mode-desc">设定管理账号和口令即可使用</div>
                </div>
                <div class="mode-btn" onclick="selectMode('strict')">
                    <div>严格模式</div>
                    <div class="mode-desc">需配置SMTP邮箱，通过验证码登录</div>
                </div>
            </div>

            <div id="looseForm">
                <form id="looseInstallForm">
                    <div class="form-group">
                        <label>管理账号</label>
                        <input type="text" name="admin_username" placeholder="设置管理账号" value="admin" required>
                    </div>
                    <div class="form-group">
                        <label>admin口令</label>
                        <input type="password" name="admin_password" placeholder="设置admin口令" required>
                    </div>
                    <button type="submit" class="btn">完成安装</button>
                </form>
            </div>

            <div id="strictForm" style="display:none;">
                <form id="strictInstallForm">
                    <div class="form-group">
                        <label>SMTP服务器地址</label>
                        <input type="text" name="smtp_host" placeholder="smtp.qq.com">
                    </div>
                    <div class="form-group">
                        <label>SMTP端口</label>
                        <input type="text" name="smtp_port" placeholder="587" value="587">
                    </div>
                    <div class="form-group">
                        <label>SMTP邮箱账号</label>
                        <input type="text" name="smtp_user" placeholder="your@email.com">
                    </div>
                    <div class="form-group">
                        <label>SMTP授权码</label>
                        <input type="password" name="smtp_pass" placeholder="SMTP授权码">
                    </div>
                    <div class="form-group">
                        <label>admin邮箱（用于接收验证码登录）</label>
                        <input type="email" name="admin_email" placeholder="admin@email.com">
                    </div>
                    <div class="form-group">
                        <label>验证码</label>
                        <div class="code-input-group">
                            <input type="text" name="verify_code" placeholder="6位验证码">
                            <button type="button" id="sendCodeBtn" onclick="sendVerifyCode()">获取验证码</button>
                        </div>
                    </div>
                    <button type="submit" class="btn">完成安装</button>
                </form>
            </div>
        </div>

        <div class="warning-box" id="resultMsg" style="display:none;"></div>
    </div>

    <script>
        let currentMode = 'loose';
        let cooldownTimer = null;

        function selectMode(mode) {
            currentMode = mode;
            document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
            event.target.closest('.mode-btn').classList.add('active');
            document.getElementById('looseForm').style.display = mode === 'loose' ? 'block' : 'none';
            document.getElementById('strictForm').style.display = mode === 'strict' ? 'block' : 'none';
        }

        function showResult(msg, isError) {
            const el = document.getElementById('resultMsg');
            el.textContent = msg;
            el.style.display = 'block';
            el.style.borderColor = isError ? '#e74c3c' : '#27ae60';
            el.style.color = isError ? '#ff9999' : '#90ee90';
            el.style.background = isError ? 'rgba(231,76,60,0.1)' : 'rgba(39,174,96,0.1)';
        }

        function goStep2(msg) {
            document.getElementById('step1').classList.remove('active');
            document.getElementById('step2').classList.add('active');
            showResult(msg, false);
        }

        document.getElementById('dbForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('step', '1');

            try {
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                if (data.success) goStep2(data.message);
                else showResult(data.message, true);
            } catch (err) {
                showResult('请求失败: ' + err.message, true);
            }
        });

        async function skipStep1() {
            const formData = new FormData();
            formData.append('step', 'skip');
            try {
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                if (data.success) goStep2(data.message);
                else showResult(data.message, true);
            } catch (err) {
                showResult('请求失败: ' + err.message, true);
            }
        }

        async function sendVerifyCode() {
            const form = document.getElementById('strictInstallForm');
            const btn = document.getElementById('sendCodeBtn');

            const formData = new FormData();
            formData.append('step', 'send_code');
            formData.append('smtp_host', form.smtp_host.value);
            formData.append('smtp_port', form.smtp_port.value);
            formData.append('smtp_user', form.smtp_user.value);
            formData.append('smtp_pass', form.smtp_pass.value);
            formData.append('admin_email', form.admin_email.value);

            btn.disabled = true;
            try {
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                showResult(data.message, !data.success);

                if (data.success) {
                    let sec = 60;
                    btn.textContent = sec + 's';
                    cooldownTimer = setInterval(() => {
                        sec--;
                        if (sec <= 0) {
                            clearInterval(cooldownTimer);
                            btn.disabled = false;
                            btn.textContent = '获取验证码';
                        } else {
                            btn.textContent = sec + 's';
                        }
                    }, 1000);
                } else {
                    btn.disabled = false;
                }
            } catch (err) {
                showResult('发送失败: ' + err.message, true);
                btn.disabled = false;
            }
        }

        document.getElementById('looseInstallForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData();
            formData.append('step', '2');
            formData.append('mode', 'loose');
            formData.append('admin_dir', document.getElementById('adminDirInput').value);
            formData.append('admin_username', this.admin_username.value);
            formData.append('admin_password', this.admin_password.value);

            try {
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                if (data.success) {
                    showResult('安装成功！3秒后跳转...', false);
                    setTimeout(() => window.location.href = '../' + (data.admin_dir || 'admin') + '/', 3000);
                } else {
                    showResult(data.message, true);
                }
            } catch (err) {
                showResult('安装失败: ' + err.message, true);
            }
        });

        document.getElementById('strictInstallForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData();
            formData.append('step', '2');
            formData.append('mode', 'strict');
            formData.append('admin_dir', document.getElementById('adminDirInput').value);
            formData.append('smtp_host', this.smtp_host.value);
            formData.append('smtp_port', this.smtp_port.value);
            formData.append('smtp_user', this.smtp_user.value);
            formData.append('smtp_pass', this.smtp_pass.value);
            formData.append('admin_email', this.admin_email.value);
            formData.append('verify_code', this.verify_code.value);

            try {
                const res = await fetch('', { method: 'POST', body: formData });
                const data = await res.json();
                if (data.success) {
                    showResult('严格模式安装成功！3秒后跳转...', false);
                    setTimeout(() => window.location.href = '../' + (data.admin_dir || 'admin') + '/', 3000);
                } else {
                    showResult(data.message, true);
                }
            } catch (err) {
                showResult('安装失败: ' + err.message, true);
            }
        });
    </script>
</body>
</html>