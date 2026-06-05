<?php
/**
 * 私密加密网盘 - 主页
 * 上传 | 文件列表 | 保密文件
 */

// === 安装检测（每次访问都检测，支持故障重装） ===
if (!file_exists(__DIR__ . '/install.lock')) {
    header('Location: ./install/');
    exit;
}

require __DIR__ . '/config.php';

function generateHashName(): string {
    return bin2hex(random_bytes(16));
}

function sha256(string $data): string {
    return hash('sha256', $data);
}

function xorEncrypt(string $data, string $password): string {
    $key = md5($password, true);
    $keyLen = strlen($key);
    $dataLen = strlen($data);
    $result = '';
    for ($i = 0; $i < $dataLen; $i++) {
        $result .= $data[$i] ^ $key[$i % $keyLen];
    }
    return $result;
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

function cleanExpiredTemp(): void {
    global $CONFIG;
    $tempDir = __DIR__ . '/temp/';
    if (!is_dir($tempDir)) return;
    $now = time();
    foreach (glob($tempDir . '*') as $file) {
        if (is_file($file) && ($now - filemtime($file)) > 300) {
            @unlink($file);
        }
    }
}

cleanExpiredTemp();

$action = $_GET['action'] ?? 'home';

// 上传处理
if ($action === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    $pdo = getDB();
    $admin = $pdo->query("SELECT * FROM admin LIMIT 1")->fetch(PDO::FETCH_ASSOC);

    if ($admin['upload_password_enabled']) {
        if (empty($_SESSION['upload_auth']) || $_SESSION['upload_auth'] !== true) {
            echo json_encode(['success' => false, 'message' => '请先验证上传口令']);
            exit;
        }
    }

    $password = trim($_POST['password'] ?? '');
    if (empty($password)) {
        echo json_encode(['success' => false, 'message' => '加密密钥不能为空']);
        exit;
    }

    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['success' => false, 'message' => '上传失败']);
        exit;
    }

    $file = $_FILES['file'];
    if ($file['size'] > 100 * 1024 * 1024) {
        echo json_encode(['success' => false, 'message' => '文件超过最大限制']);
        exit;
    }

    $rawData = file_get_contents($file['tmp_name']);
    $encryptedData = xorEncrypt($rawData, $password);

    $hashName = generateHashName();
    $savePath = __DIR__ . '/uploads/' . $hashName;

    if (file_put_contents($savePath, $encryptedData) === false) {
        echo json_encode(['success' => false, 'message' => '文件保存失败']);
        exit;
    }

    $isSecret = isset($_POST['is_secret']) && $_POST['is_secret'] === '1';
    $secretPassword = trim($_POST['secret_password'] ?? '');

    $stmt = $pdo->prepare("INSERT INTO files (hash_name, is_secret, secret_password_hash) VALUES (?, ?, ?)");
    $stmt->execute([
        $hashName,
        $isSecret ? 1 : 0,
        $isSecret && !empty($secretPassword) ? sha256($secretPassword) : null
    ]);

    echo json_encode([
        'success'    => true,
        'message'    => '上传成功！',
        'hash_name'  => $hashName,
        'is_secret'  => $isSecret,
        'warning'    => '【重要】请保存混淆文件名和密码！服务器不存储任何文件信息，丢失无法找回！上传后不可删除！',
    ]);
    exit;
}

// 下载处理
if ($action === 'download' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    $hashName = preg_replace('/[^a-f0-9]/', '', $_POST['hash_name'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($hashName) || strlen($hashName) !== 32) {
        echo json_encode(['success' => false, 'message' => '文件名无效']);
        exit;
    }

    $encryptedPath = __DIR__ . '/uploads/' . $hashName;
    if (!file_exists($encryptedPath)) {
        echo json_encode(['success' => false, 'message' => '文件不存在']);
        exit;
    }

    $encryptedData = file_get_contents($encryptedPath);
    $decryptedData = xorEncrypt($encryptedData, $password);

    $tempName = substr(md5($hashName), 0, 16) . '.bin';
    $tempPath = __DIR__ . '/temp/' . $tempName;
    file_put_contents($tempPath, $decryptedData);

    echo json_encode([
        'success'      => true,
        'temp_url'     => './temp/' . $tempName,
        'message'      => '解密成功',
    ]);
    exit;
}

// 获取临时文件（强制下载）
if ($action === 'getfile') {
    $token = preg_replace('/[^a-f0-9.]/', '', $_GET['token'] ?? '');
    $tempPath = __DIR__ . '/temp/' . $token;

    if (!file_exists($tempPath)) {
        http_response_code(404);
        die('文件已过期或不存在');
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment');
    header('Content-Length: ' . filesize($tempPath));
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    readfile($tempPath);
    @unlink($tempPath);
    exit;
}

// 公开文件列表
if ($action === 'list') {
    header('Content-Type: application/json');
    $pdo = getDB();

    $stmt = $pdo->query("SELECT hash_name FROM files WHERE is_secret = 0 ORDER BY upload_time DESC");
    $files = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $path = __DIR__ . '/uploads/' . $row['hash_name'];
        if (file_exists($path)) {
            $files[] = [
                'hash_name'  => $row['hash_name'],
                'size'       => formatSize(filesize($path)),
                'size_bytes' => filesize($path),
            ];
        }
    }
    echo json_encode(['success' => true, 'files' => $files]);
    exit;
}

// 保密文件列表
if ($action === 'secret_list' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    $secretPass = trim($_POST['secret_password'] ?? '');
    if (empty($secretPass)) {
        echo json_encode(['success' => false, 'message' => '请输入保密口令']);
        exit;
    }

    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT hash_name FROM files WHERE is_secret = 1 AND secret_password_hash = ? ORDER BY upload_time DESC");
    $stmt->execute([sha256($secretPass)]);

    $files = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $path = __DIR__ . '/uploads/' . $row['hash_name'];
        if (file_exists($path)) {
            $files[] = [
                'hash_name'  => $row['hash_name'],
                'size'       => formatSize(filesize($path)),
                'size_bytes' => filesize($path),
            ];
        }
    }

    echo json_encode(['success' => true, 'files' => $files]);
    exit;
}

// 检查上传口令是否启用
if ($action === 'check_upload_password') {
    header('Content-Type: application/json');
    $pdo = getDB();
    $admin = $pdo->query("SELECT upload_password_enabled, upload_password_hash FROM admin LIMIT 1")->fetch(PDO::FETCH_ASSOC);
    echo json_encode([
        'enabled' => (bool)$admin['upload_password_enabled'],
        'authenticated' => !empty($_SESSION['upload_auth']) && $_SESSION['upload_auth'] === true
    ]);
    exit;
}

// 验证上传口令
if ($action === 'verify_upload_password' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $pdo = getDB();
    $admin = $pdo->query("SELECT upload_password_enabled, upload_password_hash FROM admin LIMIT 1")->fetch(PDO::FETCH_ASSOC);

    if (!$admin['upload_password_enabled']) {
        $_SESSION['upload_auth'] = true;
        echo json_encode(['success' => true, 'message' => '无需密码']);
        exit;
    }

    $inputPass = $_POST['upload_password'] ?? '';
    if (empty($inputPass)) {
        echo json_encode(['success' => false, 'message' => '请输入上传口令']);
        exit;
    }

    if (sha256($inputPass) === $admin['upload_password_hash']) {
        $_SESSION['upload_auth'] = true;
        echo json_encode(['success' => true, 'message' => '密码正确']);
    } else {
        echo json_encode(['success' => false, 'message' => '上传口令错误']);
    }
    exit;
}

?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>私密加密盘</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d1b2a 100%);
            min-height: 100vh;
            color: #e0e0e0;
        }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 30px 0 20px; position: relative; }
        .header h1 {
            font-size: 2.2em;
            background: linear-gradient(90deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .header p { color: #888; font-size: 0.9em; margin-top: 5px; }
        .admin-link {
            position: absolute;
            top: 10px;
            right: 0;
            padding: 6px 14px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #888;
            text-decoration: none;
            font-size: 0.8em;
        }
        .admin-link:hover { color: #e94560; border-color: rgba(233,69,96,0.3); }
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
        .form-group input[type="text"],
        .form-group input[type="password"],
        .form-group input[type="file"] {
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
            display: inline-block;
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #e94560, #c73e54);
            color: #fff;
            font-size: 1em;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover { transform: translateY(-2px); }
        .btn-secondary {
            background: linear-gradient(135deg, #533483, #7b2cbf);
        }
        .file-list { max-height: 500px; overflow-y: auto; }
        .file-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 15px;
            margin-bottom: 10px;
            background: rgba(0,0,0,0.25);
            border-radius: 10px;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .file-hash {
            font-family: 'Courier New', monospace;
            color: #e94560;
            font-size: 0.85em;
            word-break: break-all;
            cursor: pointer;
            user-select: all;
        }
        .file-hash:hover { text-decoration: underline; }
        .file-meta { color: #666; font-size: 0.8em; margin-top: 4px; }
        .btn-download {
            padding: 8px 20px;
            border: none;
            border-radius: 6px;
            background: #27ae60;
            color: #fff;
            font-size: 0.9em;
            cursor: pointer;
        }
        .btn-download:hover { background: #2ecc71; }
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.85);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: #0f0f23;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 30px;
            max-width: 450px;
            width: 90%;
            position: relative;
        }
        .modal-close {
            position: absolute;
            top: 15px;
            right: 20px;
            font-size: 1.5em;
            cursor: pointer;
            color: #666;
        }
        .modal-close:hover { color: #fff; }
        .result-box {
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(233, 69, 96, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin-top: 15px;
            display: none;
        }
        .result-box.show { display: block; }
        .hash-display {
            font-family: 'Courier New', monospace;
            background: rgba(0,0,0,0.5);
            padding: 12px;
            border-radius: 6px;
            word-break: break-all;
            color: #e94560;
            font-size: 1.1em;
            margin: 10px 0;
            user-select: all;
            text-align: center;
        }
        .warning {
            background: rgba(231, 76, 60, 0.12);
            border-left: 4px solid #e74c3c;
            padding: 12px 15px;
            border-radius: 0 8px 8px 0;
            margin: 10px 0;
            color: #ff9999;
            font-size: 0.9em;
        }
        .info {
            background: rgba(52, 152, 219, 0.12);
            border-left: 4px solid #3498db;
            padding: 12px 15px;
            border-radius: 0 8px 8px 0;
            margin: 10px 0;
            color: #85c1e9;
            font-size: 0.9em;
        }
        .secret-badge {
            display: inline-block;
            background: rgba(155, 89, 182, 0.2);
            color: #9b59b6;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75em;
            margin-left: 10px;
            border: 1px solid rgba(155, 89, 182, 0.3);
        }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            padding-bottom: 10px;
        }
        .tab {
            padding: 8px 20px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            color: #666;
        }
        .tab.active {
            background: rgba(233, 69, 96, 0.15);
            color: #e94560;
        }
        .tab:hover { background: rgba(255,255,255,0.03); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 10px 0;
        }
        .checkbox-group input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: #e94560;
        }
        .empty-state { text-align: center; padding: 40px; color: #555; }
        @media (max-width: 600px) {
            .file-item { flex-direction: column; align-items: flex-start; }
            .file-actions { margin-top: 10px; width: 100%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>私密加密盘</h1>
            <p>零元数据存储，密码即密钥，上传后不可删除</p>

        </div>

        <div class="tabs">
            <div class="tab active" onclick="switchTab('upload')">上传文件</div>
            <div class="tab" onclick="switchTab('files')">文件列表</div>
            <div class="tab" onclick="switchTab('secret')">保密文件</div>
        </div>

        <div id="tab-upload" class="tab-content active">
            <div class="card">
                <h2>上传加密文件</h2>
                <div class="warning">
                    上传后不可删除，请谨慎上传！
                </div>

                <!-- 上传口令验证界面 -->
                <div id="uploadAuthBox">
                    <div class="info">admin已开启上传口令验证，请输入密码解锁上传功能</div>
                    <div class="form-group">
                        <label>上传口令</label>
                        <input type="password" id="uploadAuthPass" placeholder="请输入上传口令...">
                    </div>
                    <button class="btn" onclick="verifyUploadPassword()">验证并解锁</button>
                </div>

                <!-- 上传表单（验证通过后显示） -->
                <form id="uploadForm" enctype="multipart/form-data" style="display:none;">
                    <div class="form-group">
                        <label>选择文件</label>
                        <input type="file" name="file" id="fileInput" required>
                    </div>
                    <div class="form-group">
                        <label>加密密钥（必填）</label>
                        <input type="password" name="password" id="uploadPassword" placeholder="请输入加密密钥..." required>
                    </div>
                    <div class="checkbox-group">
                        <input type="checkbox" id="isSecret" name="is_secret" value="1">
                        <label for="isSecret" style="margin:0; cursor:pointer;">加入保密文件列表</label>
                    </div>
                    <div class="form-group" id="secretPassGroup" style="display:none;">
                        <label>保密列表查看密码（输入保密口令才能在此列表看到该文件）</label>
                        <input type="password" name="secret_password" id="secretPassword" placeholder="设置保密查看密码">
                    </div>
                    <button type="submit" class="btn">上传并加密</button>
                </form>

                <div class="result-box" id="uploadResult">
                    <div class="info">上传成功！请保存以下信息：</div>
                    <div>混淆文件名（点击复制）：</div>
                    <div class="hash-display" id="resultHash" onclick="copyToClipboard(this.textContent)"></div>
                    <div class="warning">
                        请截图保存此文件名和密码！服务器不存储任何信息，丢失无法找回！<br>
                        上传后不可删除，请确认文件内容后再上传！
                    </div>
                </div>
            </div>
        </div>

        <div id="tab-files" class="tab-content">
            <div class="card">
                <h2>公开文件列表</h2>
                <div class="info">
                    列表中只显示混淆哈希名和加密后大小。下载后请自行判断文件类型。
                </div>
                <div class="file-list" id="fileList">
                    <div class="empty-state">加载中...</div>
                </div>
            </div>
        </div>

        <div id="tab-secret" class="tab-content">
            <div class="card">
                <h2>保密文件列表 <span class="secret-badge">需密码</span></h2>
                <div class="info">
                    输入保密口令查看对应的保密文件。多个文件使用相同保密口令会一并显示。
                </div>
                <div class="form-group">
                    <label>保密口令</label>
                    <input type="password" id="secretListPassword" placeholder="输入保密口令查看文件...">
                </div>
                <button class="btn" onclick="loadSecretList()">查看保密文件</button>
                <div class="file-list" id="secretFileList" style="margin-top:20px;">
                    <div class="empty-state">输入密码后点击"查看保密文件"</div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal" id="downloadModal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h2 style="color: #e94560; margin-bottom: 15px;">输入解密口令</h2>
            <div class="info" style="margin-bottom: 15px;">
                文件名：<span id="modalHashName" style="color: #e94560; font-family: monospace;"></span>
            </div>
            <form id="downloadForm">
                <input type="hidden" id="downloadHashName">
                <div class="form-group">
                    <label>解密口令</label>
                    <input type="password" id="downloadPassword" placeholder="请输入解密口令..." required autofocus>
                </div>
                <button type="submit" class="btn">解密并下载</button>
            </form>
        </div>
    </div>

    <script>
        // 检查上传口令状态
        fetch('?action=check_upload_password')
            .then(r => r.json())
            .then(data => {
                if (!data.enabled) {
                    // 未开启密码验证，直接显示上传表单
                    document.getElementById('uploadAuthBox').style.display = 'none';
                    document.getElementById('uploadForm').style.display = 'block';
                } else if (data.authenticated) {
                    // 已验证过，直接显示上传表单
                    document.getElementById('uploadAuthBox').style.display = 'none';
                    document.getElementById('uploadForm').style.display = 'block';
                }
                // 否则保持显示验证界面
            });

        async function verifyUploadPassword() {
            const password = document.getElementById('uploadAuthPass').value;
            if (!password) {
                alert('请输入上传口令');
                return;
            }
            try {
                const res = await fetch('?action=verify_upload_password', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'upload_password=' + encodeURIComponent(password)
                });
                const data = await res.json();
                if (data.success) {
                    document.getElementById('uploadAuthBox').style.display = 'none';
                    document.getElementById('uploadForm').style.display = 'block';
                } else {
                    alert(data.message);
                }
            } catch (err) {
                alert('验证失败: ' + err.message);
            }
        }

        document.getElementById('isSecret').addEventListener('change', function() {
            document.getElementById('secretPassGroup').style.display = this.checked ? 'block' : 'none';
        });

        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('tab-' + tab).classList.add('active');
            if (tab === 'files') loadFileList();
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('已复制：' + text);
            }).catch(() => {
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                alert('已复制到剪贴板');
            });
        }

        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            if (uploadToken && uploadToken !== 'none') {
                formData.append('upload_token', uploadToken);
            }
            const resultBox = document.getElementById('uploadResult');

            try {
                const response = await fetch('?action=upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();

                if (data.success) {
                    document.getElementById('resultHash').textContent = data.hash_name;
                    resultBox.classList.add('show');
                    this.reset();
                    document.getElementById('secretPassGroup').style.display = 'none';
                } else {
                    alert(data.message);
                    resultBox.classList.remove('show');
                }
            } catch (err) {
                alert('上传出错：' + err.message);
            }
        });

        async function loadFileList() {
            const listEl = document.getElementById('fileList');
            try {
                const response = await fetch('?action=list');
                const data = await response.json();

                if (!data.success || data.files.length === 0) {
                    listEl.innerHTML = '<div class="empty-state">暂无文件</div>';
                    return;
                }

                listEl.innerHTML = data.files.map(file => `
                    <div class="file-item">
                        <div style="flex:1; min-width:0;">
                            <div class="file-hash" onclick="copyToClipboard('${file.hash_name}')" title="点击复制">${file.hash_name}</div>
                            <div class="file-meta">加密后大小: ${file.size}</div>
                        </div>
                        <div class="file-actions">
                            <button class="btn-download" onclick="openDownload('${file.hash_name}')">下载</button>
                        </div>
                    </div>
                `).join('');
            } catch (err) {
                listEl.innerHTML = '<div class="empty-state">加载失败</div>';
            }
        }

        async function loadSecretList() {
            const password = document.getElementById('secretListPassword').value;
            const listEl = document.getElementById('secretFileList');

            if (!password) {
                alert('请输入保密口令');
                return;
            }

            try {
                const response = await fetch('?action=secret_list', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'secret_password=' + encodeURIComponent(password)
                });
                const data = await response.json();

                if (!data.success || data.files.length === 0) {
                    listEl.innerHTML = '<div class="empty-state">没有找到匹配的保密文件</div>';
                    return;
                }

                listEl.innerHTML = data.files.map(file => `
                    <div class="file-item">
                        <div style="flex:1; min-width:0;">
                            <div class="file-hash" onclick="copyToClipboard('${file.hash_name}')" title="点击复制">${file.hash_name}</div>
                            <div class="file-meta">加密后大小: ${file.size}</div>
                        </div>
                        <div class="file-actions">
                            <button class="btn-download" onclick="openDownload('${file.hash_name}')">下载</button>
                        </div>
                    </div>
                `).join('');
            } catch (err) {
                listEl.innerHTML = '<div class="empty-state">加载失败</div>';
            }
        }

        function openDownload(hashName) {
            document.getElementById('modalHashName').textContent = hashName;
            document.getElementById('downloadHashName').value = hashName;
            document.getElementById('downloadPassword').value = '';
            document.getElementById('downloadModal').classList.add('active');
            setTimeout(() => document.getElementById('downloadPassword').focus(), 100);
        }

        function closeModal() {
            document.getElementById('downloadModal').classList.remove('active');
        }

        document.getElementById('downloadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const hashName = document.getElementById('downloadHashName').value;
            const password = document.getElementById('downloadPassword').value;

            try {
                const response = await fetch('?action=download', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'hash_name=' + encodeURIComponent(hashName) + '&password=' + encodeURIComponent(password)
                });
                const data = await response.json();

                if (data.success) {
                    closeModal();
                    window.location.href = data.temp_url;
                } else {
                    alert(data.message);
                }
            } catch (err) {
                alert('下载出错：' + err.message);
            }
        });

        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', function(e) {
                if (e.target === this) this.classList.remove('active');
            });
        });
    </script>
</body>
</html>
