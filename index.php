<?php
/**
 * 私密加密盘 - 快速安装
 * 下载 → 解压 → 跳转 install
 */

$zipUrl = 'https://github.com/chidianqianying/-/releases/download/%E6%B5%8B%E8%AF%95%E7%89%88/encrypt_pan.zip';
$zipFile = __DIR__ . '/encrypt_pan.zip';

// 下载
if (!file_exists($zipFile)) {
    $ch = curl_init($zipUrl);
    $fp = fopen($zipFile, 'wb');
    curl_setopt($ch, CURLOPT_FILE, $fp);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 300);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
    curl_exec($ch);
    curl_close($ch);
    fclose($fp);

    // 下载完刷新继续解压
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}

// 解压
$zip = new ZipArchive();
if ($zip->open($zipFile) === TRUE) {
    $zip->extractTo(__DIR__ . '/');
    $zip->close();
    @unlink($zipFile);
}

// 跳转安装向导
header('Location: ./install/');
exit;
