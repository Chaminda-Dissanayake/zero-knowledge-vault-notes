<?php
declare(strict_types=1);

function b64e(string $v): string {
    return rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
}

function b64d(string $v): string {
    $v = strtr($v, '-_', '+/');
    $v .= str_repeat('=', (4 - strlen($v) % 4) % 4);
    $decoded = base64_decode($v, true);
    if ($decoded === false) throw new RuntimeException('Invalid Base64 data.');
    return $decoded;
}

function randomKey(): string {
    return random_bytes(32);
}

function validPassword(string $p): bool {
    return strlen($p) >= PASSWORD_MIN && strlen($p) <= 512;
}

function validB64Bytes(string $value, int $length): bool {
    try {
        return strlen(b64d($value)) === $length;
    } catch (Throwable) {
        return false;
    }
}

function csrfToken(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}

function verifyCsrf(): void {
    $sent = $_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', (string)$sent)) {
        http_response_code(419);
        exit('Invalid request token.');
    }
}
