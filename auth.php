<?php
declare(strict_types=1);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';

function currentUser(): ?array {
    if (empty($_SESSION['user_id'])) return null;
    $s = db()->prepare('SELECT id, username FROM users WHERE id = ?');
    $s->execute([(int)$_SESSION['user_id']]);
    return $s->fetch() ?: null;
}

function requireLogin(): array {
    $u = currentUser();
    if (!$u) {
        header('Location: login.php');
        exit;
    }
    return $u;
}

function loginUser(array $user): void {
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function logoutUser(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}
