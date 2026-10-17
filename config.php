<?php
declare(strict_types=1);

const APP_NAME = 'Vault Notes';
const DB_PATH = __DIR__ . '/data/vault-v3.sqlite';
const RECOVERY_DIR = __DIR__ . '/recovery';
const SESSION_NAME = 'vaultnotes_session';

const PASSWORD_MIN = 10;
const PBKDF2_ITERATIONS = 600000;
const AUTH_HASH_ALGO = PASSWORD_ARGON2ID;
const AUTH_HASH_OPTIONS = [
    'memory_cost' => 65536,
    'time_cost' => 3,
    'threads' => 1,
];

date_default_timezone_set('Asia/Colombo');

ini_set('session.use_only_cookies', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
// Automatically secure cookies if running over HTTPS
if (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] === 'on' || $_SERVER['HTTPS'] == 1) || 
    (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')) {
    ini_set('session.cookie_secure', '1');
}

session_name(SESSION_NAME);
session_start();

if (!is_dir(__DIR__ . '/data')) @mkdir(__DIR__ . '/data', 0700, true);
if (!is_dir(RECOVERY_DIR)) @mkdir(RECOVERY_DIR, 0700, true);
