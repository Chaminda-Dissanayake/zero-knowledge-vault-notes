<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;

    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');

    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        auth_salt TEXT NOT NULL,
        auth_verifier TEXT NOT NULL,
        vault_salt TEXT NOT NULL,
        vault_wrap TEXT NOT NULL,
        recovery_wrap TEXT NOT NULL,
        recovery_public TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        icon TEXT NOT NULL DEFAULT '📁',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        folder_id INTEGER NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        is_favorite INTEGER NOT NULL DEFAULT 0,
        is_pinned INTEGER NOT NULL DEFAULT 0,
        deleted_at INTEGER NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
    )");

    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_notes_user_folder ON notes(user_id, folder_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_notes_user_updated ON notes(user_id, updated_at)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_notes_user_deleted ON notes(user_id, deleted_at)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_folders_user_updated ON folders(user_id, updated_at)');

    return $pdo;
}
