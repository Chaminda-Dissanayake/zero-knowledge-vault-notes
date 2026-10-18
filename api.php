<?php
declare(strict_types=1);
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');

function jsonOut(array $data, int $status = 200): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

$user = requireLogin();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonOut(['error' => 'POST required'], 405);
verifyCsrf();

$action = (string)($_POST['action'] ?? '');
$pdo = db();
$uid = (int)$user['id'];

function validFolderForUser(PDO $pdo, int $folderId, int $uid): bool {
    if ($folderId <= 0) return true;
    $s = $pdo->prepare('SELECT 1 FROM folders WHERE id=? AND user_id=?');
    $s->execute([$folderId, $uid]);
    return (bool)$s->fetchColumn();
}

function noteIdsFromPost(): array {
    $raw = $_POST['ids'] ?? [];
    if (!is_array($raw)) $raw = [$raw];
    $ids = [];
    foreach ($raw as $v) {
        $id = filter_var($v, FILTER_VALIDATE_INT);
        if ($id !== false && $id > 0) $ids[] = (int)$id;
    }
    return array_values(array_unique($ids));
}

try {
    if ($action === 'list') {
        $s = $pdo->prepare('SELECT id,folder_id,title,body,is_favorite,is_pinned,deleted_at,created_at,updated_at FROM notes WHERE user_id=? ORDER BY updated_at DESC');
        $s->execute([$uid]);
        $notes = [];
        foreach ($s as $r) {
            $notes[] = [
                'id' => (int)$r['id'],
                'folder_id' => $r['folder_id'] === null ? null : (int)$r['folder_id'],
                'title' => $r['title'],
                'body' => $r['body'],
                'is_favorite' => (bool)$r['is_favorite'],
                'is_pinned' => (bool)$r['is_pinned'],
                'deleted_at' => $r['deleted_at'] === null ? null : (int)$r['deleted_at'],
                'created_at' => (int)$r['created_at'],
                'updated_at' => (int)$r['updated_at'],
            ];
        }

        $f = $pdo->prepare('SELECT id,name,icon,created_at,updated_at FROM folders WHERE user_id=? ORDER BY updated_at DESC, id ASC');
        $f->execute([$uid]);
        $folders = [];
        foreach ($f as $r) {
            $folders[] = [
                'id' => (int)$r['id'],
                'name' => $r['name'],
                'icon' => $r['icon'],
                'created_at' => (int)$r['created_at'],
                'updated_at' => (int)$r['updated_at'],
            ];
        }
        $max = $pdo->prepare('SELECT MAX(updated_at) FROM notes WHERE user_id=? AND deleted_at IS NULL');
        $max->execute([$uid]);
        $last = $max->fetchColumn();
        $fm = $pdo->prepare('SELECT MAX(updated_at) FROM folders WHERE user_id=?');
        $fm->execute([$uid]);
        $folderLast = $fm->fetchColumn();
        if ($folderLast !== false && $folderLast !== null && ($last === false || $last === null || (int)$folderLast > (int)$last)) $last = $folderLast;

        jsonOut(['notes' => $notes, 'folders' => $folders, 'last_updated_at' => $last === false || $last === null ? null : (int)$last]);
    }

    if ($action === 'save') {
        $id = (int)($_POST['id'] ?? 0);
        $title = (string)($_POST['title'] ?? '');
        $body = (string)($_POST['body'] ?? '');
        $folderId = (int)($_POST['folder_id'] ?? 0);
        $favorite = !empty($_POST['is_favorite']) ? 1 : 0;
        $pinned = !empty($_POST['is_pinned']) ? 1 : 0;
        if ($title === '' || strlen($title) > 4000 || strlen($body) > 150000) jsonOut(['error' => 'Invalid or oversized encrypted note.'], 422);
        if (!validFolderForUser($pdo, $folderId, $uid)) jsonOut(['error' => 'Invalid folder.'], 422);
        $now = time();

        if ($id > 0) {
            $check = $pdo->prepare('SELECT 1 FROM notes WHERE id=? AND user_id=?');
            $check->execute([$id, $uid]);
            if (!$check->fetchColumn()) jsonOut(['error' => 'Note not found.'], 404);
            $s = $pdo->prepare('UPDATE notes SET title=?,body=?,folder_id=?,is_favorite=?,is_pinned=?,deleted_at=NULL,updated_at=? WHERE id=? AND user_id=?');
            $s->execute([$title, $body, $folderId > 0 ? $folderId : null, $favorite, $pinned, $now, $id, $uid]);
        } else {
            $s = $pdo->prepare('INSERT INTO notes(user_id,folder_id,title,body,is_favorite,is_pinned,deleted_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)');
            $s->execute([$uid, $folderId > 0 ? $folderId : null, $title, $body, $favorite, $pinned, null, $now, $now]);
            $id = (int)$pdo->lastInsertId();
        }
        if ($folderId > 0) $pdo->prepare('UPDATE folders SET updated_at=? WHERE id=? AND user_id=?')->execute([$now, $folderId, $uid]);
        jsonOut(['ok' => true, 'id' => $id, 'updated_at' => $now]);
    }

    if ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);
        $now = time();
        $s = $pdo->prepare('UPDATE notes SET deleted_at=?,updated_at=? WHERE id=? AND user_id=?');
        $s->execute([$now, $now, $id, $uid]);
        jsonOut(['ok' => true, 'updated_at' => $now]);
    }

    if ($action === 'restore') {
        $id = (int)($_POST['id'] ?? 0);
        $now = time();
        $s = $pdo->prepare('UPDATE notes SET deleted_at=NULL,updated_at=? WHERE id=? AND user_id=?');
        $s->execute([$now, $id, $uid]);
        jsonOut(['ok' => true, 'updated_at' => $now]);
    }

    if ($action === 'delete_permanently') {
        $ids = noteIdsFromPost();
        if (!$ids) jsonOut(['ok' => true]);
        $ph = implode(',', array_fill(0, count($ids), '?'));
        $params = array_merge([$uid], $ids);
        $pdo->prepare("DELETE FROM notes WHERE user_id=? AND id IN ($ph)")->execute($params);
        jsonOut(['ok' => true]);
    }

    if ($action === 'empty_trash') {
        $pdo->prepare('DELETE FROM notes WHERE user_id=? AND deleted_at IS NOT NULL')->execute([$uid]);
        jsonOut(['ok' => true]);
    }

    if ($action === 'toggle_flag') {
        $id = (int)($_POST['id'] ?? 0);
        $field = (string)($_POST['field'] ?? '');
        if (!in_array($field, ['is_favorite', 'is_pinned'], true)) jsonOut(['error' => 'Invalid flag.'], 422);
        $s = $pdo->prepare("SELECT $field FROM notes WHERE id=? AND user_id=?");
        $s->execute([$id, $uid]);
        $old = $s->fetchColumn();
        if ($old === false) jsonOut(['error' => 'Note not found.'], 404);
        $new = ((int)$old) ? 0 : 1;
        $now = time();
        $pdo->prepare("UPDATE notes SET $field=?,updated_at=? WHERE id=? AND user_id=?")->execute([$new, $now, $id, $uid]);
        jsonOut(['ok' => true, 'value' => (bool)$new, 'updated_at' => $now]);
    }

    if ($action === 'move_notes') {
        $ids = noteIdsFromPost();
        $folderId = (int)($_POST['folder_id'] ?? 0);
        if (!$ids) jsonOut(['ok' => true]);
        if (!validFolderForUser($pdo, $folderId, $uid)) jsonOut(['error' => 'Invalid folder.'], 422);
        $now = time();
        $ph = implode(',', array_fill(0, count($ids), '?'));
        $params = array_merge([$folderId > 0 ? $folderId : null, $now, $uid], $ids);
        $pdo->prepare("UPDATE notes SET folder_id=?,updated_at=? WHERE user_id=? AND id IN ($ph)")->execute($params);
        if ($folderId > 0) $pdo->prepare('UPDATE folders SET updated_at=? WHERE id=? AND user_id=?')->execute([$now, $folderId, $uid]);
        jsonOut(['ok' => true, 'updated_at' => $now]);
    }

    if ($action === 'bulk_flag') {
        $ids = noteIdsFromPost();
        $field = (string)($_POST['field'] ?? '');
        $value = !empty($_POST['value']) ? 1 : 0;
        if (!$ids || !in_array($field, ['is_favorite', 'is_pinned'], true)) jsonOut(['error' => 'Invalid bulk operation.'], 422);
        $ph = implode(',', array_fill(0, count($ids), '?'));
        $params = array_merge([$value, time(), $uid], $ids);
        $pdo->prepare("UPDATE notes SET $field=?,updated_at=? WHERE user_id=? AND id IN ($ph)")->execute($params);
        jsonOut(['ok' => true]);
    }

    if ($action === 'bulk_trash') {
        $ids = noteIdsFromPost();
        if (!$ids) jsonOut(['ok' => true]);
        $ph = implode(',', array_fill(0, count($ids), '?'));
        $params = array_merge([time(), time(), $uid], $ids);
        $pdo->prepare("UPDATE notes SET deleted_at=?,updated_at=? WHERE user_id=? AND id IN ($ph)")->execute($params);
        jsonOut(['ok' => true]);
    }

    if ($action === 'create_folder') {
        $name = (string)($_POST['name'] ?? '');
        $icon = (string)($_POST['icon'] ?? '📁');
        if ($name === '' || strlen($name) > 4000 || strlen($icon) > 32) jsonOut(['error' => 'Invalid folder.'], 422);
        $now = time();
        $s = $pdo->prepare('INSERT INTO folders(user_id,name,icon,created_at,updated_at) VALUES(?,?,?,?,?)');
        $s->execute([$uid, $name, $icon ?: '📁', $now, $now]);
        jsonOut(['ok' => true, 'id' => (int)$pdo->lastInsertId(), 'updated_at' => $now]);
    }

    if ($action === 'rename_folder') {
        $id = (int)($_POST['id'] ?? 0);
        $name = (string)($_POST['name'] ?? '');
        $icon = (string)($_POST['icon'] ?? '📁');
        if ($name === '' || strlen($name) > 4000 || strlen($icon) > 32) jsonOut(['error' => 'Invalid folder.'], 422);
        $now = time();
        $check = $pdo->prepare('SELECT 1 FROM folders WHERE id=? AND user_id=?');
        $check->execute([$id, $uid]);
        if (!$check->fetchColumn()) jsonOut(['error' => 'Folder not found.'], 404);
        $s = $pdo->prepare('UPDATE folders SET name=?,icon=?,updated_at=? WHERE id=? AND user_id=?');
        $s->execute([$name, $icon ?: '📁', $now, $id, $uid]);
        jsonOut(['ok' => true, 'updated_at' => $now]);
    }

    if ($action === 'delete_folder') {
        $id = (int)($_POST['id'] ?? 0);
        $now = time();
        $pdo->beginTransaction();
        $s = $pdo->prepare('UPDATE notes SET folder_id=NULL,updated_at=? WHERE folder_id=? AND user_id=?');
        $s->execute([$now, $id, $uid]);
        $d = $pdo->prepare('DELETE FROM folders WHERE id=? AND user_id=?');
        $d->execute([$id, $uid]);
        $pdo->commit();
        if (!$d->rowCount()) jsonOut(['error' => 'Folder not found.'], 404);
        jsonOut(['ok' => true, 'updated_at' => $now]);
    }

    jsonOut(['error' => 'Unknown action.'], 400);
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    jsonOut(['error' => 'Operation failed.'], 500);
}
