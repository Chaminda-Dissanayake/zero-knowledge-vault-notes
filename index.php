<?php
require_once __DIR__ . '/auth.php';
$user = requireLogin();
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="<?=htmlspecialchars(csrfToken(), ENT_QUOTES)?>">
<meta name="user-id" content="<?= (int)$user['id'] ?>">
<title><?=htmlspecialchars(APP_NAME)?> — Notes</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="app-shell">
<header class="topbar">
  <div>
  <div class="brand">Vault Notes</div>
  <div class="sub">
    Private notes by 
    <a href="https://github.com/Chaminda-Dissanayake" target="_blank" rel="noopener noreferrer">
      Chaminda Dissanayake
    </a>
  </div>
</div>
<div class="top-actions"><span class="user-chip"><?=htmlspecialchars($user['username'])?></span><a class="btn ghost" href="account.php">Account</a><a class="btn ghost" href="recovery.php">Recovery</a><a class="btn ghost" href="logout.php">Lock</a></div>
</header>
<div class="mobile-backdrop" id="mobileBackdrop"></div>
<div class="mobile-bar">
  <button class="mobile-bar-btn" id="mobileMenuBtn" aria-label="Open navigation">☰</button>
  <button class="mobile-bar-title" id="mobileListBtn">Notes</button>
  <button class="mobile-bar-btn" id="mobileBackBtn" aria-label="Back to notes">‹</button>
</div>
<main class="workspace">
  <aside class="sidebar">
    <div class="side-head"><button id="newBtn" class="btn primary full">＋ New note</button></div>
    <label class="search"><span>⌕</span><input id="search" type="search" placeholder="Search notes…" autocomplete="off"></label>
    <nav class="smart-nav" id="smartNav">
      <button class="nav-item active" data-view="all">◉ <span>All notes</span><b id="allCount">0</b></button>
      <button class="nav-item" data-view="favorites">☆ <span>Favorites</span><b id="favoriteCount">0</b></button>
      <button class="nav-item" data-view="recent">◷ <span>Recently updated</span><b id="recentCount">0</b></button>
    </nav>
    <div class="section-label"><span>FOLDERS</span><button id="newFolderBtn" class="icon-btn" title="New folder">＋</button></div>
    <div id="folderList" class="folder-list"></div>
    <button class="nav-item" data-view="unfiled" id="unfiledBtn">📄 <span>Unfiled</span><b id="unfiledCount">0</b></button>
    <button class="nav-item trash-nav" data-view="trash" id="trashBtn">🗑 <span>Trash</span><b id="trashCount">0</b></button>
    <div class="sidebar-footer"><span id="vaultLastUpdated">Last updated —</span></div>
  </aside>

  <section class="note-pane">
    <div class="list-toolbar">
      <div><div id="viewTitle" class="view-title">All notes</div><div id="viewSubtitle" class="view-subtitle">Your active notes</div></div>
      <div class="toolbar-actions"><select id="sortSelect" class="sort-select"><option value="updated">Recently updated</option><option value="created">Recently created</option><option value="titleAsc">Title A → Z</option><option value="titleDesc">Title Z → A</option></select><button id="selectBtn" class="btn ghost">Select</button><button id="expandEditorBtn" class="btn ghost panel-toggle">Editor</button></div>
    </div>
    <div id="bulkBar" class="bulk-bar hidden"><span id="selectedCount">0 selected</span><button id="bulkMoveBtn" class="btn">Move</button><button id="bulkFavBtn" class="btn">☆ Favorite</button><button id="bulkPinBtn" class="btn">📌 Pin</button><button id="bulkTrashBtn" class="btn danger">Delete</button><button id="clearSelectBtn" class="btn ghost">Cancel</button></div>
    <div id="noteList" class="note-list"></div>
  </section>

  <section class="editor" id="editor">
    <div id="emptyState" class="empty"><div class="empty-icon">✦</div><h2>Select a note</h2><p>Create a note or select one from the list.</p></div>
    <form id="noteForm" class="note-form hidden">
      <div class="editor-topline"><div class="editor-heading"><button type="button" id="showNotesBtn" class="btn ghost panel-toggle">‹ Notes</button><div id="noteLocation" class="note-location">Unfiled</div></div><div id="noteMeta" class="note-meta"></div></div>
      <input type="hidden" id="noteId"><input id="title" maxlength="180" placeholder="Note title" required>
      <textarea id="body" maxlength="100000" placeholder="Write anything…"></textarea>
      <div class="editor-footer"><span id="saveState" class="muted"></span><div class="editor-buttons"><button type="button" id="favoriteBtn" class="btn ghost">☆ Favorite</button><button type="button" id="pinBtn" class="btn ghost">📌 Pin</button><button type="button" id="moveBtn" class="btn ghost">📁 Move</button><button type="button" id="deleteBtn" class="btn danger ghost">Delete</button><button type="submit" class="btn primary" id="saveBtn">Save</button></div></div>
    </form>
  </section>
</main>
</div>

<div id="modal" class="modal hidden"><div class="modal-card"><div class="modal-head"><h3 id="modalTitle">Folder</h3><button id="modalClose" class="icon-btn">×</button></div><div id="modalBody"></div></div></div>
<div id="toast" class="toast"></div>
<script src="crypto-client.js"></script><script src="app.js"></script>
</body>
</html>
