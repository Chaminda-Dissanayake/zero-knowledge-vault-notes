# Vault Notes v3.1
Developed by **Chaminda Dissanayake** (GitHub: [Chaminda-Dissanayake](https://github.com/Chaminda-Dissanayake))

Vault Notes v3.1 keeps the v3 client-side encryption model and adds note organization and usability features.

## v3.1 features

- Folders with encrypted folder names
- Unfiled notes
- Search across note title, body, and decrypted folder name locally in the browser
- Search automatically scoped to the current folder/view
- Favorites
- Pinned notes
- Recently updated view
- Sorting by updated time, created time, or title
- Move one or many notes between folders
- Multi-select and bulk actions
- Trash with restore
- Permanent deletion from Trash
- Folder rename/delete management
- Folder icons
- Note previews and folder labels
- Exact created/last-updated date and time for each note
- Vault-level last-updated timestamp
- Ctrl/Cmd+K search and Ctrl/Cmd+N new note shortcuts
- Unsaved-change indicator

## Security model

PHP stores encrypted note titles/bodies and encrypted folder names. Plaintext note content and folder names are decrypted only in the browser using the in-memory vault key.

The server can still see structural metadata such as note IDs, folder IDs, timestamps, ciphertext sizes, favorite/pin state, and which notes share a folder. It does not receive plaintext note titles, bodies, or folder names.

Folder membership is intentionally represented by an opaque database folder ID. This avoids re-encrypting a note when it is moved between folders.

Search remains local. The server never performs plaintext search over notes.

## Cryptography

The existing v3 cryptographic implementation is retained:

- AES-256-GCM through browser Web Crypto
- Fresh 96-bit IV for each encryption operation
- PBKDF2-HMAC-SHA-256 with 600,000 iterations for password-derived keys
- Argon2id for the authentication verifier
- P-256 ECDSA recovery keys
- Separate encryption AAD domains for note titles, note bodies, and folder names

Folder names use the AAD domain `folder-name-v3`.

Existing note AAD domains remain `note-title-v3` and `note-body-v3`, so existing v3 notes remain compatible.

## Last-updated timestamps

Each note already had `created_at` and `updated_at` in v3. v3.1 continues using `updated_at` and now displays it in the note list, editor, and vault sidebar.

Folder records also have `created_at` and `updated_at`.

The API returns `last_updated_at`, calculated from active notes and folders, so the sidebar can show the latest vault activity.

Timestamps are stored as Unix timestamps. The browser formats them using the user's local timezone.

## Database migration

On first request after upgrading, `db.php` creates the `folders` table and adds the following columns to an existing v3 `notes` table when missing:

- `folder_id`
- `is_favorite`
- `is_pinned`
- `deleted_at`

Existing notes remain active, unfiled, unfavorited, and unpinned.

No note body/title is re-encrypted during this migration.

## Trash behavior

Deleting a note now performs a soft delete by setting `deleted_at`. The note remains encrypted and recoverable until permanently deleted.

Deleting a folder does not delete its notes. Its notes are moved to Unfiled.

Emptying Trash permanently deletes only notes currently in Trash.

## Important limitation

As with v3, this is not protection against a fully compromised live web server that can modify the JavaScript/HTML delivered to the browser. Such an attacker can potentially capture passwords or vault keys while they are in browser memory.

Use HTTPS, secure deployment, strict file permissions, backups, and current PHP/browser versions.

This project has not undergone a professional security audit.


## Responsive UI (v3.2)

The workspace is responsive across desktop, tablet, and phone widths. On smaller screens, the three-pane desktop workspace becomes a mobile panel workflow:

- Navigation opens as a slide-out drawer.
- The note list uses the full available screen width.
- Opening or creating a note switches to a full-screen editor.
- A back control returns from the editor to the note list.
- Search, sorting, selection, folder management, modals, and editor actions remain usable on touch screens.
- Safe-area padding is used for phones with gesture/navigation areas.
- Reduced-motion preferences are respected.

No encryption or storage architecture was changed by the responsive update.
