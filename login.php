<?php
require_once __DIR__ . '/auth.php';

if (currentUser()) {
    header('Location: index.php');
    exit;
}

/*
 * Salt information endpoint.
 *
 * This endpoint intentionally does not authenticate the user because
 * the salts are not secrets. They are required by the browser before
 * it can derive the password authentication secret and vault-wrap key.
 *
 * For unknown usernames, random salts are returned.
 */
if (isset($_GET['info'])) {

    header('Content-Type: application/json; charset=utf-8');

    try {

        $username =
            trim((string)($_GET['username'] ?? ''));

        if (
            $username === '' ||
            !preg_match(
                '/^[A-Za-z0-9_.-]{3,80}$/',
                $username
            )
        ) {
            echo json_encode([
                'auth_salt' =>
                    b64e(random_bytes(16)),
                'vault_salt' =>
                    b64e(random_bytes(16))
            ]);

            exit;
        }

        $s = db()->prepare(
            'SELECT auth_salt,vault_salt
             FROM users
             WHERE username=?'
        );

        $s->execute([$username]);

        $u = $s->fetch();

        if (!$u) {
            // Fake calculation to completely mirror missing users timing structure
            b64e(random_bytes(16));
            echo json_encode([
                'auth_salt' => b64e(random_bytes(16)),
                'vault_salt' => b64e(random_bytes(16))
            ]);
        }else {

            echo json_encode([
                'auth_salt' => $u['auth_salt'],
                'vault_salt' => $u['vault_salt']
            ]);
        }

    } catch (Throwable $e) {

        /*
         * Keep the response shape identical on errors.
         */
        echo json_encode([
            'auth_salt' =>
                b64e(random_bytes(16)),
            'vault_salt' =>
                b64e(random_bytes(16))
        ]);
    }

    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    header(
        'Content-Type: application/json; charset=utf-8'
    );

    try {

        verifyCsrf();

        $username =
            trim((string)($_POST['username'] ?? ''));

        $authSecret =
            (string)($_POST['auth_secret'] ?? '');

        if (
            $username === '' ||
            !preg_match(
                '/^[A-Za-z0-9_.-]{3,80}$/',
                $username
            )
        ) {
            throw new RuntimeException(
                'Invalid credentials.'
            );
        }

        if (!validB64Bytes($authSecret, 32)) {
            throw new RuntimeException(
                'Invalid credentials.'
            );
        }

        $s = db()->prepare(
            'SELECT
                id,
                username,
                auth_verifier,
                vault_salt,
                vault_wrap
             FROM users
             WHERE username=?'
        );

        $s->execute([$username]);

        $u = $s->fetch();

        if (
            !$u ||
            !password_verify(
                $authSecret,
                $u['auth_verifier']
            )
        ) {
            throw new RuntimeException(
                'Invalid credentials.'
            );
        }

        /*
         * Upgrade the Argon2id verifier automatically
         * if the configured parameters have changed.
         */
        if (
            password_needs_rehash(
                $u['auth_verifier'],
                AUTH_HASH_ALGO,
                AUTH_HASH_OPTIONS
            )
        ) {
            db()
                ->prepare(
                    'UPDATE users
                     SET auth_verifier=?
                     WHERE id=?'
                )
                ->execute([
                    password_hash(
                        $authSecret,
                        AUTH_HASH_ALGO,
                        AUTH_HASH_OPTIONS
                    ),
                    (int)$u['id']
                ]);
        }

        loginUser($u);

        echo json_encode([
            'ok' => true,
            'user_id' => (int)$u['id'],
            'username' => $u['username'],
            'vault_salt' => $u['vault_salt'],
            'vault_wrap' => $u['vault_wrap']
        ]);

    } catch (Throwable $e) {

        http_response_code(401);

        echo json_encode([
            'error' =>
                'Invalid username or password.'
        ]);
    }

    exit;
}
?>
<!doctype html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<meta
    name="csrf-token"
    content="<?=htmlspecialchars(
        csrfToken(),
        ENT_QUOTES
    )?>"
>

<title>Login — Vault Notes</title>

<link rel="stylesheet" href="style.css">

</head>

<body class="auth-page">

<main class="auth-card">

<div class="brand">
    Vault Notes
</div>

<p class="sub">
    Private notes, kept encrypted.
</p>

<div
    id="error"
    class="alert error hidden"
></div>

<form
    id="loginForm"
    class="stack"
>

<label>
    Username
    <input
        id="username"
        autocomplete="username"
        required
        maxlength="80"
    >
</label>

<label>
    Password
    <input
        id="password"
        type="password"
        autocomplete="current-password"
        required
    >
</label>

<button
    class="btn primary full"
    id="loginBtn"
>
    Unlock vault
</button>

</form>

<p class="auth-link">
    <a href="register.php">Create account</a>
    ·
    <a href="recover.php">Forgot password?</a>
</p>

</main>

<script src="crypto-client.js"></script>

<script>

const csrf =
    document.querySelector(
        'meta[name="csrf-token"]'
    ).content;

const form =
    document.getElementById('loginForm');

const errorBox =
    document.getElementById('error');

function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove('hidden');
}

form.addEventListener(
    'submit',
    async e => {

        e.preventDefault();

        errorBox.classList.add('hidden');

        const btn =
            document.getElementById('loginBtn');

        const username =
            document.getElementById(
                'username'
            ).value.trim();

        const password =
            document.getElementById(
                'password'
            ).value;

        btn.disabled = true;
        btn.textContent = 'Unlocking…';

        try {

            /*
             * PHP receives only password-derived material.
             * The plaintext password stays in this browser.
             */

            const saltReq =
                await fetch(
                    'login.php?info=1&username=' +
                    encodeURIComponent(username),
                    {
                        credentials: 'same-origin',
                        headers: {
                            'X-CSRF-Token': csrf
                        }
                    }
                );

            const info =
                await saltReq.json();

            if (
                !saltReq.ok ||
                info.error ||
                !VaultCrypto.b64d(info.auth_salt) ||
                !VaultCrypto.b64d(info.vault_salt)
            ) {
                throw new Error(
                    'Invalid username or password.'
                );
            }

            const keys =
                await VaultCrypto.derivePasswordKeys(
                    password,
                    info.auth_salt,
                    info.vault_salt
                );

            const fd =
                new FormData();

            fd.append(
                'csrf',
                csrf
            );

            fd.append(
                'username',
                username
            );

            fd.append(
                'auth_secret',
                VaultCrypto.b64e(
                    keys.authSecret
                )
            );

            const r =
                await fetch(
                    'login.php',
                    {
                        method: 'POST',
                        body: fd,
                        credentials: 'same-origin'
                    }
                );

            const j =
                await r.json();

            if (
                !r.ok ||
                j.error
            ) {
                throw new Error(
                    j.error ||
                    'Invalid username or password.'
                );
            }

            /*
             * Only the browser can unwrap the vault key.
             */
            const vaultKey =
                await VaultCrypto.decryptBytes(
                    j.vault_wrap,
                    keys.wrapKey,
                    'vault-wrap-v3'
                );

            if (vaultKey.length !== 32) {
                throw new Error(
                    'Invalid vault key.'
                );
            }

            VaultCrypto.setVaultKey(
                vaultKey
            );

            location.href =
                'index.php';

        } catch (err) {

            showError(
                err.message ||
                'Invalid username or password.'
            );

        } finally {

            btn.disabled = false;
            btn.textContent =
                'Unlock vault';
        }
    }
);

</script>

</body>
</html>