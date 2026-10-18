<?php
require_once __DIR__ . '/auth.php';

function derLen(int $n): string
{
    if ($n < 128) {
        return chr($n);
    }

    $out = '';

    while ($n > 0) {
        $out = chr($n & 255) . $out;
        $n >>= 8;
    }

    return chr(0x80 | strlen($out)) . $out;
}

function derSeq(string $v): string
{
    return "\x30" . derLen(strlen($v)) . $v;
}

function derInt(string $v): string
{
    $v = ltrim($v, "\x00");

    if ($v === '') {
        $v = "\x00";
    }

    if ((ord($v[0]) & 0x80) !== 0) {
        $v = "\x00" . $v;
    }

    return "\x02" . derLen(strlen($v)) . $v;
}

function rawEcdsaToDer(string $raw): string
{
    if (strlen($raw) !== 64) {
        throw new RuntimeException(
            'Invalid signature.'
        );
    }

    return derSeq(
        derInt(substr($raw, 0, 32)) .
        derInt(substr($raw, 32, 32))
    );
}

function jwkToPem(array $jwk): string
{
    if (
        ($jwk['kty'] ?? '') !== 'EC' ||
        ($jwk['crv'] ?? '') !== 'P-256' ||
        !isset($jwk['x']) ||
        !isset($jwk['y'])
    ) {
        throw new RuntimeException(
            'Invalid recovery public key.'
        );
    }

    $x = b64d((string)$jwk['x']);
    $y = b64d((string)$jwk['y']);

    if (
        strlen($x) !== 32 ||
        strlen($y) !== 32
    ) {
        throw new RuntimeException(
            'Invalid recovery public key.'
        );
    }

    /*
     * SubjectPublicKeyInfo for:
     *
     * id-ecPublicKey / prime256v1
     */
    $algorithmIdentifier =
        derSeq(
            "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01" .
            "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"
        );

    /*
     * EC uncompressed point:
     *
     * 00 = unused bits
     * 04 = uncompressed point
     * X   = 32 bytes
     * Y   = 32 bytes
     *
     * Total BIT STRING content = 66 bytes.
     */
    $publicPoint =
        "\x00" .
        "\x04" .
        $x .
        $y;

    $bitString =
        "\x03" .
        derLen(strlen($publicPoint)) .
        $publicPoint;

    $der =
        derSeq(
            $algorithmIdentifier .
            $bitString
        );

    return
        "-----BEGIN PUBLIC KEY-----\n" .
        chunk_split(
            base64_encode($der),
            64,
            "\n"
        ) .
        "-----END PUBLIC KEY-----\n";
}

function validRecoveryWrap(string $wrap): bool
{
    try {

        /*
         * AES-GCM:
         * 12 byte IV
         * 32 byte vault key
         * 16 byte authentication tag
         */
        return strlen(b64d($wrap)) === 60;

    } catch (Throwable) {

        return false;
    }
}

function validRecoveryPublic(array $jwk): bool
{
    try {

        if (
            ($jwk['kty'] ?? '') !== 'EC' ||
            ($jwk['crv'] ?? '') !== 'P-256' ||
            !isset($jwk['x']) ||
            !isset($jwk['y'])
        ) {
            return false;
        }

        return
            strlen(
                b64d((string)$jwk['x'])
            ) === 32 &&
            strlen(
                b64d((string)$jwk['y'])
            ) === 32;

    } catch (Throwable) {

        return false;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    header(
        'Content-Type: application/json; charset=utf-8'
    );

    try {

        verifyCsrf();

        $action =
            (string)($_POST['action'] ?? '');

        /*
         * BEGIN RECOVERY
         */
        if ($action === 'begin') {

            $username =
                trim(
                    (string)($_POST['username'] ?? '')
                );

            $accountId =
                (int)($_POST['account_id'] ?? 0);

            if (
                $accountId <= 0 ||
                $username === ''
            ) {
                throw new RuntimeException();
            }

            $s = db()->prepare(
                'SELECT
                    id,
                    username,
                    recovery_wrap,
                    recovery_public
                 FROM users
                 WHERE id=? AND username=?'
            );

            $s->execute([
                $accountId,
                $username
            ]);

            $u = $s->fetch();

            if (!$u) {
                throw new RuntimeException();
            }

            /*
             * Validate the stored recovery material before
             * giving it to the browser.
             */
            if (
                !validRecoveryWrap(
                    $u['recovery_wrap']
                )
            ) {
                throw new RuntimeException();
            }

            $public =
                json_decode(
                    $u['recovery_public'],
                    true,
                    8,
                    JSON_THROW_ON_ERROR
                );

            if (
                !is_array($public) ||
                !validRecoveryPublic($public)
            ) {
                throw new RuntimeException();
            }

            $challenge =
                b64e(
                    random_bytes(32)
                );

            $_SESSION['recovery_challenge'] = [
                'account_id' =>
                    (int)$u['id'],

                'challenge' =>
                    $challenge,

                'expires' =>
                    time() + 300
            ];

            echo json_encode([
                'ok' => true,

                'recovery_wrap' =>
                    $u['recovery_wrap'],

                'recovery_public' =>
                    $public,

                'challenge' =>
                    $challenge
            ]);

            exit;
        }

        /*
         * RESET PASSWORD
         */
        if ($action === 'reset') {

            $accountId =
                (int)($_POST['account_id'] ?? 0);

            $signature =
                (string)($_POST['signature'] ?? '');

            $newAuth =
                (string)($_POST['new_auth_secret'] ?? '');

            $newAuthSalt =
                (string)($_POST['new_auth_salt'] ?? '');

            $newVaultSalt =
                (string)($_POST['new_vault_salt'] ?? '');

            $newVaultWrap =
                (string)($_POST['new_vault_wrap'] ?? '');

            $c =
                $_SESSION['recovery_challenge']
                ?? null;

            if (
                !$c ||
                time() > (int)$c['expires'] ||
                (int)$c['account_id'] !== $accountId
            ) {
                throw new RuntimeException(
                    'Recovery session expired.'
                );
            }

            if (
                !validB64Bytes(
                    $signature,
                    64
                ) ||
                !validB64Bytes(
                    $newAuth,
                    32
                ) ||
                !validB64Bytes(
                    $newAuthSalt,
                    16
                ) ||
                !validB64Bytes(
                    $newVaultSalt,
                    16
                ) ||
                !validRecoveryWrap(
                    $newVaultWrap
                )
            ) {
                throw new RuntimeException();
            }

            $s = db()->prepare(
                'SELECT
                    id,
                    username,
                    recovery_public
                 FROM users
                 WHERE id=?'
            );

            $s->execute([
                $accountId
            ]);

            $u = $s->fetch();

            if (!$u) {
                throw new RuntimeException();
            }

            $public =
                json_decode(
                    $u['recovery_public'],
                    true,
                    8,
                    JSON_THROW_ON_ERROR
                );

            if (
                !is_array($public) ||
                !validRecoveryPublic($public)
            ) {
                throw new RuntimeException();
            }

            $pem =
                jwkToPem($public);

            $ok =
                openssl_verify(
                    (string)$c['challenge'],
                    rawEcdsaToDer(
                        b64d($signature)
                    ),
                    $pem,
                    OPENSSL_ALGO_SHA256
                );

            if ($ok !== 1) {
                throw new RuntimeException(
                    'Invalid recovery proof.'
                );
            }

            $newVerifier =
                password_hash(
                    $newAuth,
                    AUTH_HASH_ALGO,
                    AUTH_HASH_OPTIONS
                );

            db()
                ->prepare(
                    'UPDATE users
                     SET
                        auth_salt=?,
                        auth_verifier=?,
                        vault_salt=?,
                        vault_wrap=?
                     WHERE id=?'
                )
                ->execute([
                    $newAuthSalt,
                    $newVerifier,
                    $newVaultSalt,
                    $newVaultWrap,
                    $accountId
                ]);

            unset(
                $_SESSION['recovery_challenge']
            );

            loginUser($u);

            echo json_encode([
                'ok' => true,
                'username' => $u['username']
            ]);

            exit;
        }

        throw new RuntimeException();

    } catch (Throwable $e) {

        http_response_code(422);

        echo json_encode([
            'error' =>
                'Recovery failed. Check the recovery file and new password.'
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

<title>Recover — Vault Notes</title>

<link rel="stylesheet" href="style.css">

</head>

<body class="auth-page">

<main class="auth-card wide">

<div class="brand">
    Recover vault
</div>

<p>
    The recovery file proves possession of a
    private recovery key. The browser uses that
    key to decrypt the vault; the server never
    receives it.
</p>

<div
    id="error"
    class="alert error hidden"
></div>

<form
    id="recoverForm"
    class="stack"
>

<label>
    Username
    <input
        id="username"
        required
        autocomplete="username"
    >
</label>

<label>
    Recovery file
    <input
        id="file"
        type="file"
        accept=".srec,application/octet-stream"
        required
    >
</label>

<label>
    New password
    <input
        id="newPassword"
        type="password"
        minlength="10"
        required
        autocomplete="new-password"
    >
</label>

<label>
    Confirm new password
    <input
        id="confirm"
        type="password"
        minlength="10"
        required
        autocomplete="new-password"
    >
</label>

<button
    class="btn primary full"
    id="recoverBtn"
>
    Reset password
</button>

</form>

<p class="auth-link">
    <a href="login.php">Back to login</a>
</p>

</main>

<script src="crypto-client.js"></script>

<script>

const csrf =
    document.querySelector(
        'meta[name="csrf-token"]'
    ).content;

const form =
    document.getElementById(
        'recoverForm'
    );

const errorBox =
    document.getElementById(
        'error'
    );

function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove('hidden');
}

function samePublic(a, b) {

    return !!(
        a &&
        b &&
        a.kty === b.kty &&
        a.crv === b.crv &&
        a.x === b.x &&
        a.y === b.y
    );
}

form.addEventListener(
    'submit',
    async e => {

        e.preventDefault();

        errorBox.classList.add('hidden');

        const btn =
            document.getElementById(
                'recoverBtn'
            );

        const username =
            document.getElementById(
                'username'
            ).value.trim();

        const file =
            document.getElementById(
                'file'
            ).files[0];

        const newP =
            document.getElementById(
                'newPassword'
            ).value;

        const confirm =
            document.getElementById(
                'confirm'
            ).value;

        if (!file) {
            showError(
                'Choose your recovery file.'
            );
            return;
        }

        if (
            newP.length < 10 ||
            newP.length > 512
        ) {
            showError(
                'Password must be 10–512 characters.'
            );
            return;
        }

        if (newP !== confirm) {
            showError(
                'Passwords do not match.'
            );
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Recovering…';

        try {

            const text =
                await file.text();

            const rec =
                VaultCrypto.parseRecoveryFile(
                    text
                );

            if (
                rec.username !== username
            ) {
                throw new Error(
                    'Username does not match the recovery file.'
                );
            }

            const beginFd =
                new FormData();

            beginFd.append(
                'csrf',
                csrf
            );

            beginFd.append(
                'action',
                'begin'
            );

            beginFd.append(
                'username',
                username
            );

            beginFd.append(
                'account_id',
                String(rec.account_id)
            );

            const br =
                await fetch(
                    'recover.php',
                    {
                        method: 'POST',
                        body: beginFd,
                        credentials: 'same-origin'
                    }
                );

            const bj =
                await br.json();

            if (
                !br.ok ||
                bj.error
            ) {
                throw new Error(
                    'Recovery failed.'
                );
            }

            if (
                !samePublic(
                    rec.publicJwk,
                    bj.recovery_public
                )
            ) {
                throw new Error(
                    'Recovery file does not match this account.'
                );
            }

            const recoveryAes =
                await VaultCrypto.recoveryAesKey(
                    rec.privateJwk
                );

            const vaultKey =
                await VaultCrypto.decryptBytes(
                    bj.recovery_wrap,
                    recoveryAes,
                    'recovery-wrap-v3'
                );

            if (vaultKey.length !== 32) {
                throw new Error(
                    'Invalid vault key.'
                );
            }

            const newAuthSalt =
                VaultCrypto.randomBytes(16);

            const newVaultSalt =
                VaultCrypto.randomBytes(16);

            const keys =
                await VaultCrypto.derivePasswordKeys(
                    newP,
                    VaultCrypto.b64e(
                        newAuthSalt
                    ),
                    VaultCrypto.b64e(
                        newVaultSalt
                    )
                );

            const wrap =
                await VaultCrypto.encryptBytes(
                    vaultKey,
                    keys.wrapKey,
                    'vault-wrap-v3'
                );

            const signature =
                await VaultCrypto.signRecoveryChallenge(
                    rec.privateJwk,
                    bj.challenge
                );

            const fd =
                new FormData();

            fd.append(
                'csrf',
                csrf
            );

            fd.append(
                'action',
                'reset'
            );

            fd.append(
                'account_id',
                String(rec.account_id)
            );

            fd.append(
                'signature',
                signature
            );

            fd.append(
                'new_auth_secret',
                VaultCrypto.b64e(
                    keys.authSecret
                )
            );

            fd.append(
                'new_auth_salt',
                VaultCrypto.b64e(
                    newAuthSalt
                )
            );

            fd.append(
                'new_vault_salt',
                VaultCrypto.b64e(
                    newVaultSalt
                )
            );

            fd.append(
                'new_vault_wrap',
                wrap
            );

            const rr =
                await fetch(
                    'recover.php',
                    {
                        method: 'POST',
                        body: fd,
                        credentials: 'same-origin'
                    }
                );

            const rj =
                await rr.json();

            if (
                !rr.ok ||
                rj.error
            ) {
                throw new Error(
                    rj.error ||
                    'Recovery failed.'
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
                'Recovery failed.'
            );

        } finally {

            btn.disabled = false;
            btn.textContent =
                'Reset password';
        }
    }
);

</script>

</body>
</html>