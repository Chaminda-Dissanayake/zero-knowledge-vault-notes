<?php
require_once __DIR__ . '/auth.php';

$user = requireLogin();

function recoveryPublicToPem(array $jwk): string
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
     * AlgorithmIdentifier:
     *
     * id-ecPublicKey
     * prime256v1 / P-256
     */
    $algorithmIdentifier =
        derSeq(
            "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01" .
            "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"
        );

    /*
     * Uncompressed P-256 public point.
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
        throw new RuntimeException('Invalid signature.');
    }

    return derSeq(
        derInt(substr($raw, 0, 32)) .
        derInt(substr($raw, 32, 32))
    );
}

function validRecoveryWrap(string $wrap): bool
{
    try {
        /*
         * AES-GCM wrapper format:
         *
         * 12 byte IV
         * 32 byte plaintext vault key
         * 16 byte authentication tag
         *
         * Total minimum = 60 bytes.
         */
        return strlen(b64d($wrap)) === 12 + 32 + 16;
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
            strlen(b64d((string)$jwk['x'])) === 32 &&
            strlen(b64d((string)$jwk['y'])) === 32;
    } catch (Throwable) {
        return false;
    }
}

function recoveryRotationMessage(
    int $accountId,
    string $recoveryWrap,
    array $public
): string {
    return
        'vault-notes-v3/recovery-rotation|' .
        $accountId .
        '|' .
        $recoveryWrap .
        '|' .
        json_encode(
            $public,
            JSON_UNESCAPED_UNICODE |
            JSON_UNESCAPED_SLASHES |
            JSON_THROW_ON_ERROR
        );
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');

    try {
        verifyCsrf();

        $wrap = (string)($_POST['recovery_wrap'] ?? '');
        $publicJson = (string)($_POST['recovery_public'] ?? '');
        $signature = (string)($_POST['recovery_signature'] ?? '');

        if ($wrap === '' || $publicJson === '' || $signature === '') {
            throw new RuntimeException();
        }

        if (!validRecoveryWrap($wrap)) {
            throw new RuntimeException();
        }

        $public = json_decode(
            $publicJson,
            true,
            8,
            JSON_THROW_ON_ERROR
        );

        if (!is_array($public) || !validRecoveryPublic($public)) {
            throw new RuntimeException();
        }

        if (!validB64Bytes($signature, 64)) {
            throw new RuntimeException();
        }

        /*
         * The signature proves that the browser submitting this
         * recovery public key also possesses its corresponding
         * private key.
         */
        $message = recoveryRotationMessage(
            (int)$user['id'],
            $wrap,
            $public
        );

        $pem = recoveryPublicToPem($public);

        $verified = openssl_verify(
            $message,
            rawEcdsaToDer(b64d($signature)),
            $pem,
            OPENSSL_ALGO_SHA256
        );

        if ($verified !== 1) {
            throw new RuntimeException(
                'Invalid recovery key proof.'
            );
        }

        /*
         * We deliberately do NOT decrypt the recovery wrapper here.
         *
         * The server must never know the vault key.
         *
         * The server verifies:
         * - authenticated session
         * - valid AES-GCM wrapper structure
         * - valid P-256 public key
         * - possession of the corresponding private key
         *
         * The browser is responsible for creating the wrapper from
         * the currently-held vault key.
         */
        db()
            ->prepare(
                'UPDATE users
                 SET recovery_wrap=?, recovery_public=?
                 WHERE id=?'
            )
            ->execute([
                $wrap,
                $publicJson,
                (int)$user['id']
            ]);

        echo json_encode([
            'ok' => true,
            'account_id' => (int)$user['id'],
            'username' => $user['username']
        ]);

    } catch (Throwable $e) {
        http_response_code(422);

        echo json_encode([
            'error' => 'Could not update recovery key.'
        ]);
    }

    exit;
}

$first = isset($_GET['first']);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<meta
    name="csrf-token"
    content="<?=htmlspecialchars(csrfToken(),ENT_QUOTES)?>"
>

<meta
    name="user-id"
    content="<?= (int)$user['id'] ?>"
>

<title>Recovery — Vault Notes</title>

<link rel="stylesheet" href="style.css">
</head>

<body class="auth-page">

<main class="auth-card wide">

<div class="brand">Recovery file</div>

<?php if ($first): ?>
<div class="alert success">
    Account created. Download your recovery file now.
</div>
<?php endif; ?>

<p>
    A recovery file contains a separate private recovery key.
    <strong>Anyone who obtains it can recover the vault.</strong>
    The server never receives that private key.
</p>

<div id="error" class="alert error hidden"></div>

<button
    id="generate"
    class="btn primary full"
>
    Generate fresh recovery file
</button>

<p class="hint">
    Generating a new file replaces the old recovery key.
    Keep the new file offline and private.
</p>

<a
    class="btn ghost full"
    href="index.php"
>
    Back to notes
</a>

</main>

<script src="crypto-client.js"></script>

<script>
const csrf =
    document.querySelector(
        'meta[name="csrf-token"]'
    ).content;

const username =
    <?=json_encode(
        $user['username'],
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    )?>;

const accountId =
    Number(
        document.querySelector(
            'meta[name="user-id"]'
        ).content
    );

const errorBox =
    document.getElementById('error');

function err(message) {
    errorBox.textContent = message;
    errorBox.classList.remove('hidden');
}

document.getElementById('generate').onclick = async () => {

    errorBox.classList.add('hidden');

    const vaultKey =
        VaultCrypto.getVaultKey();

    if (!vaultKey) {
        location.href = 'login.php';
        return;
    }

    const btn =
        document.getElementById('generate');

    btn.disabled = true;
    btn.textContent = 'Generating…';

    try {

        const recovery =
            await VaultCrypto.createRecoveryKey();

        const wrap =
            await VaultCrypto.encryptBytes(
                vaultKey,
                recovery.aesKey,
                'recovery-wrap-v3'
            );

        /*
         * Prove possession of the private key corresponding
         * to the public key being submitted.
         */
        const signature =
            await VaultCrypto.signRecoveryRotation(
                recovery.privateJwk,
                accountId,
                wrap,
                recovery.publicJwk
            );

        const fd = new FormData();

        fd.append('csrf', csrf);
        fd.append('recovery_wrap', wrap);

        fd.append(
            'recovery_public',
            JSON.stringify(recovery.publicJwk)
        );

        fd.append(
            'recovery_signature',
            signature
        );

        const r =
            await fetch(
                'recovery.php',
                {
                    method: 'POST',
                    body: fd,
                    credentials: 'same-origin'
                }
            );

        const j = await r.json();

        if (!r.ok || j.error) {
            throw new Error(
                j.error ||
                'Could not update recovery key.'
            );
        }

        /*
         * Only download the recovery file AFTER the
         * server has successfully accepted the new key.
         */
        const payload =
            VaultCrypto.makeRecoveryPayload(
                username,
                accountId,
                recovery.privateJwk,
                recovery.publicJwk
            );

        VaultCrypto.downloadRecovery(
            payload,
            username
        );

    } catch (e) {

        err(
            e.message ||
            'Could not generate recovery file.'
        );

    } finally {

        btn.disabled = false;
        btn.textContent =
            'Generate fresh recovery file';
    }
};
</script>

</body>
</html>