<?php
require_once __DIR__ . '/auth.php';

if (currentUser()) { header('Location: index.php'); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    try {
        verifyCsrf();
        $username = trim((string)($_POST['username'] ?? ''));
        $authSalt = (string)($_POST['auth_salt'] ?? '');
        $authSecret = (string)($_POST['auth_secret'] ?? '');
        $vaultSalt = (string)($_POST['vault_salt'] ?? '');
        $vaultWrap = (string)($_POST['vault_wrap'] ?? '');
        $recoveryWrap = (string)($_POST['recovery_wrap'] ?? '');
        $recoveryPublic = (string)($_POST['recovery_public'] ?? '');

        if (!preg_match('/^[A-Za-z0-9_.-]{3,80}$/', $username)) throw new RuntimeException('Invalid username.');
        if (!validB64Bytes($authSalt, 16)) throw new RuntimeException('Invalid authentication salt.');
        if (!validB64Bytes($authSecret, 32)) throw new RuntimeException('Invalid authentication secret.');
        if (!validB64Bytes($vaultSalt, 16)) throw new RuntimeException('Invalid vault salt.');
        if ($vaultWrap === '' || $recoveryWrap === '' || $recoveryPublic === '') throw new RuntimeException('Missing vault data.');
        if (!defined('PASSWORD_ARGON2ID')) throw new RuntimeException('PHP Argon2id is required.');

        $pdo = db();
        $hash = password_hash($authSecret, AUTH_HASH_ALGO, AUTH_HASH_OPTIONS);

        $stmt = $pdo->prepare('
            INSERT INTO users(username,auth_salt,auth_verifier,vault_salt,vault_wrap,recovery_wrap,recovery_public,created_at)
            VALUES(?,?,?,?,?,?,?,?)
        ');
        $stmt->execute([
            $username,
            $authSalt,
            $hash,
            $vaultSalt,
            $vaultWrap,
            $recoveryWrap,
            $recoveryPublic,
            time()
        ]);

        $id = (int)$pdo->lastInsertId();
        loginUser(['id' => $id, 'username' => $username]);

        echo json_encode(['ok'=>true, 'account_id'=>$id, 'username'=>$username]);
    } catch (Throwable $e) {
        $status = ($e instanceof PDOException && str_contains($e->getMessage(), 'UNIQUE')) ? 409 : 422;
        http_response_code($status);
        echo json_encode(['error' => $status === 409 ? 'Username is already in use.' : 'Could not create account.']);
    }
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="<?=htmlspecialchars(csrfToken(), ENT_QUOTES)?>">
<title>Create account — Vault Notes</title><link rel="stylesheet" href="style.css">
</head>
<body class="auth-page">
<main class="auth-card">
<div class="brand">Vault Notes</div><p class="sub">Create your private encrypted vault.</p>
<div id="error" class="alert error hidden"></div>
<form id="registerForm" class="stack">
<label>Username<input id="username" autocomplete="username" required maxlength="80" pattern="[A-Za-z0-9_.-]{3,80}"></label>
<label>Password<input id="password" type="password" autocomplete="new-password" required minlength="10"></label>
<label>Confirm password<input id="confirm" type="password" autocomplete="new-password" required></label>
<p class="hint">Use at least 10 characters. A long unique passphrase is better.</p>
<button class="btn primary full" id="registerBtn">Create vault</button>
</form>
<p class="auth-link"><a href="login.php">Already have an account?</a></p>
</main>
<script src="crypto-client.js"></script>
<script>
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const form = document.getElementById('registerForm');
const errorBox = document.getElementById('error');

function showError(m){ errorBox.textContent=m; errorBox.classList.remove('hidden'); }

form.addEventListener('submit', async (e)=>{
  e.preventDefault();
  errorBox.classList.add('hidden');
  const btn=document.getElementById('registerBtn');
  const username=document.getElementById('username').value.trim();
  const password=document.getElementById('password').value;
  const confirm=document.getElementById('confirm').value;
  if(password.length<10 || password.length>512){ showError('Password must be 10–512 characters.'); return; }
  if(password!==confirm){ showError('Passwords do not match.'); return; }

  btn.disabled=true; btn.textContent='Creating…';
  try {
    const authSalt = VaultCrypto.randomBytes(16);
    const vaultSalt = VaultCrypto.randomBytes(16);
    const vaultKey = VaultCrypto.randomBytes(32);
    const recovery = await VaultCrypto.createRecoveryKey();
    const keys = await VaultCrypto.derivePasswordKeys(password, VaultCrypto.b64e(authSalt), VaultCrypto.b64e(vaultSalt));
    const vaultWrap = await VaultCrypto.encryptBytes(vaultKey, keys.wrapKey, 'vault-wrap-v3');
    const recoveryWrap = await VaultCrypto.encryptBytes(vaultKey, recovery.aesKey, 'recovery-wrap-v3');

    const fd=new FormData();
    fd.append('csrf',csrf);
    fd.append('username',username);
    fd.append('auth_salt',VaultCrypto.b64e(authSalt));
    fd.append('auth_secret',VaultCrypto.b64e(keys.authSecret));
    fd.append('vault_salt',VaultCrypto.b64e(vaultSalt));
    fd.append('vault_wrap',vaultWrap);
    fd.append('recovery_wrap',recoveryWrap);
    fd.append('recovery_public',JSON.stringify(recovery.publicJwk));

    const r=await fetch('register.php',{method:'POST',body:fd,credentials:'same-origin'});
    const j=await r.json();
    if(!r.ok||j.error) throw new Error(j.error||'Registration failed.');

    VaultCrypto.setVaultKey(vaultKey);
    const payload=VaultCrypto.makeRecoveryPayload(j.username,j.account_id,recovery.privateJwk,recovery.publicJwk);
    VaultCrypto.downloadRecovery(payload,j.username);
    location.href='recovery.php?first=1';
  } catch(err) {
    showError(err.message||'Could not create account.');
  } finally {
    btn.disabled=false; btn.textContent='Create vault';
  }
});
</script>
</body></html>
