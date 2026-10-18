<?php
require_once __DIR__ . '/auth.php';
$user=requireLogin();
$uStmt=db()->prepare('SELECT auth_salt FROM users WHERE id=?');
$uStmt->execute([$user['id']]);
$account=$uStmt->fetch();
if(!$account) exit('Account unavailable.');

if($_SERVER['REQUEST_METHOD']==='POST'){
    header('Content-Type: application/json; charset=utf-8');
    try{
        verifyCsrf();
        $oldAuth=(string)($_POST['old_auth_secret']??'');
        $newAuth=(string)($_POST['new_auth_secret']??'');
        $newAuthSalt=(string)($_POST['new_auth_salt']??'');
        $newVaultSalt=(string)($_POST['new_vault_salt']??'');
        $newVaultWrap=(string)($_POST['new_vault_wrap']??'');

        if(!validB64Bytes($oldAuth,32)||!validB64Bytes($newAuth,32)) throw new RuntimeException();
        if(!validB64Bytes($newAuthSalt,16)||!validB64Bytes($newVaultSalt,16)) throw new RuntimeException();
        if($newVaultWrap==='') throw new RuntimeException();

        $s=db()->prepare('SELECT auth_verifier FROM users WHERE id=?');
        $s->execute([$user['id']]); $row=$s->fetch();
        if(!$row || !password_verify($oldAuth,$row['auth_verifier'])) throw new RuntimeException('Invalid current password.');

        $newVerifier=password_hash($newAuth,AUTH_HASH_ALGO,AUTH_HASH_OPTIONS);
        db()->prepare('UPDATE users SET auth_salt=?,auth_verifier=?,vault_salt=?,vault_wrap=? WHERE id=?')
          ->execute([$newAuthSalt,$newVerifier,$newVaultSalt,$newVaultWrap,(int)$user['id']]);

        echo json_encode(['ok'=>true]);
    }catch(Throwable $e){
        http_response_code(422);
        echo json_encode(['error'=>$e->getMessage()==='Invalid current password.'?'Invalid current password.':'Could not change password.']);
    }
    exit;
}
?>
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="<?=htmlspecialchars(csrfToken(),ENT_QUOTES)?>">
<meta name="auth-salt" content="<?=htmlspecialchars($account['auth_salt'],ENT_QUOTES)?>">
<title>Account — Vault Notes</title><link rel="stylesheet" href="style.css"></head>
<body class="auth-page"><main class="auth-card">
<div class="brand">Account</div><p class="sub"><?=htmlspecialchars($user['username'])?></p>
<div id="error" class="alert error hidden"></div><div id="success" class="alert success hidden"></div>
<form id="accountForm" class="stack">
<label>Current password<input id="oldPassword" type="password" autocomplete="current-password" required></label>
<label>New password<input id="newPassword" type="password" minlength="10" autocomplete="new-password" required></label>
<label>Confirm new password<input id="confirm" type="password" minlength="10" autocomplete="new-password" required></label>
<button class="btn primary full" id="saveBtn">Change password</button>
</form>
<p class="hint">The vault key does not change. Only its password wrapper and authentication verifier are replaced.</p>
<a class="btn ghost full" href="index.php">Back to notes</a>
</main>
<script src="crypto-client.js"></script>
<script>
const csrf=document.querySelector('meta[name="csrf-token"]').content;
const authSalt=document.querySelector('meta[name="auth-salt"]').content;
const form=document.getElementById('accountForm'), errorBox=document.getElementById('error'), successBox=document.getElementById('success');
function show(box,m){box.textContent=m;box.classList.remove('hidden');}
form.addEventListener('submit',async e=>{
 e.preventDefault(); errorBox.classList.add('hidden'); successBox.classList.add('hidden');
 const oldP=document.getElementById('oldPassword').value;
 const newP=document.getElementById('newPassword').value;
 const confirm=document.getElementById('confirm').value;
 if(newP.length<10||newP.length>512){show(errorBox,'New password must be 10–512 characters.');return;}
 if(newP!==confirm){show(errorBox,'Passwords do not match.');return;}
 const vaultKey=VaultCrypto.getVaultKey();
 if(!vaultKey){location.href='login.php';return;}
 const btn=document.getElementById('saveBtn');btn.disabled=true;btn.textContent='Changing…';
 try{
   const oldAuth=await VaultCrypto.deriveAuthSecret(oldP,authSalt);
   const newAuthSalt=VaultCrypto.randomBytes(16), newVaultSalt=VaultCrypto.randomBytes(16);
   const newKeys=await VaultCrypto.derivePasswordKeys(newP,VaultCrypto.b64e(newAuthSalt),VaultCrypto.b64e(newVaultSalt));
   const wrap=await VaultCrypto.encryptBytes(vaultKey,newKeys.wrapKey,'vault-wrap-v3');
   const fd=new FormData();
   fd.append('csrf',csrf);fd.append('old_auth_secret',VaultCrypto.b64e(oldAuth));
   fd.append('new_auth_secret',VaultCrypto.b64e(newKeys.authSecret));
   fd.append('new_auth_salt',VaultCrypto.b64e(newAuthSalt));
   fd.append('new_vault_salt',VaultCrypto.b64e(newVaultSalt));
   fd.append('new_vault_wrap',wrap);
   const r=await fetch('account.php',{method:'POST',body:fd,credentials:'same-origin'});
   const j=await r.json();if(!r.ok||j.error)throw new Error(j.error||'Could not change password.');
   show(successBox,'Password changed successfully. Your recovery file is still valid.');
   form.reset();
 }catch(err){show(errorBox,err.message||'Could not change password.');}
 finally{btn.disabled=false;btn.textContent='Change password';}
});
</script>
</body></html>
