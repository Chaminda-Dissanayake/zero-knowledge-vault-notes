<?php
require_once __DIR__ . '/auth.php';
logoutUser();
?>
<!doctype html><html><body>
<script>try{sessionStorage.removeItem('vaultKey');}catch(e){} location.replace('login.php');</script>
<noscript><a href="login.php">Continue to login</a></noscript>
</body></html>
