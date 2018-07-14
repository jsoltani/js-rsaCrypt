<?php

require_once '../vendor/autoload.php';

$crypt = new jsRsaCrypt();

//$crypt->genKeys(512);
$crypt->setPublicKey('public.pem');
$crypt->setPrivateKey('private.pem');
$data = $crypt->encrypt("Test Crypt");

echo "Encrypt: $data <br>";
echo "Decrypt: " . $crypt->decrypt($data);
