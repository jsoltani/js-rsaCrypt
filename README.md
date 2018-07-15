# js-rsaCrypt
rsa encryption and decryption in php

#Requirements
js-crypto Requires PHP >= 5.3.3

# Installation
## Using Composer
You can install this package using composer. Add this package to your composer.json:

```
"require": {
	"jsoltani/js-rsa-crypt": "dev-master"
}
```

or if you prefer command line, change directory to project root and:

```
php composer.phar require "jsoltani/js-rsa-crypt":"dev-master"
```

# Example Usage
```
$crypt = new jsRsaCrypt();

//$crypt->genKeys(512);
$crypt->setPublicKey('public.pem');
$crypt->setPrivateKey('private.pem');
$data = $crypt->encrypt("Test Crypt");

echo "Encrypt: $data <br>";
echo "Decrypt: " . $crypt->decrypt($data);
```
