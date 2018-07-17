## vaultlib

A simple Vault client for PHP making use of Guzzle for HTTP API requests.

### Installation

Install via Composer:

```
composer require psecio/vaultlib
```

### Usage:

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$accessToken = "[... token from Vault account ...]";
$baseUrl = "https://your-vault-server:8200";

$client = new \Psecio\Vaultlib\Client($accessToken, $baseUrl);

// Check for seal
if ($client->isSealed() == true) {
    echo 'The vault is sealed';
}

// Get a secret value
$secret = 'secretName';
$result = $client->getSecret($secret);

/// Delete a secret value
$client->deleteSecret($secret);

// Set a secret value
$client->setSecret($secret, ['testing1' => 'foo']);
?>
```
