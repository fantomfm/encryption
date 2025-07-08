# WhatsApp Media Encryption Library

[![PHP Version](https://img.shields.io/badge/php-8.1%2B-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

PHP library for stream encryption/decryption of media files with support for PSR-7 stream including WhatsApp.

## 🚀 Features

- 🔒 Stream-based AES-256-CBC encryption/decryption
- 📁 Supports all WhatsApp media types (images, videos, audio, documents)
- 🌊 PSR-7 stream decorators for memory-efficient processing
- 🔎 Sidecar generation for media verification
- 🧪 100% test coverage with unit and integration tests

## 📦 Installation

```bash
composer install
#composer require your-package/encryption
```

## 💻 Basic Usage

### Encryption
```php
use Encryption\Enum\MediaType;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use Encryption\Stream\EncryptedStreamDecorator;
use GuzzleHttp\Psr7\Stream;

// Prepare your media key and input stream
$mediaKey = '0123456789abcdef0123456789abcdef'; // 32-byte key
$inputStream = new Stream(fopen('input.jpg', 'r'));

// Create encryptor and decorator
$encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::IMAGE);
$encryptedStream = new EncryptedStreamDecorator($inputStream, $encryptor);

// Get encrypted content
$encryptedContent = $encryptedStream->getContents();
file_put_contents('encrypted.jpg', $encryptedContent);
```

### Decryption
```php
use Encryption\Enum\MediaType;
use Encryption\WhatsApp\WhatsAppMediaDecryptor;
use Encryption\Stream\DecryptedStreamDecorator;
use GuzzleHttp\Psr7\Stream;

// Prepare your media key and encrypted stream
$mediaKey = '0123456789abcdef0123456789abcdef'; // Same key used for encryption
$encryptedStream = new Stream(fopen('encrypted.jpg', 'r'));

// Create decryptor and decorator
$decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::IMAGE);
$decryptedStream = new DecryptedStreamDecorator($encryptedStream, $decryptor);

// Get decrypted content
$decryptedContent = $decryptedStream->getContents();
file_put_contents('decrypted.jpg', $decryptedContent);
```

### With Sidecar Generation
```php
use Encryption\Enum\MediaType;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use Encryption\WhatsApp\WhatsAppMediaStreamInfoGenerator;
use Encryption\Stream\EncryptedStreamDecorator;
use GuzzleHttp\Psr7\Stream;

$mediaKey = '0123456789abcdef0123456789abcdef';
$inputStream = new Stream(fopen('input.mp4', 'r'));

$encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::VIDEO);
$sidecarGenerator = new WhatsAppMediaStreamInfoGenerator(
    $encryptor->getMacKey(), 
    $encryptor->start()
);

$encryptedStream = new EncryptedStreamDecorator(
    $inputStream, 
    $encryptor,
    65536, // chunk size
    $sidecarGenerator
);

$encryptedContent = $encryptedStream->getContents();
$sidecar = $encryptedStream->getSidecar();

file_put_contents('encrypted.mp4', $encryptedContent);
file_put_contents('encrypted.mp4.sidecar', $sidecar);
```

### Chunked Processing
```php
$encryptedStream = new EncryptedStreamDecorator($stream, $encryptor, 8192);

while (!$encryptedStream->eof()) {
    $chunk = $encryptedStream->read(8192);
    // Process chunk...
}
```

## 🗂️ Media Types
Supported media types are defined in the MediaType enum:
```php
namespace Encryption\Enum;

enum MediaType: string
{
    case IMAGE = 'IMAGE';
    case VIDEO = 'VIDEO';
    case AUDIO = 'AUDIO';
    case DOCUMENT = 'DOCUMENT';
}
```

## ⚙️ Stream Decorators

### 🔒 EncryptedStreamDecorator
Decorates a readable stream to encrypt its contents:

- Implements PSR-7 StreamInterface
- Processes data in chunks for memory efficiency
- Supports sidecar generation
- Automatically handles finalization and MAC generation

### 🔓 DecryptedStreamDecorator
Decorates a readable stream to decrypt its contents:

- Implements PSR-7 StreamInterface
- Verifies MAC during decryption
- Processes data in chunks for memory efficiency
- Throws exceptions for invalid or tampered data

## ⚠️ Error Handling
The library throws specific exceptions for different error conditions:

- `CryptoException`: Base exception for cryptographic operations
- `DecryptionException`: Errors during decryption
- `EncryptionException`: Errors during encryption
- `InvalidMacException`: MAC verification failed
- `StreamException`: Stream-related errors

## 🧪 Testing
The library includes comprehensive unit and integration tests. To run tests:

```bash
composer test
# Runs 100+ tests including:
# - Unit tests for core crypto
# - Integration tests with real files
# - Stream compatibility tests
```

## 🚀 Performance Considerations
- For large files, use chunked reading/writing to minimize memory usage.
- The default chunk size (65536 bytes) provides a good balance between performance and memory usage.
- Stream processing ensures constant memory usage regardless of file size.

## 🛡️ Security Considerations
- Always use cryptographically secure random media keys.
- Never reuse media keys for different files.
- The library uses AES-256-CBC encryption with HMAC-SHA256 for authentication.

## 📜 License

MIT - See [LICENSE](https://en.wikipedia.org/wiki/MIT_License) for details.
