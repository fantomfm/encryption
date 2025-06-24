<?php

namespace Encryption;

use Encryption\Enum\MediaType;
use Encryption\Exception\EncryptionException;
use http\Exception\InvalidArgumentException;
use HashContext;

class WhatsAppMediaEncryptor implements Interface\MediaEncryptorInterface
{
    private const BLOCK_SIZE = 16;
    private const MAC_SIZE = 10;
    private const KEY_EXPANSION_LENGTH = 112;

    private string $iv;
    private string $cipherKey;
    private string $macKey;

    private ?HashContext $hmacContext = null;
    private ?string $currentIv = null;
    private bool $finalized = false;

    public function __construct(string $mediaKey, MediaType $mediaType)
    {
        if (mb_strlen($mediaKey, '8bit') !== 32) {
            throw new InvalidArgumentException('mediaKey must be 32 bytes');
        }

        $mediaKeyExpanded = self::expandMediaKey($mediaKey, self::KEY_EXPANSION_LENGTH, $mediaType);

        [$this->iv, $this->cipherKey, $this->macKey] = self::splitExpandedKey($mediaKeyExpanded);

        $this->currentIv = $this->iv;

        $this->hmacContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->hmacContext, $this->iv);
    }

    public function start(): string
    {
        return $this->iv;
    }

    public function update(string $chunk): string
    {
        if ($this->finalized) {
            throw new EncryptionException("Encryption already finalized");
        }

        return $this->encryptChunk($chunk);
    }

    public function finish(string $chunk = ''): string
    {
        if ($this->finalized) {
            return '';
        }

        $encrypted = $this->encryptChunk($chunk);
        $this->finalized = true;

        $mac = substr(hash_final($this->hmacContext, true), 0, self::MAC_SIZE);

        return $encrypted . $mac;
    }

    private static function expandMediaKey(string $mediaKey, int $length, MediaType $mediaType): string
    {
        if (mb_strlen($mediaKey, '8bit') !== 32) {
            throw new InvalidArgumentException('mediaKey must be 32 bytes long');
        }

        return hash_hkdf(
            'sha256',
            $mediaKey,
            $length,
            $mediaType->getWhatsAppMediaInfo()
        );
    }

    private static function splitExpandedKey(string $expandedKey): array
    {
        if (mb_strlen($expandedKey, '8bit') !== self::KEY_EXPANSION_LENGTH) {
            throw new InvalidArgumentException(
                sprintf("Expanded key must be %s bytes long", self::KEY_EXPANSION_LENGTH)
            );
        }

        $iv = substr($expandedKey, 0, self::BLOCK_SIZE);               // 16 bytes
        $cipherKey = substr($expandedKey, self::BLOCK_SIZE, 32);       // 32 bytes
        $macKey = substr($expandedKey, 48, 32);          // 32 bytes

        return [$iv, $cipherKey, $macKey];
    }

    private function encryptChunk(string $chunk): string
    {
        $data = $chunk !== '' ? $this->addPadding($chunk) : '';

        $encrypted = openssl_encrypt(
            $data,
            'AES-256-CBC',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $this->currentIv
        );

        if ($encrypted === false) {
            throw EncryptionException::createFromOpenSSLError();
        }

        hash_update($this->hmacContext, $encrypted);

        $this->currentIv = substr($encrypted, -self::BLOCK_SIZE);

        return $encrypted;
    }

    private function addPadding(string $data): string
    {
        $padLength = self::BLOCK_SIZE - (mb_strlen($data, '8bit') % self::BLOCK_SIZE);
        if ($padLength === 0) {
            $padLength = self::BLOCK_SIZE;
        }

        return $data . str_repeat(chr($padLength), $padLength);
    }
}
