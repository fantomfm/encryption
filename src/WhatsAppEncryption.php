<?php

declare(strict_types=1);

namespace Encryption;

use Encryption\Enum\MediaType;
use Encryption\Exception\DecryptionException;
use Encryption\Exception\EncryptionException;
use Encryption\Exception\InvalidMacException;
use Encryption\Interface\EncryptionInterface;

class WhatsAppEncryption implements EncryptionInterface
{
    private const BLOCK_SIZE = 16; // AES block size in bytes
    private const MAC_LENGTH = 10;
    private const KEY_EXPANSION_LENGTH = 112;

    public function encrypt(string $data, string $mediaKey, MediaType $mediaType): string
    {
        // Extending the key to 112 bytes using HKDF
        $mediaKeyExpanded = $this->expandMediaKey($mediaKey, $mediaType);

        if ($mediaKeyExpanded === false) {
            throw new EncryptionException('HKDF generation error');
        }

        [$iv, $cipherKey, $macKey] = $this->splitExpandedKey($mediaKeyExpanded);

        // PKCS7 padding
        $padded = $this->addPadding($data);

        // Encrypt with AES-CBC
        $enc = openssl_encrypt(
            $padded,
            'AES-256-CBC',
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($enc === false) {
            throw EncryptionException::createFromOpenSSLError();
        }

        // Calculate HMAC-SHA256 of IV + encrypted data
        $hmac = hash_hmac('sha256', $iv . $enc, $macKey, true);
        $mac = substr($hmac, 0, self::MAC_LENGTH);

        return $enc . $mac;
    }

    public function decrypt(string $data, string $mediaKey, MediaType $mediaType): string
    {
        if (strlen($data) < self::MAC_LENGTH) {
            throw new \InvalidArgumentException('The data is too short to extract MAC');
        }
        
        // Extending the key to 112 bytes using HKDF
        $mediaKeyExpanded = $this->expandMediaKey($mediaKey, $mediaType);

        if ($mediaKeyExpanded === false) {
            throw new EncryptionException('HKDF generation error');
        }

        [$iv, $cipherKey, $macKey] = $this->splitExpandedKey($mediaKeyExpanded);

        // Split encrypted data and MAC
        $mac = substr($data, -self::MAC_LENGTH);
        $file = substr($data, 0, -self::MAC_LENGTH);

        $calculatedHmac = hash_hmac('sha256', $iv . $file, $macKey, true);
        $calculatedMac = substr($calculatedHmac, 0, self::MAC_LENGTH);

        if (!hash_equals($mac, $calculatedMac)) {
            throw new InvalidMacException('MAC validation failed');
        }

        $decrypted = openssl_decrypt(
            $file,
            'AES-256-CBC',
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($decrypted === false) {
            throw DecryptionException::createFromOpenSSLError();
        }

        return $this->removePadding($decrypted);
    }

    public function generateStreamingInfo(string $encryptedData, string $mediaKey, MediaType $mediaType): string
    {
        // $expandedKey = $this->expandKey($mediaKey, $mediaType);
        // [, , $macKey] = $this->splitExpandedKey($expandedKey);

        // $sidecar = '';
        // $chunkSize = 64 * 1024; // 64KB
        // $length = strlen($encryptedData);

        // for ($i = 0; $i < $length; $i += $chunkSize) {
        //     // Take chunk of [n*64K, (n+1)*64K+16]
        //     $endPosition = min($i + $chunkSize + self::BLOCK_SIZE, $length);
        //     $chunk = substr($encryptedData, $i, $endPosition - $i);

        //     // Sign with macKey and take first 10 bytes
        //     $hmac = hash_hmac('sha256', $chunk, $macKey, true);
        //     $sidecar .= substr($hmac, 0, self::MAC_LENGTH);
        // }

        // return $sidecar;
        
        return '';
    }

    private function expandMediaKey(string $mediaKey, MediaType $mediaType): string
    {
        if (strlen($mediaKey) !== 32) {
            throw new \InvalidArgumentException('mediaKey must be 32 bytes long');
        }
        
        return hash_hkdf(
            'sha256',
            $mediaKey,
            self::KEY_EXPANSION_LENGTH,
            $mediaType->getWhatsAppMediaInfo(),
        );
    }

    private function splitExpandedKey(string $expandedKey): array
    {
        if (strlen($expandedKey) !== self::KEY_EXPANSION_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf("Expanded key must be %s bytes long", self::KEY_EXPANSION_LENGTH)
            );
        }

        $iv = substr($expandedKey, 0, 16);               // 16 bytes
        $cipherKey = substr($expandedKey, 16, 32);       // 32 bytes
        $macKey = substr($expandedKey, 48, 32);          // 32 bytes
        
        return [$iv, $cipherKey, $macKey];
    }

    private function addPadding(string $data): string
    {
        $padLength = self::BLOCK_SIZE - (strlen($data) % self::BLOCK_SIZE);

        return $data . str_repeat(chr($padLength), $padLength);
    }

    private function removePadding(string $data): string
    {
        $length = strlen($data);
        $pad = ord($data[$length - 1]);

        if ($pad > self::BLOCK_SIZE) {
            throw new DecryptionException('Incorrect PKCS#7 padding');
        }

        return substr($data, 0, $length - $pad);
    }
}