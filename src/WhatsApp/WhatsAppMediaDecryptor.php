<?php

namespace Encryption\WhatsApp;

use Encryption\Exception\DecryptionException;
use Encryption\Exception\InvalidMacException;

class WhatsAppMediaDecryptor extends WhatsAppMediaCipher
{
    private string $buffer = '';

    public function update(string $chunk): string
    {
        if ($this->finalized) {
            return '';
        }

        $this->buffer .= $chunk;

        $len = mb_strlen($this->buffer, '8bit');
        $blocks = (int)($len / self::BLOCK_SIZE);

        if ($blocks === 0) {
            return '';
        }

        $toDecrypt = substr($this->buffer, 0, $blocks * self::BLOCK_SIZE);
        $this->buffer = substr($this->buffer, $blocks * self::BLOCK_SIZE);

        hash_update($this->hmacContext, $toDecrypt);

        $len = mb_strlen($toDecrypt, '8bit');
        if ($len % self::BLOCK_SIZE !== 0) {
            throw new DecryptionException("Encrypted data length must be multiple of block size");
        }

        $decrypted = openssl_decrypt(
            $toDecrypt,
            'AES-256-CBC',
            $this->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->currentIv
        );

        if ($decrypted === false) {
            throw DecryptionException::createFromOpenSSLError();
        }

        $this->currentIv = substr($toDecrypt, -self::BLOCK_SIZE);

        return $decrypted;
    }

    public function finish(string $chunk = ''): string
    {
        if ($this->finalized) {
            return '';
        }

        $this->buffer .= $chunk;

        if (mb_strlen($this->buffer, '8bit') < self::MAC_SIZE) {
            throw new InvalidMacException('Not enough data to extract MAC');
        }

        $encryptedData = substr($this->buffer, 0, -self::MAC_SIZE);
        $receivedMac = substr($this->buffer, -self::MAC_SIZE);

        hash_update($this->hmacContext, $encryptedData);
        $expectedMac = substr(hash_final($this->hmacContext, true), 0, self::MAC_SIZE);

        if (!hash_equals($expectedMac, $receivedMac)) {
            throw new InvalidMacException('HMAC verification failed');
        }

        $len = mb_strlen($encryptedData, '8bit');
        if ($len % self::BLOCK_SIZE !== 0) {
            throw new DecryptionException("Encrypted data length must be multiple of block size");
        }

        $decrypted = openssl_decrypt(
            $encryptedData,
            'AES-256-CBC',
            $this->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->currentIv
        );

        if ($decrypted === false) {
            throw DecryptionException::createFromOpenSSLError();
        }

        $this->finalized = true;

        return $this->removePadding($decrypted);
    }

    private function removePadding(string $data): string
    {
        $len = mb_strlen($data, '8bit');

        if ($len === 0 || $len % self::BLOCK_SIZE !== 0) {
            throw new DecryptionException('Invalid data length or padding');
        }

        $padLength = ord($data[$len - 1]);

        if ($padLength <= 0 || $padLength > self::BLOCK_SIZE) {
            throw new DecryptionException('Invalid padding');
        }

        $padding = substr($data, -$padLength);
        if ($padding !== str_repeat(chr($padLength), $padLength)) {
            throw new DecryptionException('Invalid padding bytes');
        }

        return substr($data, 0, $len - $padLength);
    }
}
