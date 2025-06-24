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

        if (mb_strlen($this->buffer, '8bit') < self::BLOCK_SIZE) {
            return '';
        }

        $decryptLength = mb_strlen($this->buffer, '8bit') - self::BLOCK_SIZE;
        if ($decryptLength > 0) {
            $toDecrypt = substr($this->buffer, 0, $decryptLength);
            $this->buffer = substr($this->buffer, $decryptLength);

            hash_update($this->hmacContext, $toDecrypt);

            $decrypted = openssl_decrypt(
                $toDecrypt,
                'AES-256-CBC',
                $this->cipherKey,
                OPENSSL_RAW_DATA,
                $this->currentIv
            );

            if ($decrypted === false) {
                throw DecryptionException::createFromOpenSSLError();
            }

            $this->currentIv = substr($toDecrypt, -self::BLOCK_SIZE);

            // if ($decryptLength < self::BLOCK_SIZE) {
                var_dump('$decryptLength < self::BLOCK_SIZE');
                $decrypted = $this->removePadding($decrypted);
            // }

            return $decrypted;
        }

        return '';
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

        $decrypted = openssl_decrypt(
            $encryptedData,
            'AES-256-CBC',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
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

        if ($len === 0) {
            return '';
        }

        $padLength = ord($data[$len - 1]);

        if ($padLength <= 0 || $padLength > self::BLOCK_SIZE) {
            throw new DecryptionException('Invalid padding');
        }

        $padding = substr($data, -1 * $padLength);
        if ($padding !== str_repeat(chr($padLength), $padLength)) {
            throw new DecryptionException('Invalid padding bytes');
        }

        return substr($data, 0, $len - $padLength);
    }
}