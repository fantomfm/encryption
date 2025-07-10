<?php

declare(strict_types=1);

namespace Encryption\WhatsApp;

use Encryption\Exception\DecryptionException;
use Encryption\Exception\InvalidMacException;

class WhatsAppMediaDecryptor extends WhatsAppMediaCipher
{
    private string $buffer = '';

    public function update(string $chunk): string
    {
        if ($this->finalized) {
            throw new DecryptionException("Decryption already finalized");
        }

        if (mb_strlen($this->buffer, '8bit') > 65536) {
            throw new DecryptionException("Buffer size exceeded maximum limit");
        }

        $this->buffer .= $chunk;

        $len = mb_strlen($this->buffer, '8bit');
        $blocks = (int)($len / self::BLOCK_SIZE);

        if ($blocks === 0) {
            return '';
        }

        $toDecrypt = substr($this->buffer, 0, $blocks * self::BLOCK_SIZE);
        $this->buffer = substr($this->buffer, $blocks * self::BLOCK_SIZE);

        return $this->decryptChunk($toDecrypt);
    }

    public function finish(string $chunk = ''): string
    {
        if ($this->finalized) {
            return '';
        }

        $data = $this->buffer . $chunk;
        $this->buffer = '';

        if (mb_strlen($data, '8bit') < self::MAC_SIZE) {
            throw new DecryptionException("Final chunk is too small to contain encrypted data and MAC");
        }

        $encryptedData = substr($data, 0, -self::MAC_SIZE);
        $receivedMac = substr($data, -self::MAC_SIZE);

        $decrypted = $this->decryptChunk($encryptedData);
        $this->finalized = true;

        $calculatedMac = substr(hash_final($this->hmacContext, true), 0, self::MAC_SIZE);
        $this->hmacContext = null;

        if (!hash_equals($calculatedMac, $receivedMac)) {
            throw new InvalidMacException("MAC verification failed");
        }

        return $this->removePadding($decrypted);
    }

    private function decryptChunk(string $chunk): string
    {
        if ($chunk === '') {
            return '';
        }

        $len = mb_strlen($chunk, '8bit');

        if ($len % self::BLOCK_SIZE !== 0) {
            throw new DecryptionException("Data length must be multiple of block size");
        }

        $decrypted = openssl_decrypt(
            $chunk,
            'AES-256-CBC',
            $this->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->currentIv
        );

        if ($decrypted === false) {
            throw DecryptionException::createFromOpenSSLError();
        }

        hash_update($this->hmacContext, $chunk);

        $this->currentIv = substr($chunk, -self::BLOCK_SIZE);

        return $decrypted;
    }

    private function removePadding(string $data): string
    {
        $len = mb_strlen($data, '8bit');
        if ($len === 0) {
            return '';
        }

        $padLength = ord($data[$len - 1]);
        if ($padLength > self::BLOCK_SIZE || $padLength <= 0) {
            throw new DecryptionException("Invalid padding");
        }

        for ($i = 1; $i <= $padLength; $i++) {
            if (ord($data[$len - $i]) !== $padLength) {
                throw new DecryptionException("Invalid padding");
            }
        }

        return substr($data, 0, -$padLength);
    }
}
