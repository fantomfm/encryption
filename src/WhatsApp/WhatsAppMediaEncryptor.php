<?php

declare(strict_types=1);

namespace Encryption\WhatsApp;

use Encryption\Exception\EncryptionException;

class WhatsAppMediaEncryptor extends WhatsAppMediaCipher
{
    private string $buffer = '';

    public function update(string $chunk): string
    {
        if ($this->finalized) {
            throw new EncryptionException("Encryption already finalized");
        }

        if (mb_strlen($this->buffer, '8bit') > 65536) {
            throw new EncryptionException("Buffer size exceeded maximum limit");
        }

        $this->buffer .= $chunk;

        $len = mb_strlen($this->buffer, '8bit');
        $blocks = (int)($len / self::BLOCK_SIZE);

        if ($blocks === 0) {
            return '';
        }

        $toEncrypt = substr($this->buffer, 0, $blocks * self::BLOCK_SIZE);
        $this->buffer = substr($this->buffer, $blocks * self::BLOCK_SIZE);

        return $this->encryptChunk($toEncrypt);
    }

    public function finish(string $chunk = ''): string
    {
        if ($this->finalized) {
            return '';
        }

        $data = $this->buffer . $chunk;
        $this->buffer = '';

        $padded = $this->addPadding($data);

        $encrypted = $this->encryptChunk($padded);
        $this->finalized = true;

        $mac = substr(hash_final($this->hmacContext, true), 0, self::MAC_SIZE);
        $this->hmacContext = null;

        return $encrypted . $mac;
    }

    private function encryptChunk(string $chunk): string
    {
        if ($chunk === '') {
            return '';
        }

        $len = mb_strlen($chunk, '8bit');

        if ($len % self::BLOCK_SIZE !== 0) {
            throw new EncryptionException("Data length must be multiple of block size");
        }

        $encrypted = openssl_encrypt(
            $chunk,
            'AES-256-CBC',
            $this->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
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
        // if ($padLength === 0) {
        //     $padLength = self::BLOCK_SIZE;
        // }

        return $data . str_repeat(chr($padLength), $padLength);
    }
}
