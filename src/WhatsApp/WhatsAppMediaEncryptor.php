<?php

namespace Encryption\WhatsApp;

use Encryption\Exception\EncryptionException;

class WhatsAppMediaEncryptor extends WhatsAppMediaCipher
{
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
        $this->hmacContext = null;

        return $encrypted . $mac;
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
