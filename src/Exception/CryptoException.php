<?php

namespace Encryption\Exception;

use RuntimeException;

class CryptoException extends RuntimeException
{
    public static function createFromOpenSSLError(): self
    {
        $error = openssl_error_string() ?: 'Unknown OpenSSL error';
        return new self("OpenSSL error: $error");
    }
}