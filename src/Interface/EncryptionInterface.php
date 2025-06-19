<?php

declare(strict_types=1);

namespace Encryption\Interface;

use Encryption\Enum\MediaType;
use Encryption\Exception\InvalidMacException;

interface EncryptionInterface
{
    public function encrypt(string $data, string $mediaKey, MediaType $mediaType): string;

    /**
     * @throws InvalidMacException If MAC validation fails
     */
    public function decrypt(string $data, string $mediaKey, MediaType $mediaType): string;

    public function generateStreamingInfo(string $encryptedData, string $mediaKey, MediaType $mediaType): string;
}