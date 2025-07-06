<?php

declare(strict_types=1);

namespace Encryption\WhatsApp;

use Encryption\Enum\MediaType;
use Encryption\Interface\MediaCipherInterface;
use InvalidArgumentException;
use HashContext;

abstract class WhatsAppMediaCipher implements MediaCipherInterface
{
    protected const BLOCK_SIZE = 16;
    protected const MAC_SIZE = 10;
    protected const KEY_EXPANSION_LENGTH = 112;

    protected string $iv;
    protected string $cipherKey;
    protected string $macKey;

    protected ?HashContext $hmacContext = null;
    protected ?string $currentIv = null;
    protected bool $finalized = false;

    public function __construct(string $mediaKey, MediaType $mediaType)
    {
        if (mb_strlen($mediaKey, '8bit') !== 32) {
            throw new InvalidArgumentException('mediaKey must be 32 bytes long');
        }

        $mediaKeyExpanded = $this->expandMediaKey($mediaKey, self::KEY_EXPANSION_LENGTH, $mediaType);

        [$this->iv, $this->cipherKey, $this->macKey] = $this->splitExpandedKey($mediaKeyExpanded);

        $this->currentIv = $this->iv;

        $this->initHmac();
    }

    private function initHmac(): void
    {
        $this->hmacContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->hmacContext, $this->iv);
    }

    public function start(): string
    {
        return $this->iv;
    }

    final protected function expandMediaKey(string $mediaKey, int $length, MediaType $mediaType): string
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

    final protected function splitExpandedKey(string $expandedKey): array
    {
        if (mb_strlen($expandedKey, '8bit') !== self::KEY_EXPANSION_LENGTH) {
            throw new InvalidArgumentException(
                sprintf("Expanded key must be %s bytes long", self::KEY_EXPANSION_LENGTH)
            );
        }

        $iv = substr($expandedKey, 0, self::BLOCK_SIZE);            // 16 bytes
        $cipherKey = substr($expandedKey, self::BLOCK_SIZE, 32);    // 32 bytes
        $macKey = substr($expandedKey, 48, 32);                     // 32 bytes

        return [$iv, $cipherKey, $macKey];
    }

    public function getBlockSize(): int
    {
        return self::BLOCK_SIZE;
    }

    public function getMacSize(): int
    {
        return self::MAC_SIZE;
    }
}
