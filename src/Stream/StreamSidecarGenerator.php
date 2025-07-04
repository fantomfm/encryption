<?php

declare(strict_types=1);

namespace Encryption\Stream;

use HashContext;
use InvalidArgumentException;

class StreamSidecarGenerator
{
    private const BLOCK_SIZE = 16;
    private const MAC_SIZE = 10;

    private string $macKey;
    private string $buffer = '';
    private string $sidecar = '';
    private ?HashContext $hmacContext = null;

    public function __construct(string $macKey)
    {
        if (mb_strlen($macKey, '8bit') !== 32) {
            throw new InvalidArgumentException('macKey must be 32 bytes long');
        }
        $this->macKey = $macKey;
        $this->initHmac();
    }

    private function initHmac(): void
    {
        $this->hmacContext = hash_init('sha256', HASH_HMAC, $this->macKey);
    }

    public function processChunk(string $chunk): string
    {
        $this->buffer .= $chunk;
        $len = mb_strlen($this->buffer, '8bit');
        $blocks = (int)($len / self::BLOCK_SIZE);

        for ($i = 0; $i < $blocks; $i++) {
            $block = substr($this->buffer, $i * self::BLOCK_SIZE, self::BLOCK_SIZE);
            hash_update($this->hmacContext, $block);
            $mac = substr(hash_final($this->hmacContext, true), 0, self::MAC_SIZE);
            $this->sidecar .= $mac;
            $this->initHmac();
        }

        $this->buffer = substr($this->buffer, $blocks * self::BLOCK_SIZE);

        return $this->sidecar;
    }

    public function finalize(): string
    {
        if (!empty($this->buffer)) {
            $padded = $this->addPadding($this->buffer);
            hash_update($this->hmacContext, $padded);
            $mac = substr(hash_final($this->hmacContext, true), 0, self::MAC_SIZE);
            $this->sidecar .= $mac;
        }
        return $this->sidecar;
    }

    private function addPadding(string $data): string
    {
        $padLength = self::BLOCK_SIZE - (mb_strlen($data, '8bit') % self::BLOCK_SIZE);
        return $data . str_repeat(chr($padLength), $padLength);
    }

    public function getSidecar(): string
    {
        return $this->sidecar;
    }
}