<?php

declare(strict_types=1);

namespace Encryption\WhatsApp;

use Encryption\Exception\EncryptionException;
use Encryption\Interface\MediaStreamInfoGeneratorInterface;
use http\Exception\InvalidArgumentException;

class WhatsAppMediaStreamInfoGenerator implements MediaStreamInfoGeneratorInterface
{
    private const CHUNK_SIZE = 65536;
    private const IV_SIZE = 16;
    private const SIGNATURE_SIZE = 10;

    private string $sidecar = '';
    private string $buffer = '';
    private string $overlap = '';
    protected bool $finalized = false;
    private bool $isFirstChunk = true;

    public function __construct(private string $macKey, private string $iv)
    {
        if (mb_strlen($iv, '8bit') !== self::IV_SIZE) {
            throw new InvalidArgumentException('IV must be 16 bytes long');
        }
    }

    public function update(string $chunk): string
    {
        if ($this->finalized) {
            throw new EncryptionException("Generator already finalized");
        }

        $this->buffer .= $chunk;

        while (mb_strlen($this->buffer, '8bit') >= self::CHUNK_SIZE) {
            $chunkToProcess = substr($this->buffer, 0, self::CHUNK_SIZE);
            $this->buffer = substr($this->buffer, self::CHUNK_SIZE);

            $this->processChunk($chunkToProcess);
        }

        return '';
    }

    public function finish(string $chunk = ''): string
    {
        if ($this->finalized) {
            return $this->sidecar;
        }

        // Process remaining data
        $remainingData = $this->buffer . $chunk;
        if (!empty($remainingData)) {
            $this->processChunk($remainingData);
        }

        $this->finalized = true;

        return $this->sidecar;
    }

    public function getSidecar(): string
    {
        return $this->sidecar;
    }

    private function processChunk(string $chunk): void
    {
        if ($this->isFirstChunk) {
            $dataToSign = $this->iv . $chunk;
            $this->isFirstChunk = false;
        } else {
            $dataToSign = $this->overlap . $chunk;
        }

        $this->overlap = substr($chunk, -self::IV_SIZE);

        $mac = hash_hmac('sha256', $dataToSign, $this->macKey, true);
        $this->sidecar .= substr($mac, 0, self::SIGNATURE_SIZE);
    }
}
