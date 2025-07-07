<?php

declare(strict_types=1);

namespace Encryption\Stream;

use Encryption\Exception\StreamException;
use Encryption\Interface\MediaCipherInterface;
use Encryption\Interface\MediaStreamInfoGeneratorInterface;
use Psr\Http\Message\StreamInterface;
use InvalidArgumentException;

class EncryptedStreamDecorator implements StreamInterface
{
    use StreamDecoratorTrait;

    private string $buffer = '';
    private bool $finalized = false;
    private int $position = 0;
    private bool $sourceEof = false;
    private int $blockSize;

    public function __construct(
        private StreamInterface $stream,
        private MediaCipherInterface $encryptor,
        private int $chunkSize = 65536,
        private ?MediaStreamInfoGeneratorInterface $sidecar = null
    ) {
        if (!$stream->isReadable()) {
            throw new InvalidArgumentException('Stream must be readable');
        }

        $this->blockSize = $this->encryptor->getBlockSize();

        if ($chunkSize < $this->blockSize) {
            throw new InvalidArgumentException(sprintf(
                'Chunk size must be at least %d bytes',
                $this->blockSize
            ));
        }
    }

    public function read(int $length): string
    {
        if ($this->eof()) {
            return '';
        }

        $readSize = $this->calculateReadSize($length);

        if (mb_strlen($this->buffer, '8bit') >= $length) {
            return $this->extractFromBuffer($length);
        }

        while (mb_strlen($this->buffer, '8bit') < $length && !$this->sourceEof) {
            $chunk = $this->stream->read($readSize);

            if (empty($chunk)) {
                $this->sourceEof = true;
                $encrypted = $this->finalize();
                $this->buffer .= $encrypted;
                break;
            }

            $this->buffer .= $this->update($chunk);
        }

        return $this->extractFromBuffer($length);
    }

    public function getContents(): string
    {
        if ($this->eof()) {
            return '';
        }

        $result = $this->buffer;
        $this->buffer = '';

        if ($this->stream->getSize() !== null && $this->stream->getSize() <= $this->chunkSize) {
            $data = $this->stream->getContents();
            $result = $this->update($data) . $this->finalize();

            $this->position += mb_strlen($result, '8bit');

            $this->sourceEof = true;

            return $result;
        }

        while (!$this->eof()) {
            $result .= $this->read($this->chunkSize);
        }

        return $result;
    }

    public function getSidecar(): string
    {
        if (!$this->sidecar) {
            throw new StreamException('Sidecar generation was not enabled');
        }

        return $this->sidecar->getSidecar();
    }

    private function update($data): string
    {
        $encrypted = $this->encryptor->update($data);
        $this->sidecar?->update($encrypted);

        return $encrypted;
    }

    private function finalize(): string
    {
        if ($this->finalized) {
            return '';
        }

        $this->finalized = true;

        $finalizedData = $this->encryptor->finish();

        $this->sidecar?->update($finalizedData);
        $this->sidecar?->finish();

        return $finalizedData;
    }

    private function calculateReadSize(int $requested): int
    {
        return min(
            max($requested, $this->blockSize),
            $this->chunkSize
        );
    }

    private function extractFromBuffer(int $length): string
    {
        $result = substr($this->buffer, 0, $length);

        if ($result === false) {
            throw new StreamException('Failed to extract data from buffer');
        }

        $this->buffer = substr($this->buffer, $length);
        $this->position += mb_strlen($result, '8bit');

        return $result;
    }
}
