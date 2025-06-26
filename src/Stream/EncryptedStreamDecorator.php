<?php

declare(strict_types=1);

namespace Encryption\Stream;

use Encryption\Exception\StreamException;
use Encryption\Interface\MediaCipherInterface;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use InvalidArgumentException;

class EncryptedStreamDecorator implements StreamInterface
{
    private string $buffer = '';
    private bool $finalized = false;
    private int $position = 0;
    private bool $sourceEof = false;

    private int $blockSize;

    public function __construct(
        private StreamInterface $stream,
        private MediaCipherInterface $encryptor,
        private int $chunkSize = 65536
    ) {
        $this->blockSize = $this->encryptor->getBlockSize();

        if ($chunkSize < $this->blockSize) {
            throw new InvalidArgumentException(sprintf(
                'Chunk size must be at least %d bytes',
                $this->blockSize
            ));
        }
    }

    public function __toString(): string
    {
        try {
            return $this->getContents();
        } catch (\Throwable $e) {
            throw new StreamException('Error reading stream contents: ' . $e->getMessage(), 0, $e);
        }
    }

    public function close(): void
    {
        $this->finalize();
        $this->stream->close();
        $this->buffer = '';
    }

    public function detach()
    {
        $this->finalize();
        $this->buffer = '';
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->sourceEof && $this->buffer === '' && $this->finalized;
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new RuntimeException('Encrypted stream does not support seeking');
    }

    public function rewind(): void
    {
        throw new RuntimeException('Encrypted stream does not support seeking');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new RuntimeException('Cannot write to an encrypted read-only stream');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        if ($this->eof()) {
            return '';
        }

        $readSize = $this->calculateReadSize($length);

        while (mb_strlen($this->buffer, '8bit') < $length && !$this->sourceEof) {
            $chunk = $this->stream->read($readSize);

            if ($chunk === '') {
                $this->sourceEof = true;
                $this->buffer .= $this->finalize();
            } else {
                $this->buffer .= $this->encryptor->update($chunk);
            }
        }

        return $this->extractFromBuffer($length);
    }

    public function getContents(): string
    {
        if ($this->eof()) {
            return '';
        }

        if ($this->stream->getSize() !== null && $this->stream->getSize() <= $this->chunkSize) {
            $data = $this->stream->getContents();
            $this->buffer = $this->encryptor->update($data) . $this->finalize();

            return $this->extractFromBuffer(mb_strlen($this->buffer, '8bit'));
        }

        $result = '';
        while (!$this->eof()) {
            $result .= $this->read($this->chunkSize);
        }

        return $result;
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }

    private function finalize(): string
    {
        if ($this->finalized) {
            return '';
        }

        $this->finalized = true;
        $result = $this->encryptor->finish();

        return $result;
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
        $this->buffer = substr($this->buffer, $length);
        $this->position += mb_strlen($result, '8bit');

        return $result;
    }
}
