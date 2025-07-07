<?php

declare(strict_types=1);

namespace Encryption\Stream;

use Encryption\Exception\StreamException;

trait StreamDecoratorTrait
{
    public function __toString(): string
    {
        try {
            return $this->getContents();
        } catch (\Throwable $e) {
            return '';
        }
    }

    public function close(): void
    {
        $this->finalize();
        $this->stream->close();
        $this->buffer = '';
        $this->sourceEof = true;
    }

    public function detach()
    {
        $this->finalize();
        $this->buffer = '';
        $this->sourceEof = true;

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
        return $this->sourceEof && empty($this->buffer);
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new StreamException('Stream does not support seeking');
    }

    public function rewind(): void
    {
        throw new StreamException('Stream does not support seeking');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new StreamException('Cannot write to read-only stream');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }
}
