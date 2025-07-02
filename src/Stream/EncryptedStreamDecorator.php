<?php

declare(strict_types=1);

namespace Encryption\Stream;

use Encryption\Exception\StreamException;
use Encryption\Interface\MediaCipherInterface;
use Psr\Http\Message\StreamInterface;
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
        throw new StreamException('Encrypted stream does not support seeking');
    }

    public function rewind(): void
    {
        throw new StreamException('Encrypted stream does not support seeking');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new StreamException('Cannot write to an encrypted read-only stream');
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

        if (mb_strlen($this->buffer, '8bit') >= $length) {
            return $this->extractFromBuffer($length);
        }

        while (mb_strlen($this->buffer, '8bit') < $length && !$this->sourceEof) {
            $chunk = $this->stream->read($readSize);

            if (empty($chunk)) {
                $this->sourceEof = true;
                $this->buffer .= $this->finalize();
                break;
            }
            
            $this->buffer .= $this->encryptor->update($chunk);
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
            $result = $this->encryptor->update($data) . $this->finalize();
            $this->position += mb_strlen($result, '8bit');

            $this->sourceEof = true;

            return $result;
        }

        while (!$this->eof()) {
            $chunk = $this->stream->read($this->chunkSize);
            if ($chunk === '') {
                $this->sourceEof = true;
                break;
            }
            $result .= $this->encryptor->update($chunk);
        }

        $result .= $this->finalize();

        $this->position += strlen($result);
        $this->sourceEof = true;

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

        return $this->encryptor->finish();
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
