<?php

declare(strict_types=1);

namespace Encryption\Stream;

use Encryption\Exception\DecryptionException;
use Encryption\Exception\StreamException;
use Encryption\Interface\MediaCipherInterface;
use Psr\Http\Message\StreamInterface;
use InvalidArgumentException;

class DecryptedStreamDecorator implements StreamInterface
{
    private string $buffer = '';
    private bool $finalized = false;
    private int $position = 0;
    private bool $sourceEof = false;
    private int $blockSize;

    public function __construct(
        private StreamInterface $stream,
        private MediaCipherInterface $decryptor,
        private int $chunkSize = 65536
    ) {
        if (!$stream->isReadable()) {
            throw new InvalidArgumentException('Stream must be readable');
        }

        $this->blockSize = $this->decryptor->getBlockSize();

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
        throw new StreamException('Decrypted stream does not support seeking');
    }

    public function rewind(): void
    {
        throw new StreamException('Decrypted stream does not support seeking');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new StreamException('Cannot write to an decrypted read-only stream');
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

        while (mb_strlen($this->buffer, '8bit') < $length && !$this->stream->eof()) {
            $chunk = $this->stream->read($readSize);

            if (empty($chunk)) {
                $this->sourceEof = true;
                $this->buffer .= $this->finalize();
                break;
            }
            
            if ($this->stream->eof()) {
                $this->sourceEof = true;
                $this->buffer .= $this->getDecryptedFinal($chunk);
            } else {
                $this->buffer .= $this->decryptor->update($chunk);
            }
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
            $result = $this->getDecryptedFinal($data);

            $this->position += mb_strlen($result, '8bit');
            $this->sourceEof = true;

            return $result;
        }

        while (!$this->eof()) {
            $result .= $this->read($this->chunkSize);
        }

        return $result;
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
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

    private function getDecryptedFinal(string $finalChunk): string
    {
        $offset = $this->getFinalOffsetSize();
        $chunkLength = mb_strlen($finalChunk, '8bit');
    
        if ($chunkLength < $offset) {
            try {
                return $this->finalize($finalChunk);
            } catch (DecryptionException $e) {
                throw new StreamException('Final chunk is too small for decryption');
            }
        }

        $encrypted = substr($finalChunk, 0, -$offset);
        $encryptedFinal = substr($finalChunk, -$offset);
        
        return $this->decryptor->update($encrypted) . $this->finalize($encryptedFinal);
    }

    private function getFinalOffsetSize(): int
    {
        return $this->decryptor->getBlockSize() + $this->decryptor->getMacSize();
    }

    private function finalize(string $chunk = ''): string
    {
        if ($this->finalized) {
            return '';
        }

        $this->finalized = true;

        return $this->decryptor->finish($chunk);
    }
}
