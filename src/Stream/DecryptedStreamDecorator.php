<?php

declare(strict_types=1);

namespace Encryption\Stream;

use Encryption\Enum\MediaType;
use Psr\Http\Message\StreamInterface;
use Encryption\Exception\DecryptionException;
use Encryption\Exception\StreamException;
use Encryption\Interface\MediaCipherInterface;
use Encryption\WhatsApp\WhatsAppMediaDecryptor;
use InvalidArgumentException;

class DecryptedStreamDecorator implements StreamInterface
{
    private string $buffer = '';
    private bool $finalized = false;

    public function __construct(
        private StreamInterface $stream,
        private MediaCipherInterface $decryptor,
        private int $chunkSize = 65536
    ) {
        if (!$stream->isReadable()) {
            throw new InvalidArgumentException('Stream must be readable');
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

    public function read($length): string
    {
        if ($this->finalized) {
            return '';
        }

        // Читаем из внутреннего буфера
        $available = mb_strlen($this->buffer, '8bit');
        if ($available >= $length) {
            $result = substr($this->buffer, 0, $length);
            $this->buffer = substr($this->buffer, $length);
            return $result;
        }

        while (!$this->stream->eof()) {
            $chunk = $this->stream->read(8192);
            if ($chunk === '') {
                break;
            }
            $this->buffer .= $this->decryptor->update($chunk);

            // Если накоплено достаточно данных для чтения — отдаем
            if (mb_strlen($this->buffer, '8bit') >= $length) {
                $result = substr($this->buffer, 0, $length);
                $this->buffer = substr($this->buffer, $length);
                return $result;
            }
        }

        // EOF — достаём остаток + вызываем finish()
        $remaining = $this->stream->getContents();
        if ($remaining !== '') {
            $this->buffer .= $this->decryptor->update($remaining);
        }

        try {
            $finalChunk = $this->decryptor->finish();
            $this->buffer .= $finalChunk;
        } catch (DecryptionException $e) {
            throw new \RuntimeException("Finalizing decryption failed: " . $e->getMessage(), 0, $e);
        }

        $this->finalized = true;

        // Отдаём оставшиеся данные
        $result = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);

        return $result;
    }

    public function eof(): bool
    {
        return $this->stream->eof() && $this->finalized && $this->buffer === '';
    }

    public function close(): void
    {
        $this->stream->close();
    }

    public function detach()
    {
        return $this->stream->detach();
    }

    public function getSize()
    {
        return null;
    }

    public function tell()
    {
        return $this->stream->tell();
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write($string)
    {
        throw new StreamException('Cannot write to a decrypting stream');
    }

    public function isReadable(): bool
    {
        return $this->stream->isReadable();
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        throw new StreamException('Seeking not supported in decrypting stream');
    }

    public function rewind()
    {
        throw new StreamException('Rewinding not supported in decrypting stream');
    }

    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }

    public function getContents()
    {
        if ($this->finalized) {
            return $this->buffer;
        }
        // Читаем всё из оригинального потока до конца
        while (!$this->stream->eof()) {
            $chunk = $this->stream->read(8192);
            if ($chunk === '') {
                break;
            }
            $this->buffer .= $this->decryptor->update($chunk);
        }
        $remaining = $this->stream->getContents();
        if ($remaining !== '') {
            $this->buffer .= $this->decryptor->update($remaining);
        }
        if (!$this->finalized) {
            try {
                $finalChunk = $this->decryptor->finish();
                $this->buffer .= $finalChunk;
            } catch (DecryptionException $e) {
                throw new StreamException("Finalizing decryption failed: " . $e->getMessage(), 0, $e);
            }
            $this->finalized = true;
        }
        return $this->buffer;
    }
}