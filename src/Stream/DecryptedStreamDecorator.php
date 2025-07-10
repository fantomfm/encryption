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
    use StreamDecoratorTrait;

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

    public function read(int $length): string
    {
        if ($this->eof()) {
            return '';
        }

        if (mb_strlen($this->buffer, '8bit') >= $length) {
            return $this->extractFromBuffer($length);
        }

        while (mb_strlen($this->buffer, '8bit') < $length && !$this->sourceEof) {
            $chunk = $this->stream->read($this->chunkSize);

            if ($chunk === '') {
                if ($this->stream->eof()) {
                    $this->handleFinalChunk($chunk);
                }
                break;
            }

            if ($this->stream->eof()) {
                $this->handleFinalChunk($chunk);
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

    private function extractFromBuffer(int $length): string
    {
        $available = mb_strlen($this->buffer, '8bit');
        $length = min($length, $available);
        $result = substr($this->buffer, 0, $length);

        if ($result === false) {
            throw new StreamException('Failed to extract data from buffer');
        }

        $this->buffer = substr($this->buffer, $length);
        $this->position += $length;

        return $result;
    }

    private function getDecryptedFinal(string $finalChunk): string
    {
        try {
            return $this->finalize($finalChunk);
        } catch (DecryptionException $e) {
            throw new StreamException('Failed to decrypt final chunk: ' . $e->getMessage());
        }
    }

    private function handleFinalChunk(string $chunk): void
    {
        $this->sourceEof = true;
        $this->buffer .= $this->getDecryptedFinal($chunk);
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
