<?php

declare(strict_types=1);

namespace Encryption\Stream;

use Encryption\Enum\MediaType;
use Encryption\Interface\EncryptionInterface;
use Psr\Http\Message\StreamInterface;
use Encryption\Exception\EncryptionException;

class EncryptingStream implements StreamInterface
{
    private bool $isEof = false;
    private string $buffer = '';
    private int $position = 0;
    private string $encryptedData = '';
    
    public function __construct(
        private StreamInterface $stream,
        private string $mediaKey,
        private MediaType $mediaType,
        private EncryptionInterface $encryption,
        private int $blockSize,
    ) {}
    
    public function __toString(): string
    {
        try {
            $this->stream->rewind();
            $result = '';
            
            while (!$this->stream->eof()) {
                $result .= $this->read(8192);
            }
            
            return $result;
        } catch (\Throwable $e) {
            throw new EncryptionException("Error converting stream to string", 0, $e);
        }
    }
    
    public function close(): void
    {
        $this->stream->close();
        $this->buffer = '';
        $this->position = 0;
        $this->isEof = false;
        $this->encryptedData = '';
    }
    
    public function detach()
    {
        $this->close();
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
        return $this->isEof;
    }
    
    public function isSeekable(): bool
    {
        return false;
    }
    
    public function rewind(): void
    {
        $this->stream->rewind();
        $this->position = 0;
        $this->buffer = '';
        $this->isEof = false;
        $this->encryptedData = '';
    }
    
    public function seek($offset, $whence = SEEK_SET): void
    {
        throw new EncryptionException("Cannot seek in encrypted stream");
    }
    
    public function read($length): string
    {
        if ($this->isEof) {
            return '';
        }

        $data = substr($this->buffer, 0, $length);
        $remaining = $length - strlen($data);

        while ($remaining > 0 && !$this->stream->eof()) {
            $sourceData = $this->stream->read($remaining * 2);
            
            if ($sourceData === '') {
                $this->isEof = true;
                $this->buffer = '';
                return $data;
            }
            
            $this->encryptedData .= $sourceData;
            
            $blockSize = $this->blockSize;
            $fullBlocks = (int)floor(strlen($this->encryptedData) / $blockSize);
            
            if ($fullBlocks === 0) {
                continue;
            }
            
            $processedBytes = $fullBlocks * $blockSize;
            $blocksToEncrypt = substr($this->encryptedData, 0, $processedBytes);
            
            $encrypted = $this->encryption->encrypt($blocksToEncrypt, $this->mediaKey, $this->mediaType);
            
            $this->encryptedData = substr($this->encryptedData, $processedBytes);
            
            $this->buffer .= $encrypted;
        }
        
        if ($this->isEof && !empty($this->encryptedData)) {
            $padLength = $blockSize - (strlen($this->encryptedData) % $blockSize);
            $this->encryptedData .= str_repeat(chr($padLength), $padLength);
            
            $finalBlock = $this->encryption->encrypt($this->encryptedData, $this->mediaKey, $this->mediaType);
            
            $this->buffer .= $finalBlock;
        }
        
        $data .= substr($this->buffer, 0, $remaining);
        $this->buffer = substr($this->buffer, $remaining);
        
        $this->position += strlen($data);

        return $data;
    }

    public function isReadable(): bool
    {
        return true;
    }
    
    public function write($string): int
    {
        throw new EncryptionException("Cannot write to encrypted stream");
    }
    
    public function isWritable(): bool
    {
        return false;
    }
    
    public function getMetadata($key = null)
    {
        $metadata = $this->stream->getMetadata();
        
        if ($key === null) {
            return $metadata;
        }
        
        return $metadata[$key] ?? null;
    }
    
    public function getContents(): string
    {
        return $this->__toString();
    }
}