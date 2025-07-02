<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Exception\StreamException;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorBehaviorTest extends TestCase
{
    private EncryptedStreamDecorator $decorator;
    private StreamInterface $stream;
    private MediaCipherInterface $encryptor;

    protected function setUp(): void
    {
        $this->stream = $this->createMock(StreamInterface::class);
        $this->stream->method('isReadable')->willReturn(true);
        
        $this->encryptor = $this->createMock(MediaCipherInterface::class);
        $this->encryptor->method('getBlockSize')->willReturn(16);
        
        $this->decorator = new EncryptedStreamDecorator(
            $this->stream,
            $this->encryptor,
            1024
        );
    }

    public function testIsReadableReturnsTrue(): void
    {
        $this->assertTrue($this->decorator->isReadable());
    }

    public function testIsWritableReturnsFalse(): void
    {
        $this->assertFalse($this->decorator->isWritable());
    }

    public function testIsSeekableReturnsFalse(): void
    {
        $this->assertFalse($this->decorator->isSeekable());
    }

    public function testWriteThrowsException(): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Cannot write to an encrypted read-only stream');
        
        $this->decorator->write('data');
    }

    public function testSeekThrowsException(): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Encrypted stream does not support seeking');
        
        $this->decorator->seek(0);
    }

    public function testRewindThrowsException(): void
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Encrypted stream does not support seeking');
        
        $this->decorator->rewind();
    }

    protected function tearDown(): void
    {
        unset($this->decorator, $this->stream, $this->encryptor);
    }
}