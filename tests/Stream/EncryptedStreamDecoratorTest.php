<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorTest extends TestCase
{
    private function createEncryptorMock(): MediaCipherInterface
    {
        $encryptor = $this->createMock(MediaCipherInterface::class);
        $encryptor->method('getBlockSize')->willReturn(16);
        $encryptor->method('update')->willReturnArgument(0);
        $encryptor->method('finish')->willReturn('MAC');
        
        return $encryptor;
    }

    private function createStreamMock(string $content): StreamInterface
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isReadable')->willReturn(true);
        $stream->method('read')->willReturnCallback(
            fn($length) => substr($content, 0, $length)
        );
        $stream->method('getSize')->willReturn(strlen($content));
        
        return $stream;
    }

    public function testReadSmallerThanBlockSize(): void
    {
        $stream = $this->createStreamMock(str_repeat('a', 32));
        $decorator = new EncryptedStreamDecorator($stream, $this->createEncryptorMock(), 16);
        
        $result = $decorator->read(10);
        $this->assertEquals(10, strlen($result));
        $this->assertEquals(10, $decorator->tell());
    }

    // ... другие тестовые методы ...
}