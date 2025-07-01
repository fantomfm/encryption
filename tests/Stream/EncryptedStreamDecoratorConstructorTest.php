<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorConstructorTest extends TestCase
{
    private function createEncryptorMock(): MediaCipherInterface
    {
        $encryptor = $this->createMock(MediaCipherInterface::class);
        $encryptor->method('getBlockSize')->willReturn(16);
        return $encryptor;
    }

    private function createReadableStreamMock(): StreamInterface
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isReadable')->willReturn(true);
        return $stream;
    }

    private function createUnreadableStreamMock(): StreamInterface
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isReadable')->willReturn(false);
        return $stream;
    }

    public function testValidatesReadableStream(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Stream must be readable');

        new EncryptedStreamDecorator(
            $this->createUnreadableStreamMock(),
            $this->createEncryptorMock(),
            1024
        );
    }

    public function testValidatesChunkSize(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Chunk size must be at least 16 bytes');

        new EncryptedStreamDecorator(
            $this->createReadableStreamMock(),
            $this->createEncryptorMock(),
            15
        );
    }

    public function testConstructorPassesWithReadableStream(): void
    {
        $decorator = new EncryptedStreamDecorator(
            $this->createReadableStreamMock(),
            $this->createEncryptorMock(),
            1024
        );

        $this->assertInstanceOf(EncryptedStreamDecorator::class, $decorator);
    }

    public function testSetsProperties(): void
    {
        $stream = $this->createReadableStreamMock();
        $encryptor = $this->createEncryptorMock();
        $chunkSize = 1024;

        $decorator = new EncryptedStreamDecorator($stream, $encryptor, $chunkSize);

        $reflection = new \ReflectionClass($decorator);

        $streamProperty = $reflection->getProperty('stream');
        $streamProperty->setAccessible(true);
        $this->assertSame($stream, $streamProperty->getValue($decorator));

        $encryptorProperty = $reflection->getProperty('encryptor');
        $encryptorProperty->setAccessible(true);
        $this->assertSame($encryptor, $encryptorProperty->getValue($decorator));

        $chunkSizeProperty = $reflection->getProperty('chunkSize');
        $chunkSizeProperty->setAccessible(true);
        $this->assertEquals($chunkSize, $chunkSizeProperty->getValue($decorator));

        $blockSizeProperty = $reflection->getProperty('blockSize');
        $blockSizeProperty->setAccessible(true);
        $this->assertEquals(16, $blockSizeProperty->getValue($decorator));
    }
}
