<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorReadTest extends TestCase
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
        $this->encryptor->method('update')->willReturnArgument(0);
        $this->encryptor->method('finish')->willReturn('__MAC__');

        $this->decorator = new EncryptedStreamDecorator(
            $this->stream,
            $this->encryptor,
            1024
        );
    }

    public function testReadEmptyStreamReturnsEmptyString(): void
    {
        $this->stream->method('read')->willReturn('');
        $this->stream->method('eof')->willReturn(true);

        $result = $this->decorator->read(100);

        $this->assertSame('', $result);
        $this->assertSame(0, $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testReadSmallerThanBlockSize(): void
    {
        $testData = str_repeat('a', 10);
        $this->stream->method('read')->willReturn($testData);

        $result = $this->decorator->read(10);

        $this->assertSame($testData, $result);
        $this->assertSame(10, $this->decorator->tell());
    }

    public function testReadExactBlockSize(): void
    {
        $testData = str_repeat('b', 16);
        $this->stream->method('read')->willReturn($testData);

        $result = $this->decorator->read(16);

        $this->assertSame($testData, $result);
        $this->assertSame(16, $this->decorator->tell());
    }

    public function testReadLargerThanBlockSize(): void
    {
        $testData = str_repeat('c', 64);
        $this->stream->method('read')->willReturn($testData);

        $result = $this->decorator->read(64);

        $this->assertSame($testData, $result);
        $this->assertSame(64, $this->decorator->tell());
    }

    public function testReadMultipleTimes(): void
    {
        $testChunks = [
            str_repeat('a', 10),
            str_repeat('b', 20),
            str_repeat('c', 5)
        ];

        $this->stream->method('read')
            ->willReturnOnConsecutiveCalls(...$testChunks);

        $result1 = $this->decorator->read(10);
        $this->assertSame($testChunks[0], $result1);
        $this->assertSame(10, $this->decorator->tell());

        $result2 = $this->decorator->read(20);
        $this->assertSame($testChunks[1], $result2);
        $this->assertSame(30, $this->decorator->tell());

        $result3 = $this->decorator->read(5);
        $this->assertSame($testChunks[2], $result3);
        $this->assertSame(35, $this->decorator->tell());
    }

    public function testReadAfterEofReturnsEmptyString(): void
    {
        $this->stream->method('read')
            ->willReturnOnConsecutiveCalls(
                str_repeat('a', 10),
                ''
            );

        $firstRead = $this->decorator->read(10);
        $this->assertSame(str_repeat('a', 10), $firstRead);
        $this->assertFalse($this->decorator->eof());

        $secondRead = $this->decorator->read(10);
        $this->assertSame('', $secondRead);
        $this->assertTrue($this->decorator->eof());

        $thirdRead = $this->decorator->read(10);
        $this->assertSame('', $thirdRead);
    }

    public function testReadAfterCloseReturnsEmptyString(): void
    {
        $this->decorator->close();

        $this->assertTrue($this->decorator->eof());
        $this->assertSame('', $this->decorator->read(10));
        $this->assertSame('', $this->decorator->read(100));
    }

    public function testCloseIsIdempotent(): void
    {
        $this->decorator->close();
        $this->assertTrue($this->decorator->eof());

        $this->decorator->close();
        $this->assertSame('', $this->decorator->read(10));
    }

    public function testCorruptedStreamHandling(): void
    {
        $this->stream->method('read')->willReturn('corrupted_data');

        $this->encryptor->method('update')
            ->willThrowException(new \RuntimeException('Decryption failed'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Decryption failed');

        $this->decorator->read(16);
    }

    protected function tearDown(): void
    {
        unset($this->decorator, $this->stream, $this->encryptor);
    }
}
