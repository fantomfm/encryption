<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Exception\EncryptionException;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorGetContentsTest extends TestCase
{
    private EncryptedStreamDecorator $decorator;
    private StreamInterface $stream;
    private MediaCipherInterface $encryptor;

    private const MOCK_MAC = '__MAC__';
    private const CHUNK_SIZE = 1024;

    protected function setUp(): void
    {
        $this->stream = $this->createMock(StreamInterface::class);
        $this->stream->method('isReadable')->willReturn(true);

        $this->encryptor = $this->createMock(MediaCipherInterface::class);
        $this->encryptor->method('getBlockSize')->willReturn(16);
        $this->encryptor->method('update')->willReturnArgument(0);
        $this->encryptor->method('finish')->willReturn(self::MOCK_MAC);

        $this->decorator = new EncryptedStreamDecorator(
            $this->stream,
            $this->encryptor,
            self::CHUNK_SIZE
        );
    }

    public function testGetContentsSmallStream(): void
    {
        $testData = str_repeat('a', 500);
        $this->stream->expects($this->never())
            ->method('read');

        $this->stream->method('getSize')
            ->willReturn(500);
        $this->stream->method('getContents')
            ->willReturn($testData);

        $result = $this->decorator->getContents();

        $this->assertSame($testData . self::MOCK_MAC, $result);
        $this->assertEquals(500 + mb_strlen(self::MOCK_MAC, '8bit'), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsLargeStream(): void
    {
        $largeData = str_repeat('b', self::CHUNK_SIZE * 2 - 50);

        $chunks = [
            substr($largeData, 0, self::CHUNK_SIZE),
            substr($largeData, self::CHUNK_SIZE, self::CHUNK_SIZE),
            ''
        ];

        $this->stream->method('getSize')->willReturn(strlen($largeData));
        $this->stream->expects($this->exactly(3))
            ->method('read')
            ->willReturnOnConsecutiveCalls(...$chunks);

        $this->encryptor->method('update')
            ->willReturnCallback(fn($data) => $data);
        $this->encryptor->method('finish')
            ->willReturn(self::MOCK_MAC);

        $result = $this->decorator->getContents();

        $this->assertSame($largeData . self::MOCK_MAC, $result);
        $this->assertEquals(strlen($largeData) + strlen(self::MOCK_MAC), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsUpdatesPosition(): void
    {
        $testData = str_repeat('c', 800);
        $this->stream->method('getSize')->willReturn(800);
        $this->stream->method('getContents')->willReturn($testData);

        $initialPos = $this->decorator->tell();

        $result = $this->decorator->getContents();

        $this->assertEquals(0, $initialPos);
        $this->assertEquals(800 + mb_strlen(self::MOCK_MAC, '8bit'), $this->decorator->tell());
        $this->assertEquals($testData . self::MOCK_MAC, $result);
    }

    public function testGetContentsAfterPartialRead(): void
    {
        $testData = str_repeat('d', 1500);
        $chunks = [
            substr($testData, 0, 300),
            substr($testData, 300, 1024),
            substr($testData, 1324)
        ];

        $this->stream->method('getSize')->willReturn(1500);
        $this->stream->expects($this->exactly(4))
            ->method('read')
            ->willReturnOnConsecutiveCalls(
                $chunks[0],
                $chunks[1],
                $chunks[2],
                ''
            );

        $this->stream->method('eof')
            ->willReturnOnConsecutiveCalls(false, false, false, true);

        $firstResult = $this->decorator->read(300);
        $this->assertSame($chunks[0], $firstResult);

        $remainingResult = $this->decorator->getContents();
        $this->assertSame($chunks[1] . $chunks[2] . self::MOCK_MAC, $remainingResult);
        $this->assertEquals(1500 + mb_strlen(self::MOCK_MAC, '8bit'), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsEmptyStream(): void
    {
        $this->stream->method('getSize')->willReturn(0);
        $this->stream->expects($this->never())
            ->method('read');

        $this->stream->expects($this->once())
            ->method('getContents')
            ->willReturn('');

        $this->stream->method('eof')
            ->willReturn(true);

        $this->encryptor->expects($this->once())
            ->method('update')
            ->with('')
            ->willReturn('');

        $this->encryptor->expects($this->once())
            ->method('finish')
            ->willReturn(self::MOCK_MAC);

        $result = $this->decorator->getContents();

        $this->assertSame(self::MOCK_MAC, $result);
        $this->assertTrue($this->decorator->eof());
        $this->assertEquals(strlen(self::MOCK_MAC), $this->decorator->tell());
    }

    public function testGetContentsExactChunkSize(): void
    {
        $testData = str_repeat('d', self::CHUNK_SIZE);
        $this->stream->method('getSize')->willReturn(self::CHUNK_SIZE);
        $this->stream->expects($this->never())
            ->method('read');
        $this->stream->expects($this->once())
            ->method('getContents')
            ->willReturn($testData);

        $result = $this->decorator->getContents();
        $this->assertEquals(self::CHUNK_SIZE + strlen(self::MOCK_MAC), strlen($result));
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsAfterEncryptionError(): void
    {
        $this->stream->method('read')->willReturn('data');
        $this->encryptor->method('update')
            ->willThrowException(new EncryptionException('Error'));

        $this->expectException(EncryptionException::class);
        $this->decorator->getContents();

        $this->assertTrue($this->decorator->eof());
    }
    public function testGetContentsCalledTwice(): void
    {
        $testData = 'test data';
        $this->stream->method('getSize')->willReturn(strlen($testData));
        $this->stream->expects($this->once())
            ->method('getContents')
            ->willReturn($testData);

        $firstCall = $this->decorator->getContents();
        $secondCall = $this->decorator->getContents();

        $this->assertSame($testData . self::MOCK_MAC, $firstCall);

        $this->assertSame('', $secondCall);
        $this->assertTrue($this->decorator->eof());
    }

    protected function tearDown(): void
    {
        unset($this->decorator, $this->stream, $this->encryptor);
    }
}
