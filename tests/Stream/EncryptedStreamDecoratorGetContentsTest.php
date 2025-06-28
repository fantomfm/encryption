<?php

declare(strict_types=1);

namespace Tests\Encryption\Stream;

use Encryption\Exception\EncryptionException;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorGetContentsTest extends TestCase
{
    private EncryptedStreamDecorator $decorator;
    private StreamInterface $streamMock;
    private MediaCipherInterface $encryptorMock;

    private string $mockMac = '__MAC__';
    private int $chunkSize = 1024;

    protected function setUp(): void
    {
        $this->streamMock = $this->createMock(StreamInterface::class);
        $this->streamMock->method('isReadable')->willReturn(true);

        $this->encryptorMock = $this->createMock(MediaCipherInterface::class);
        $this->encryptorMock->method('getBlockSize')->willReturn(16);
        $this->encryptorMock->method('update')->willReturnArgument(0);
        $this->encryptorMock->method('finish')->willReturn($this->mockMac);

        $this->decorator = new EncryptedStreamDecorator(
            $this->streamMock,
            $this->encryptorMock,
            $this->chunkSize
        );
    }

    public function testGetContentsSmallStream(): void
    {
        $testData = str_repeat('a', 500);
        $this->streamMock->expects($this->never())
            ->method('read');

        $this->streamMock->method('getSize')
            ->willReturn(500);
        $this->streamMock->method('getContents')
            ->willReturn($testData);
        $this->streamMock->method('eof')
            ->willReturnOnConsecutiveCalls(false, true);

        $result = $this->decorator->getContents();

        $this->assertSame($testData . $this->mockMac, $result);
        $this->assertEquals(500 + mb_strlen($this->mockMac, '8bit'), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsLargeStream(): void
    {
        $largeData = str_repeat('b', $this->chunkSize * 2 - 50);

        $chunks = [
            substr($largeData, 0, $this->chunkSize),
            substr($largeData, $this->chunkSize, $this->chunkSize),
            ''
        ];

        $this->streamMock->method('getSize')->willReturn(strlen($largeData));
        $this->streamMock->expects($this->exactly(3))
            ->method('read')
            ->willReturnOnConsecutiveCalls(...$chunks);

        $this->encryptorMock->method('update')
            ->willReturnCallback(fn($data) => $data);
        $this->encryptorMock->method('finish')
            ->willReturn($this->mockMac);

        $result = $this->decorator->getContents();

        $this->assertSame($largeData . $this->mockMac, $result);
        $this->assertEquals(strlen($largeData) + strlen($this->mockMac), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsUpdatesPosition(): void
    {
        $testData = str_repeat('c', 800);
        $this->streamMock->method('getSize')->willReturn(800);
        $this->streamMock->method('getContents')->willReturn($testData);
        $this->streamMock->method('eof')->willReturn(true);

        $initialPos = $this->decorator->tell();

        $result = $this->decorator->getContents();

        $this->assertEquals(0, $initialPos);
        $this->assertEquals(800 + mb_strlen($this->mockMac, '8bit'), $this->decorator->tell());
        $this->assertEquals($testData . $this->mockMac, $result);
    }

    public function testGetContentsAfterPartialRead(): void
    {
        $testData = str_repeat('d', 1500);
        $chunks = [
            substr($testData, 0, 300),
            substr($testData, 300, 1024),
            substr($testData, 1324)
        ];

        $this->streamMock->method('getSize')->willReturn(1500);
        $this->streamMock->expects($this->exactly(4))
            ->method('read')
            ->willReturnOnConsecutiveCalls(
                $chunks[0],
                $chunks[1],
                $chunks[2],
                ''
            );

        $this->streamMock->method('eof')
            ->willReturnOnConsecutiveCalls(false, false, false, true);

        $firstResult = $this->decorator->read(300);
        $this->assertSame($chunks[0], $firstResult);

        $remainingResult = $this->decorator->getContents();
        $this->assertSame($chunks[1] . $chunks[2] . $this->mockMac, $remainingResult);
        $this->assertEquals(1500 + mb_strlen($this->mockMac, '8bit'), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsEmptyStream(): void
    {
        $this->streamMock->method('getSize')->willReturn(0);
        $this->streamMock->expects($this->never())
            ->method('read');

        $this->streamMock->expects($this->once())
            ->method('getContents')
            ->willReturn('');

        $this->streamMock->method('eof')
            ->willReturn(true);

        $this->encryptorMock->expects($this->once())
            ->method('update')
            ->with('')
            ->willReturn('');

        $this->encryptorMock->expects($this->once())
            ->method('finish')
            ->willReturn($this->mockMac);

        $result = $this->decorator->getContents();

        $this->assertSame($this->mockMac, $result);
        $this->assertTrue($this->decorator->eof());
        $this->assertEquals(strlen($this->mockMac), $this->decorator->tell());
    }

    public function testGetContentsExactChunkSize(): void
    {
        $testData = str_repeat('d', $this->chunkSize);
        $this->streamMock->method('getSize')->willReturn($this->chunkSize);
        $this->streamMock->expects($this->never())
            ->method('read');
        $this->streamMock->expects($this->once())
            ->method('getContents')
            ->willReturn($testData);

        $result = $this->decorator->getContents();
        $this->assertEquals($this->chunkSize + strlen($this->mockMac), strlen($result));
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsAfterEof(): void
    {
        $this->streamMock->method('eof')->willReturn(true);

        $result = $this->decorator->getContents();
        $this->assertSame('', $result);
    }

    public function testGetContentsAfterEncryptionError(): void
    {
        $this->streamMock->method('read')->willReturn('data');
        $this->encryptorMock->method('update')
            ->willThrowException(new EncryptionException('Error'));

        $this->expectException(EncryptionException::class);
        $this->decorator->getContents();

        $this->assertTrue($this->decorator->eof());
    }
    public function testGetContentsCalledTwice(): void
    {
        $testData = 'test data';
        $this->streamMock->method('getSize')->willReturn(strlen($testData));
        $this->streamMock->expects($this->once())
            ->method('getContents')
            ->willReturn($testData);

        $firstCall = $this->decorator->getContents();
        $secondCall = $this->decorator->getContents();

        $this->assertSame($testData . $this->mockMac, $firstCall);

        $this->assertSame('', $secondCall);
        $this->assertTrue($this->decorator->eof());
    }

    protected function tearDown(): void
    {
        unset($this->decorator, $this->streamMock, $this->encryptorMock);
    }
}
