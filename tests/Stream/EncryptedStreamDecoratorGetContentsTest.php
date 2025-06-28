<?php

declare(strict_types=1);

namespace Tests\Encryption\Stream;

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
    private int $mockMacSize = 8;

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
            1024
        );
    }

    public function testGetContentsSmallStream(): void
    {
        $testData = str_repeat('a', 500);
        $this->streamMock->method('getSize')->willReturn(500);
        $this->streamMock->method('getContents')->willReturn($testData);
        $this->streamMock->method('eof')->willReturn(true);
        
        $result = $this->decorator->getContents();
        
        $this->assertSame($testData . $this->mockMac, $result);
        $this->assertEquals(500 + mb_strlen($this->mockMac, '8bit'), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsLargeStream(): void
    {
        $largeData = str_repeat('b', 2000);
        
        $chunks = [
            substr($largeData, 0, 1024),
            substr($largeData, 1024, 1024),
            substr($largeData, 2048)
        ];
        
        $this->streamMock->method('getSize')->willReturn(2000);
        $this->streamMock->method('read')->willReturnOnConsecutiveCalls(...$chunks);
        $this->streamMock->method('eof')->willReturnOnConsecutiveCalls(false, false, true);
        
        $this->encryptorMock->method('update')->willReturnArgument(0);
        $this->encryptorMock->method('finish')->willReturn($this->mockMac);
        
        $result = $this->decorator->getContents();
        
        $expectedResult = $largeData . $this->mockMac;
        $this->assertSame($expectedResult, $result);
        $this->assertEquals(2000 + mb_strlen($this->mockMac, '8bit'), $this->decorator->tell());
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
            substr($testData, 0, 300),    // Первое чтение (read(300))
            substr($testData, 300, 1024), // Второе чтение (read(1024))
            substr($testData, 1324)       // Третье чтение (read(176))
        ];
        
        $this->streamMock->method('getSize')->willReturn(1500);
        $this->streamMock->expects($this->exactly(3))
            ->method('read')
            ->willReturnOnConsecutiveCalls(...$chunks);
        
        $this->streamMock->method('eof')
            ->willReturnOnConsecutiveCalls(false, false, true);
        
        // Первое чтение
        $firstResult = $this->decorator->read(300);
        $this->assertSame($chunks[0], $firstResult);
        
        // Чтение остатка
        $remainingResult = $this->decorator->getContents();
        $this->assertSame($chunks[1] . $chunks[2] . $this->mockMac, $remainingResult);
        $this->assertEquals(1500 + mb_strlen($this->mockMac, '8bit'), $this->decorator->tell());
        $this->assertTrue($this->decorator->eof());
    }

    protected function tearDown(): void
    {
        unset($this->decorator, $this->streamMock, $this->encryptorMock);
    }
}