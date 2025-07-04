<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorTellTest extends TestCase
{
    private EncryptedStreamDecorator $decorator;
    private StreamInterface $stream;
    
    private const MOCK_MAC = '__MAC__';

    protected function setUp(): void
    {
        $this->stream = $this->createMock(StreamInterface::class);
        $this->stream->method('isReadable')->willReturn(true);

        $encryptorMock = $this->createMock(MediaCipherInterface::class);
        $encryptorMock->method('getBlockSize')->willReturn(16);
        $encryptorMock->method('update')->willReturnArgument(0);
        $encryptorMock->method('finish')->willReturn(self::MOCK_MAC);

        $this->decorator = new EncryptedStreamDecorator(
            $this->stream,
            $encryptorMock,
            1024
        );
    }

    public function testReturnsZeroInitially(): void
    {
        $this->assertEquals(0, $this->decorator->tell());
    }

    public function testTellUpdatesAfterRead(): void
    {
        $this->stream->method('read')
            ->willReturnOnConsecutiveCalls(
                str_repeat('a', 100),
                str_repeat('b', 50)
            );

        $firstRead = $this->decorator->read(80);
        $this->assertEquals(80, $this->decorator->tell());

        $secondRead = $this->decorator->read(40);
        $this->assertEquals(120, $this->decorator->tell());
    }

    public function testUpdatesAfterGetContents(): void
    {
        $testData = str_repeat('c', 200);

        $this->stream->method('getSize')->willReturn(200);
        $this->stream->method('getContents')->willReturn($testData);
        $this->stream->method('read')->willReturn($testData);

        $contents = $this->decorator->getContents();

        $expectedPosition = mb_strlen($testData, '8bit') + mb_strlen(self::MOCK_MAC, '8bit');
        $this->assertEquals($expectedPosition, $this->decorator->tell());
    }

    public function testPositionNotAffectedByMac(): void
    {
        $this->stream->method('read')->willReturn('data');

        $this->decorator->read(4);
        $this->decorator->close();

        $this->assertEquals(4, $this->decorator->tell());
    }

    public function testWithEmptyReads(): void
    {
        $this->stream->method('read')->willReturn('');
        $this->decorator->read(100);

        $this->assertEquals(mb_strlen(self::MOCK_MAC, '8bit'), $this->decorator->tell());
    }

    protected function tearDown(): void
    {
        unset($this->decorator, $this->stream);
    }
}
