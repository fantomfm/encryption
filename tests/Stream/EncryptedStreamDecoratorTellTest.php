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
    private StreamInterface $streamMock;
    private string $mockMac = '__MAC__';

    protected function setUp(): void
    {
        $this->streamMock = $this->createMock(StreamInterface::class);
        $this->streamMock->method('isReadable')->willReturn(true);

        $encryptorMock = $this->createMock(MediaCipherInterface::class);
        $encryptorMock->method('getBlockSize')->willReturn(16);
        $encryptorMock->method('update')->willReturnArgument(0);
        $encryptorMock->method('finish')->willReturn($this->mockMac);

        $this->decorator = new EncryptedStreamDecorator(
            $this->streamMock,
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
        $this->streamMock->method('read')
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

        $this->streamMock->method('getSize')->willReturn(200);
        $this->streamMock->method('getContents')->willReturn($testData);
        $this->streamMock->method('read')->willReturn($testData);
        $this->streamMock->method('eof')->willReturn(true);

        $contents = $this->decorator->getContents();

        $expectedPosition = mb_strlen($testData, '8bit') + mb_strlen($this->mockMac, '8bit');
        $this->assertEquals($expectedPosition, $this->decorator->tell());
    }

    public function testAfterFinalize(): void
    {
        $this->invokeFinalize();

        $this->assertStringEndsWith($this->mockMac, $this->getBufferContent());

        $this->assertEquals(0, $this->decorator->tell());
    }

    public function testPositionNotAffectedByMac(): void
    {
        $this->streamMock->method('read')->willReturn('data');

        $this->decorator->read(4);
        $this->decorator->close();

        $this->assertEquals(4, $this->decorator->tell());
    }

    public function testWithEmptyReads(): void
    {
        $this->streamMock->method('read')->willReturn('');
        $this->decorator->read(100);

        $this->assertEquals(0, $this->decorator->tell());
    }

    private function invokeFinalize(): void
    {
        $reflection = new \ReflectionClass($this->decorator);
        $method = $reflection->getMethod('finalize');
        $method->setAccessible(true);
        $method->invoke($this->decorator);
    }

    private function getBufferContent(): string
    {
        $reflection = new \ReflectionClass($this->decorator);
        $property = $reflection->getProperty('buffer');
        $property->setAccessible(true);

        return $property->getValue($this->decorator);
    }

    protected function tearDown(): void
    {
        unset($this->decorator, $this->streamMock);
    }
}
