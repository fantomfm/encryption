<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorBufferTest extends TestCase
{
    private MediaCipherInterface $encryptor;
    private StreamInterface $stream;

    protected function setUp(): void
    {
        $this->encryptor = $this->createMock(MediaCipherInterface::class);
        $this->encryptor->method('getBlockSize')->willReturn(16);

        $this->stream = $this->createMock(StreamInterface::class);
        $this->stream->method('isReadable')->willReturn(true);
    }

    public function testBufferHandlesPartialReads(): void
    {
        $this->encryptor->expects($this->exactly(2))
            ->method('update')
            ->willReturnOnConsecutiveCalls(
                str_repeat('a', 32),
                str_repeat('b', 32)
            );

        $this->stream->method('read')
            ->willReturnOnConsecutiveCalls(
                'chunk1',
                'chunk2'
            );

        $decorator = new EncryptedStreamDecorator($this->stream, $this->encryptor, 64);

        $result1 = $decorator->read(20);
        $this->assertEquals(20, strlen($result1));
        $this->assertEquals(str_repeat('a', 20), $result1);

        $result2 = $decorator->read(20);
        $this->assertEquals(20, strlen($result2));
        $this->assertEquals(str_repeat('a', 12) . str_repeat('b', 8), $result2);

        $result3 = $decorator->read(24);
        $this->assertEquals(24, strlen($result3));
        $this->assertEquals(str_repeat('b', 24), $result3);

        $this->assertEmpty($decorator->read(1));
        $this->assertTrue($decorator->eof());
    }

    public function testBufferExactChunkSize(): void
    {
        $testData = str_repeat('x', 64);
        $readCalls = [];

        $this->encryptor->expects($this->once())
            ->method('update')
            ->with($testData)
            ->willReturn($testData);

        $this->stream->method('read')
            ->willReturnCallback(function($length) use ($testData, &$readCalls) {
                $readCalls[] = $length;
                return count($readCalls) === 1 ? $testData : '';
            });

        $this->stream->method('eof')
            ->willReturnOnConsecutiveCalls(false, true);

        $decorator = new EncryptedStreamDecorator($this->stream, $this->encryptor, 64);

        $result = $decorator->read(64);
        $this->assertEquals(64, strlen($result));
        $this->assertEquals($testData, $result);

        $this->assertCount(1, $readCalls);
        $this->assertGreaterThanOrEqual(16, $readCalls[0]);
        $this->assertLessThanOrEqual(64, $readCalls[0]);

        $this->assertEmpty($decorator->read(1));
        $this->assertTrue($decorator->eof());
    }

    public function testBufferMultipleChunks(): void
    {
        $chunk1 = str_repeat('a', 32);
        $chunk2 = str_repeat('b', 32);
        $chunk3 = str_repeat('c', 16);

        $this->encryptor->expects($this->exactly(3))
            ->method('update')
            ->willReturnOnConsecutiveCalls(
                $chunk1,
                $chunk2,
                $chunk3
            );

        $this->stream->method('read')
            ->willReturnOnConsecutiveCalls(
                'source_chunk1',
                'source_chunk2',
                'source_chunk3',
                ''
            );

        $decorator = new EncryptedStreamDecorator($this->stream, $this->encryptor, 32);

        $result1 = $decorator->read(48);
        $this->assertEquals(48, strlen($result1));
        $this->assertEquals($chunk1 . substr($chunk2, 0, 16), $result1);

        $result2 = $decorator->read(32);
        $this->assertEquals(32, strlen($result2));
        $this->assertEquals(substr($chunk2, 16) . $chunk3, $result2);

        $this->assertEmpty($decorator->read(1));
        $this->assertTrue($decorator->eof());
    }
}
