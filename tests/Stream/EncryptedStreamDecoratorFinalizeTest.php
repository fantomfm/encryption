<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorFinalizeTest extends TestCase
{
    private StreamInterface $stream;
    private MediaCipherInterface $encryptor;
    private EncryptedStreamDecorator $decorator;

    private string $mockMac = '__MAC__';

    protected function setUp(): void
    {
        $this->stream = $this->createMock(StreamInterface::class);
        $this->stream->method('isReadable')->willReturn(true);
        $this->stream->method('getSize')->willReturn(1024);

        $this->encryptor = $this->createMock(MediaCipherInterface::class);
        $this->encryptor->method('getBlockSize')->willReturn(16);

        $this->decorator = new EncryptedStreamDecorator($this->stream, $this->encryptor);
    }

    public function testFinalizeCalledOnce(): void
    {
        $this->encryptor->expects($this->once())
            ->method('finish')
            ->willReturn('final_mac');

        $this->decorator->close();

        $this->decorator->close();
    }

    public function testFinalizeAppendsMac(): void
    {
        $this->encryptor->method('finish')->willReturn($this->mockMac);
        $this->encryptor->method('update')->willReturn('test_data');

        
        $this->stream->method('getContents')->willReturn('test_data');

        $contents = $this->decorator->getContents();

        $this->assertStringEndsWith($this->mockMac, $contents);
    }
}