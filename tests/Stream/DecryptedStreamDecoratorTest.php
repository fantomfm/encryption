<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Stream\DecryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use Encryption\Exception\StreamException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class DecryptedStreamDecoratorTest extends TestCase
{
    use PropertyTrait;

    private $stream;
    private $decryptor;
    private $decorator;

    private const BLOCK_SIZE = 16;
    private const MAC_SIZE = 10;

    protected function setUp(): void
    {
        $this->stream = $this->createMock(StreamInterface::class);
        $this->decryptor = $this->createMock(MediaCipherInterface::class);
        
        $this->decryptor->method('getBlockSize')->willReturn(16);
        $this->decryptor->method('getMacSize')->willReturn(10);
        
        $this->stream->method('isReadable')->willReturn(true);
        
        $this->decorator = new DecryptedStreamDecorator($this->stream, $this->decryptor);
    }

    public function testConstructorWithNonReadableStream()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Stream must be readable');
        
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isReadable')->willReturn(false);
        
        new DecryptedStreamDecorator($stream, $this->decryptor);
    }

    public function testConstructorWithSmallChunkSize()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Chunk size must be at least 16 bytes');
        
        new DecryptedStreamDecorator($this->stream, $this->decryptor, 8);
    }

    public function testClose()
    {
        $this->stream->expects($this->once())->method('close');
        $this->decryptor->expects($this->once())->method('finish');
        
        $this->decorator->close();
        
        $this->assertTrue($this->decorator->eof());
        $this->assertSame('', $this->getPrivateProperty($this->decorator, 'buffer'));
    }

    public function testDetach()
    {
        $resource = fopen('php://memory', 'r');
        $this->stream->method('detach')->willReturn($resource);
        
        $this->decryptor->expects($this->once())->method('finish');
        
        $result = $this->decorator->detach();
        
        $this->assertSame($resource, $result);
        $this->assertTrue($this->decorator->eof());
        $this->assertSame('', $this->getPrivateProperty($this->decorator, 'buffer'));
    }

    public function testGetSizeAlwaysReturnsNull()
    {
        $this->assertNull($this->decorator->getSize());
    }

    public function testTell()
    {
        $this->assertSame(0, $this->decorator->tell());
        
        $this->setPrivateProperty($this->decorator, 'position', 42);
        $this->assertSame(42, $this->decorator->tell());
    }

    public function testEof()
    {
        $this->assertFalse($this->decorator->eof());
        
        $this->setPrivateProperty($this->decorator, 'sourceEof', true);
        $this->assertTrue($this->decorator->eof());
        
        $this->setPrivateProperty($this->decorator, 'buffer', 'data');
        $this->assertFalse($this->decorator->eof());
    }

    public function testIsSeekable()
    {
        $this->assertFalse($this->decorator->isSeekable());
    }

    public function testSeekThrowsException()
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Decrypted stream does not support seeking');
        
        $this->decorator->seek(0);
    }

    public function testRewindThrowsException()
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Decrypted stream does not support seeking');
        
        $this->decorator->rewind();
    }

    public function testIsWritable()
    {
        $this->assertFalse($this->decorator->isWritable());
    }

    public function testWriteThrowsException()
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Cannot write to an decrypted read-only stream');
        
        $this->decorator->write('data');
    }

    public function testIsReadable()
    {
        $this->assertTrue($this->decorator->isReadable());
    }

    public function testReadWithEof()
    {
        $this->setPrivateProperty($this->decorator, 'sourceEof', true);
        $this->assertSame('', $this->decorator->read(10));
    }

    public function testReadFromBuffer()
    {
        $this->setPrivateProperty($this->decorator, 'buffer', 'test data');
        
        $result = $this->decorator->read(4);
        $this->assertSame('test', $result);
        $this->assertSame(' data', $this->getPrivateProperty($this->decorator, 'buffer'));
        $this->assertSame(4, $this->decorator->tell());
    }

    public function testReadWithPartialBuffer()
    {
        $this->setPrivateProperty($this->decorator, 'buffer', 'partial');
    
        $encryptedData = str_repeat('E', self::BLOCK_SIZE);
        $mac = str_repeat('X', self::MAC_SIZE);
        $finalChunk = $encryptedData . $mac;
        
        $this->stream->method('eof')->willReturn(false, true);
        $this->stream->method('read')->willReturn($finalChunk);
        $this->decryptor->method('update')->willReturn('_more_data');
        $this->decryptor->method('finish')->willReturn('_final');
        
        $result = $this->decorator->read(23);
        
        $this->assertSame('partial_more_data_final', $result);
    }

    public function testReadWithStreamData(): void
    {
        $this->stream->method('eof')
            ->willReturnOnConsecutiveCalls(false, false, true);
        
        $this->stream->method('read')
            ->willReturnCallback(function($length) {
                static $callCount = 0;
                $callCount++;
                
                if ($callCount === 1) {
                    return '16B_ENCRYPTED_DA';
                }
                
                if ($callCount === 2) {
                    return str_repeat('E', 16) . str_repeat('X', 10);
                }
                
                return '';
            });
        
        $this->decryptor->method('update')
            ->willReturnCallback(function($chunk) {
                if ($chunk === '16B_ENCRYPTED_DA') {
                    return '16B_DECRYPTED_D';
                }
                return '';
            });
        $this->decryptor->method('finish')
            ->with('')
            ->willReturn('_VERIFIED');
        
        $result1 = $this->decorator->read(10);
        $this->assertEquals('16B_DECRYP', $result1);
        
        $result2 = $this->decorator->read(6);
        $this->assertEquals('TED_D', $result2);
        
        $result3 = $this->decorator->read(1024);
        $this->assertEquals('_VERIFIED', $result3);
        
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsWithEof()
    {
        $this->setPrivateProperty($this->decorator, 'sourceEof', true);
        $this->assertSame('', $this->decorator->getContents());
    }

    public function testGetContentsWithSmallStream()
    {
        $this->stream->method('getSize')->willReturn(100);
        $this->stream->method('getContents')->willReturn('small_encrypted_data');
        $this->decryptor->method('update')->willReturn('decrypted_');
        $this->decryptor->method('finish')->willReturn('data');
        
        $result = $this->decorator->getContents();
        
        $this->assertSame('decrypted_data', $result);
        $this->assertTrue($this->decorator->eof());
    }

    public function testGetContentsWithLargeStream()
    {
        $this->stream->method('getSize')->willReturn(100000);
        $this->stream->method('eof')->willReturn(false, false, true);
        $this->stream->method('read')->willReturn('chunk1', 'chunk2');
        $this->decryptor->method('update')->willReturn('decrypted1', 'decrypted2');
        $this->decryptor->method('finish')->willReturn('_final');
        
        $result = $this->decorator->getContents();
        
        $this->assertSame('decrypted1decrypted2_final', $result);
    }

    public function testGetMetadata()
    {
        $metadata = ['key' => 'value'];
    
        $this->stream->expects($this->exactly(2))
            ->method('getMetadata')
            ->withConsecutive(
                [null],
                ['key']
            )
            ->willReturnOnConsecutiveCalls(
                $metadata,
                'value'
            );
        
        $this->assertSame($metadata, $this->decorator->getMetadata());
        
        $this->assertSame('value', $this->decorator->getMetadata('key'));
    }

    public function testGetDecryptedFinal()
    {
        $finalChunk = str_repeat('a', 32) . 'final_part';
        $this->decryptor->method('update')->willReturn('decrypted_');
        $this->decryptor->method('finish')->willReturn('final');
        
        $result = $this->invokePrivateMethod($this->decorator, 'getDecryptedFinal', [$finalChunk]);
        
        $this->assertSame('decrypted_final', $result);
    }

    public function testFinalize()
    {
        $this->decryptor->method('finish')->willReturn('final_data');
        
        $result = $this->invokePrivateMethod($this->decorator, 'finalize', ['chunk']);
        
        $this->assertSame('final_data', $result);
        $this->assertTrue($this->getPrivateProperty($this->decorator, 'finalized'));
    }

    public function testFinalizeAlreadyFinalized()
    {
        $this->setPrivateProperty($this->decorator, 'finalized', true);
        
        $result = $this->invokePrivateMethod($this->decorator, 'finalize');
        
        $this->assertSame('', $result);
    }

    public function testCalculateReadSize()
    {
        $this->assertSame(16, $this->invokePrivateMethod($this->decorator, 'calculateReadSize', [8]));
        
        $this->assertSame(32, $this->invokePrivateMethod($this->decorator, 'calculateReadSize', [32]));
        
        $this->assertSame(65536, $this->invokePrivateMethod($this->decorator, 'calculateReadSize', [100000]));
    }

    public function testExtractFromBuffer()
    {
        $this->setPrivateProperty($this->decorator, 'buffer', 'test data');
        
        $result = $this->invokePrivateMethod($this->decorator, 'extractFromBuffer', [4]);
        
        $this->assertSame('test', $result);
        $this->assertSame(' data', $this->getPrivateProperty($this->decorator, 'buffer'));
        $this->assertSame(4, $this->decorator->tell());
    }

    public function testGetFinalOffsetSize()
    {
        $this->assertSame(26, $this->invokePrivateMethod($this->decorator, 'getFinalOffsetSize'));
    }
}