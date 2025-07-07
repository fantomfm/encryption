<?php

declare(strict_types=1);

namespace EncryptionTest\Stream;

use Encryption\Exception\EncryptionException;
use Encryption\Exception\StreamException;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\Interface\MediaCipherInterface;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class EncryptedStreamDecoratorTest extends TestCase
{
    use PropertyTrait;

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

    protected function tearDown(): void
    {
        unset($this->decorator, $this->stream, $this->encryptor);
    }

    public function testConstructorWithNonReadableStream()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Stream must be readable');
        
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isReadable')->willReturn(false);
        
        new EncryptedStreamDecorator($stream, $this->encryptor);
    }

    public function testConstructorWithSmallChunkSize()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Chunk size must be at least 16 bytes');
        
        new EncryptedStreamDecorator($this->stream, $this->encryptor, 8);
    }

    public function testConstructorPassesWithReadableStream(): void
    {
        $decorator = new EncryptedStreamDecorator(
            $this->stream,
            $this->encryptor,
            1024
        );

        $this->assertInstanceOf(EncryptedStreamDecorator::class, $decorator);
    }

    public function testSetsProperties(): void
    {
        $stream = $this->stream;
        $encryptor = $this->encryptor;
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

    public function testClose()
    {
        $this->stream->expects($this->once())->method('close');
        $this->encryptor->expects($this->once())->method('finish');
        
        $this->decorator->close();
        
        $this->assertTrue($this->decorator->eof());
        $this->assertSame('', $this->getPrivateProperty($this->decorator, 'buffer'));
    }

    public function testCloseIsIdempotent(): void
    {
        $this->decorator->close();
        $this->assertTrue($this->decorator->eof());

        $this->decorator->close();
        $this->assertSame('', $this->decorator->read(10));
    }

    public function testDetach()
    {
        $resource = fopen('php://memory', 'r');
        $this->stream->method('detach')->willReturn($resource);
        
        $this->encryptor->expects($this->once())->method('finish');
        
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

    public function testTellReturnsZeroInitially(): void
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

    public function testTellUpdatesAfterGetContents(): void
    {
        $testData = str_repeat('c', 200);

        $this->stream->method('getSize')->willReturn(200);
        $this->stream->method('getContents')->willReturn($testData);
        $this->stream->method('read')->willReturn($testData);

        $contents = $this->decorator->getContents();

        $expectedPosition = mb_strlen($testData, '8bit') + mb_strlen(self::MOCK_MAC, '8bit');
        $this->assertEquals($expectedPosition, $this->decorator->tell());
    }

    public function testTellPositionNotAffectedByMac(): void
    {
        $this->stream->method('read')->willReturn('data');

        $this->decorator->read(4);
        $this->decorator->close();

        $this->assertEquals(4, $this->decorator->tell());
    }

    public function testTellWithEmptyReads(): void
    {
        $this->stream->method('read')->willReturn('');
        $this->decorator->read(100);

        $this->assertEquals(mb_strlen(self::MOCK_MAC, '8bit'), $this->decorator->tell());
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
        $this->expectExceptionMessage('Encrypted stream does not support seeking');
        
        $this->decorator->seek(0);
    }

    public function testRewindThrowsException()
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Encrypted stream does not support seeking');
        
        $this->decorator->rewind();
    }

    public function testIsWritable()
    {
        $this->assertFalse($this->decorator->isWritable());
    }

    public function testWriteThrowsException()
    {
        $this->expectException(StreamException::class);
        $this->expectExceptionMessage('Cannot write to an encrypted read-only stream');
        
        $this->decorator->write('data');
    }

    public function testIsReadable()
    {
        $this->assertTrue($this->decorator->isReadable());
    }

    public function testFinalizeCalledOnce(): void
    {
        $this->encryptor->expects($this->once())
            ->method('finish')
            ->willReturn('final_mac');

        $this->decorator->close();

        $this->decorator->close();
    }

    public function testReadEmptyStreamReturnsEmptyString(): void
    {
        $this->stream->method('read')->willReturn('');
        $this->stream->method('eof')->willReturn(true);

        $result = $this->decorator->read(100);

        $this->assertSame(self::MOCK_MAC, $result);
        $this->assertSame(mb_strlen(self::MOCK_MAC, '8bit'), $this->decorator->tell());
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
        $this->assertSame(self::MOCK_MAC, $secondRead);
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

    public function testReadCorruptedStreamHandling(): void
    {
        $this->stream->method('read')->willReturn('corrupted_data');

        $this->encryptor->method('update')
            ->willThrowException(new \RuntimeException('Decryption failed'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Decryption failed');

        $this->decorator->read(16);
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
}
