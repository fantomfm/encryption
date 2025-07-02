<?php

declare(strict_types=1);

namespace EncryptionTest\Integration;

use Encryption\Enum\MediaType;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Stream;

class FileEncryptionTest extends TestCase
{
    private const ORIGINAL_FILE = __DIR__ . '/files/VIDEO.original';
    private const ENCRYPTED_FILE = __DIR__ . '/files/VIDEO.encrypted';
    private const KEY_FILE = __DIR__ . '/files/VIDEO.key';

    private const MEDIA_TYPE = MediaType::VIDEO;

    public function testFileEncryptionMatchesPrecomputedResult(): void
    {
        $originalContent = file_get_contents(self::ORIGINAL_FILE);
        $expectedEncryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));

        $stream = $this->createStreamFromString($originalContent);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, self::MEDIA_TYPE);
        $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor);

        $actualEncryptedContent = $encryptedStream->getContents();

        $this->assertNotEmpty($actualEncryptedContent);
        $this->assertNotEquals($originalContent, $actualEncryptedContent);
        $this->assertSame($expectedEncryptedContent, $actualEncryptedContent);
    }

    public function testFileEncryptionInChunks(): void
    {
        $originalContent = file_get_contents(self::ORIGINAL_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));

        $stream = $this->createStreamFromString($originalContent);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, self::MEDIA_TYPE);
        $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor, 1024);

        $actualEncryptedContent = '';
        while (!$encryptedStream->eof()) {
            $chunk = $encryptedStream->read(1024);
            $actualEncryptedContent .= $chunk;
        }

        $expectedEncryptedContent = file_get_contents(self::ENCRYPTED_FILE);

        $this->assertSame($expectedEncryptedContent, $actualEncryptedContent);
    }

    public function testEncryptedStreamMetadata(): void
    {
        $stream = new Stream(fopen(self::ORIGINAL_FILE, 'r'));
        $encryptor = new WhatsAppMediaEncryptor(trim(file_get_contents(self::KEY_FILE)), self::MEDIA_TYPE);
        $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor);

        $this->assertTrue($encryptedStream->isReadable());
        $this->assertFalse($encryptedStream->isWritable());
        $this->assertFalse($encryptedStream->isSeekable());
        $this->assertNull($encryptedStream->getSize());
    }

    private function createStreamFromString(string $content): Stream
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
