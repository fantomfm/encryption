<?php

declare(strict_types=1);

namespace EncryptionTest\Integration;

use Encryption\Enum\MediaType;
use Encryption\Stream\DecryptedStreamDecorator;
use Encryption\WhatsApp\WhatsAppMediaDecryptor;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Stream;

class FileDecryptionTest extends TestCase
{
    private const ORIGINAL_FILE = __DIR__ . '/files/VIDEO.original';
    private const ENCRYPTED_FILE = __DIR__ . '/files/VIDEO.encrypted';
    private const KEY_FILE = __DIR__ . '/files/VIDEO.key';

    private const MEDIA_TYPE = MediaType::VIDEO;

    public function testFileDecryptionMatchesPrecomputedResult(): void
    {
        $expectedOriginalContent = file_get_contents(self::ORIGINAL_FILE);
        $encryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));

        $stream = $this->createStreamFromString($encryptedContent);
        $decryptor = new WhatsAppMediaDecryptor($mediaKey, self::MEDIA_TYPE);
        $stream = new DecryptedStreamDecorator($stream, $decryptor);

        $actualDecryptedContent = $stream->getContents();

        $this->assertNotEmpty($actualDecryptedContent);
        $this->assertNotEquals($encryptedContent, $actualDecryptedContent);
        $this->assertSame($expectedOriginalContent, $actualDecryptedContent);
    }

    public function testFileDecryptionInChunks(): void
    {
        $expectedOriginalContent = file_get_contents(self::ORIGINAL_FILE);
        $encryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));

        $stream = $this->createStreamFromString($encryptedContent);
        $decryptor = new WhatsAppMediaDecryptor($mediaKey, self::MEDIA_TYPE);
        $stream = new DecryptedStreamDecorator($stream, $decryptor);

        $actualDecryptedContent = '';
        while (!$stream->eof()) {
            $chunk = $stream->read(10);
            $actualDecryptedContent .= $chunk;
        }

        $this->assertSame($expectedOriginalContent, $actualDecryptedContent);
    }

    private function createStreamFromString(string $content): Stream
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
