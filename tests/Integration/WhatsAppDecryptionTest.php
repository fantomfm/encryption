<?php

declare(strict_types=1);

namespace EncryptionTest\Integration;

use Encryption\Enum\MediaType;
use Encryption\Stream\DecryptedStreamDecorator;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\WhatsApp\WhatsAppMediaDecryptor;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use GuzzleHttp\Psr7\Stream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class WhatsAppDecryptionTest extends TestCase
{
    private const MEDIA_KEY = '0123456789abcdef0123456789abcdef';
    private const TEST_FILE = __DIR__ . '/testfile.bin';

    public static function setUpBeforeClass(): void
    {
        file_put_contents(self::TEST_FILE, random_bytes(1024 * 1024));
    }

    public static function tearDownAfterClass(): void
    {
        if (file_exists(self::TEST_FILE)) {
            unlink(self::TEST_FILE);
        }
    }

    public function testVariousStreamSizes(): void
    {
        $sizes = [
            0 => 'Empty stream',
            1 => '1 byte',
            15 => 'Smaller than block size',
            16 => 'Exactly block size',
            17 => 'Just over block size',
            1024 => '1KB',
            1024 * 1024 => '1MB'
        ];

        $mediaKey = self::MEDIA_KEY;
        $mediaType = MediaType::IMAGE;

        foreach ($sizes as $size => $description) {
            $plaintext = $size > 0 ? str_repeat('A', $size) : '';

            $stream = $this->createStreamFromString($plaintext);
            $encryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
            $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor);

            $encryptedContent = $encryptedStream->getContents();

            $stream = $this->createStreamFromString($encryptedContent);
            $decryptor = new WhatsAppMediaDecryptor($mediaKey, $mediaType);
            $decryptedStream = new DecryptedStreamDecorator($stream, $decryptor);

            $decryptedContent = $decryptedStream->getContents();

            $this->assertSame($plaintext, $decryptedContent);
        }
    }

    private function createStreamFromString(string $content): StreamInterface
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
