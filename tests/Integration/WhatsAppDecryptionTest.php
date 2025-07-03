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
            // 0 => 'Empty stream',
            // 1 => '1 byte',
            // 15 => 'Smaller than block size',
            16 => 'Exactly block size',
            // 17 => 'Just over block size',
            // 1024 => '1KB',
            // 1024 * 1024 => '1MB'
        ];

        $mediaKey = self::MEDIA_KEY;
        $mediaType = MediaType::IMAGE;

        foreach ($sizes as $size => $description) {
            $plaintext = $size > 0 ? random_bytes($size) : '';

            $stream = $this->createStreamFromString($plaintext);
            $encryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
            $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor);

            $encryptedContent = $encryptedStream->getContents();

            $this->assertNotEmpty($encryptedContent, "Encrypted content should not be empty for $description");

            if ($size > 0) {
                $this->assertNotEquals(
                    $plaintext,
                    $encryptedContent,
                    "Encrypted content should differ from plaintext for $description"
                );

                $this->assertGreaterThanOrEqual(
                    10,
                    strlen($encryptedContent) - $size,
                    "MAC should be present for $description"
                );
            }

            $stream = $this->createStreamFromString($encryptedContent);
            $decryptor = new WhatsAppMediaDecryptor($mediaKey, $mediaType);
            $decryptedStream = new DecryptedStreamDecorator($stream, $decryptor);

            $decryptedContent = $decryptedStream->getContents();
            // $chunk = '';
            // while (!$decryptedStream->eof()) {
            //     $chunk .= $decryptedStream->read(1024);
            // }

            $this->assertSame($plaintext, $decryptedContent);
        }
    }

    public function testMemoryUsageWithLargeStream(): void
    {
        $mediaKey = self::MEDIA_KEY;
        $mediaType = MediaType::VIDEO;

        $memoryBefore = memory_get_usage();

        $stream = new Stream(fopen(self::TEST_FILE, 'r'));
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
        $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor, 65536);

        $totalRead = 0;
        $fileSize = filesize(self::TEST_FILE);

        while (!$encryptedStream->eof()) {
            $chunk = $encryptedStream->read(65536);
            $totalRead += strlen($chunk);

            $memoryUsage = memory_get_usage() - $memoryBefore;
            $this->assertLessThan(
                5 * 1024 * 1024, // 5MB max expected memory growth
                $memoryUsage,
                "Memory usage should stay reasonable when processing large stream (currently using {$memoryUsage} bytes)"
            );
        }

        $this->assertGreaterThanOrEqual(
            $fileSize,
            $totalRead,
            'Encrypted output should be larger than input due to padding and MAC'
        );

        $stream->close();
    }

    public function testStreamReadMethods(): void
    {
        $plaintext = random_bytes(1024 * 10);
        $stream = $this->createStreamFromString($plaintext);

        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, MediaType::DOCUMENT);
        $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor, 8192);

        $firstChunk = $encryptedStream->read(1024);
        $this->assertSame(1024, strlen($firstChunk));

        $remaining = $encryptedStream->getContents();
        $this->assertGreaterThan(0, strlen($remaining));

        $stream2 = $this->createStreamFromString($plaintext);
        $encryptor2 = new WhatsAppMediaEncryptor(self::MEDIA_KEY, MediaType::DOCUMENT);
        $encryptedStream2 = new EncryptedStreamDecorator($stream2, $encryptor2);
        $fullContent = (string)$encryptedStream2;
        $this->assertNotEmpty($fullContent);
    }

    private function createStreamFromString(string $content): StreamInterface
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
