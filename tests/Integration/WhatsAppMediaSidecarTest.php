<?php

declare(strict_types=1);

namespace EncryptionTest\Integration;

use Encryption\Enum\MediaType;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use Encryption\WhatsApp\WhatsAppMediaStreamInfoGenerator;
use GuzzleHttp\Psr7\Stream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class WhatsAppMediaSidecarTest extends TestCase
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

    public function testSidecarGenerationForVariousSizes(): void
    {
        $sizes = [
            0 => 'Empty stream',
            1 => '1 byte',
            15 => 'Smaller than block size',
            16 => 'Exactly block size',
            17 => 'Just over block size',
            1024 => '1KB',
            65536 => '64KB',
            65537 => '64KB + 1 byte',
            1024 * 1024 => '1MB'
        ];

        $mediaKey = self::MEDIA_KEY;
        $mediaType = MediaType::VIDEO;

        foreach ($sizes as $size => $description) {
            $plaintext = $size > 0 ? random_bytes($size) : '';

            $stream = $this->createStreamFromString($plaintext);
            $encryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
            $sidecarGenerator = new WhatsAppMediaStreamInfoGenerator(
                $encryptor->getMacKey(),
                $encryptor->start()
            );
            $encryptedStream = new EncryptedStreamDecorator($stream, $encryptor, 65536, $sidecarGenerator);

            $encryptedContent = $encryptedStream->getContents();
            $sidecar = $encryptedStream->getSidecar();

            $expectedSidecarSize = (int)ceil(($size + 16) / 65536) * 10;
            $this->assertSame(
                $expectedSidecarSize,
                strlen($sidecar),
                "Sidecar size mismatch for {$description}"
            );
        }
    }

    public function testSidecarConsistencyWithChunkedReading(): void
    {
        $mediaKey = self::MEDIA_KEY;
        $mediaType = MediaType::VIDEO;
        $plaintext = random_bytes(1024 * 1024);

        $fullStream = $this->createStreamFromString($plaintext);
        $fullEncryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
        $fullSidecarGenerator = new WhatsAppMediaStreamInfoGenerator(
            $fullEncryptor->getMacKey(),
            $fullEncryptor->start()
        );
        $fullEncryptedStream = new EncryptedStreamDecorator(
            $fullStream,
            $fullEncryptor,
            65536,
            $fullSidecarGenerator
        );
        $fullEncryptedStream->getContents();
        $fullSidecar = $fullEncryptedStream->getSidecar();

        $chunkedStream = $this->createStreamFromString($plaintext);
        $chunkedEncryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
        $chunkedSidecarGenerator = new WhatsAppMediaStreamInfoGenerator(
            $chunkedEncryptor->getMacKey(),
            $chunkedEncryptor->start()
        );
        $chunkedEncryptedStream = new EncryptedStreamDecorator(
            $chunkedStream,
            $chunkedEncryptor,
            65536,
            $chunkedSidecarGenerator
        );

        while (!$chunkedEncryptedStream->eof()) {
            $chunkedEncryptedStream->read(16384);
        }
        $chunkedSidecar = $chunkedEncryptedStream->getSidecar();

        $this->assertSame(
            bin2hex($fullSidecar),
            bin2hex($chunkedSidecar),
            'Sidecar should be identical regardless of reading method'
        );
    }

    public function testSidecarWithPrecomputedData(): void
    {
        $mediaKey = self::MEDIA_KEY;
        $mediaType = MediaType::VIDEO;

        $testData = random_bytes(65536 + 16);

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
        $sidecarGenerator = new WhatsAppMediaStreamInfoGenerator(
            $encryptor->getMacKey(),
            $encryptor->start()
        );

        $firstChunk = substr($testData, 0, 65536);
        $secondChunk = substr($testData, 65536);

        $sidecarGenerator->update($firstChunk);
        $sidecarGenerator->update($secondChunk);
        $sidecar = $sidecarGenerator->finish();

        $this->assertSame(20, strlen($sidecar));

        $firstSignature = substr($sidecar, 0, 10);
        $secondSignature = substr($sidecar, 10, 10);

        $this->assertNotEquals(
            bin2hex($firstSignature),
            bin2hex($secondSignature),
            'Signatures for different chunks should differ'
        );
    }

    private function createStreamFromString(string $content): StreamInterface
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
