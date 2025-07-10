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

    public function testDecryptionConsistencyWithChunkedReading(): void
    {
        $mediaKey = self::MEDIA_KEY;
        $mediaType = MediaType::VIDEO;
        $original = random_bytes(1024 * 1024);

        $fullStream = $this->createStreamFromString($original);
        $fullEncryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
        $fullEncryptedStream = new EncryptedStreamDecorator(
            $fullStream,
            $fullEncryptor
        );
        $fullEncrypted = $fullEncryptedStream->getContents();

        $encryptStream = $this->createStreamFromString($fullEncrypted);
        $chunkedDecryptor = new WhatsAppMediaDecryptor($mediaKey, $mediaType);
        $chunkedDecryptedStream = new DecryptedStreamDecorator(
            $encryptStream,
            $chunkedDecryptor
        );

        $chunkedDecrypted = '';
        while (!$chunkedDecryptedStream->eof()) {
            $chunkedDecrypted .= $chunkedDecryptedStream->read(1024);
        }

        $this->assertSame($original, $chunkedDecrypted);
    }

    private function createStreamFromString(string $content): StreamInterface
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
