<?php

declare(strict_types=1);

namespace EncryptionTest\Integration;

use Encryption\Enum\MediaType;
use Encryption\Stream\EncryptedStreamDecorator;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use Encryption\WhatsApp\WhatsAppMediaStreamInfoGenerator;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Stream;

class FileSidecarTest extends TestCase
{
    private const ORIGINAL_FILE = __DIR__ . '/files/VIDEO.original';
    private const ENCRYPTED_FILE = __DIR__ . '/files/VIDEO.encrypted';
    private const KEY_FILE = __DIR__ . '/files/VIDEO.key';
    private const SIDECAR_FILE = __DIR__ . '/files/VIDEO.sidecar';

    private const MEDIA_TYPE = MediaType::VIDEO;

    public function testFileEncryptionMatchesPrecomputedResult(): void
    {
        $originalContent = file_get_contents(self::ORIGINAL_FILE);
        $expectedEncryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));
        $expectedSideCar = file_get_contents(self::SIDECAR_FILE);

        $stream = $this->createStreamFromString($originalContent);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, self::MEDIA_TYPE);
        $sidecarGenerator = new WhatsAppMediaStreamInfoGenerator($encryptor->getMacKey(), $encryptor->getIv());
        $decorator = new EncryptedStreamDecorator($stream, $encryptor, sidecar: $sidecarGenerator);

        $actualEncryptedContent = $decorator->getContents();
        $actualSidecar = $decorator->getSidecar();

        $this->assertNotEmpty($actualEncryptedContent);
        $this->assertNotEquals($originalContent, $actualEncryptedContent);
        $this->assertSame($expectedEncryptedContent, $actualEncryptedContent);
        $this->assertSame($expectedSideCar, $actualSidecar);
    }

    public function testSidecar(): void
    {
        $expectedEncryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));
        $expectedSideCar = file_get_contents(self::SIDECAR_FILE);

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, self::MEDIA_TYPE);
        $sidecarGenerator = new WhatsAppMediaStreamInfoGenerator($encryptor->getMacKey(), $encryptor->getIv());

        $sidecarGenerator->update($expectedEncryptedContent);
        $actualSidecar = $sidecarGenerator->finish();

        $this->assertSame($expectedSideCar, $actualSidecar);
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

    private function createStreamFromString(string $content): Stream
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
