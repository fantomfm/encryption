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

    public function testFileSidecarGenerationMatchesPrecomputedResult(): void
    {
        $expectedEncryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));
        $expectedSideCar = file_get_contents(self::SIDECAR_FILE);

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, self::MEDIA_TYPE);
        $sidecarGenerator = new WhatsAppMediaStreamInfoGenerator($encryptor->getMacKey(), $encryptor->start());

        $sidecarGenerator->update($expectedEncryptedContent);
        $actualSidecar = $sidecarGenerator->finish();

        $this->assertSame($expectedSideCar, $actualSidecar);
    }

    public function testFileGenerationSidecarWithEncryptionStream(): void
    {
        $originalContent = file_get_contents(self::ORIGINAL_FILE);
        $expectedEncryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));
        $expectedSideCar = file_get_contents(self::SIDECAR_FILE);

        $stream = $this->createStreamFromString($originalContent);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, self::MEDIA_TYPE);
        $sidecarGenerator = new WhatsAppMediaStreamInfoGenerator($encryptor->getMacKey(), $encryptor->start());
        $decorator = new EncryptedStreamDecorator($stream, $encryptor, sidecar: $sidecarGenerator);

        $actualEncryptedContent = $decorator->getContents();
        $actualSidecar = $decorator->getSidecar();

        $this->assertSame($expectedEncryptedContent, $actualEncryptedContent);
        $this->assertSame($expectedSideCar, $actualSidecar);
    }

    public function testFileGenerationSidecarWithEncryptionInChunks(): void
    {
        $originalContent = file_get_contents(self::ORIGINAL_FILE);
        $mediaKey = trim(file_get_contents(self::KEY_FILE));
        $expectedSideCar = file_get_contents(self::SIDECAR_FILE);

        $stream = $this->createStreamFromString($originalContent);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, self::MEDIA_TYPE);
        $sidecarGenerator = new WhatsAppMediaStreamInfoGenerator($encryptor->getMacKey(), $encryptor->start());
        $decorator = new EncryptedStreamDecorator($stream, $encryptor, 1024, $sidecarGenerator);

        $actualEncryptedContent = '';
        while (!$decorator->eof()) {
            $chunk = $decorator->read(1024);
            $actualEncryptedContent .= $chunk;
        }

        $expectedEncryptedContent = file_get_contents(self::ENCRYPTED_FILE);
        $actualSidecar = $decorator->getSidecar();

        $this->assertSame($expectedEncryptedContent, $actualEncryptedContent);
        $this->assertSame($expectedSideCar, $actualSidecar);
    }

    private function createStreamFromString(string $content): Stream
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $content);
        rewind($stream);
        return new Stream($stream);
    }
}
