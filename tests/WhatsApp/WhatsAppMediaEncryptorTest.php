<?php

namespace EncryptionTest\WhatsApp;

use Encryption\Enum\MediaType;
use Encryption\Exception\EncryptionException;
use Encryption\Interface\MediaCipherInterface;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class WhatsAppMediaEncryptorTest extends TestCase
{
    private const KEY_EXPANSION_LENGTH = 112;
    private const MEDIA_TYPE = MediaType::IMAGE;
    private const BLOCK_SIZE = 16;
    private const MAC_SIZE = 10;

    private MediaCipherInterface $encryptor;

    protected function setUp(): void
    {
        $this->encryptor = new WhatsAppMediaEncryptor(random_bytes(32), self::MEDIA_TYPE);
    }

    public function testConstructorThrowsOnInvalidMediaKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new WhatsAppMediaEncryptor(random_bytes(16), MediaType::IMAGE);
    }

    public function testConstructorInitializesKeysCorrectly(): void
    {
        $mediaKey = random_bytes(32);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::VIDEO);

        $this->assertIsString($encryptor->start());
        $this->assertEquals(16, mb_strlen($encryptor->start(), '8bit'));
    }

    public function testExpandMediaKeyReturnsCorrectLength(): void
    {
        $method = new ReflectionMethod(WhatsAppMediaEncryptor::class, 'expandMediaKey');
        $method->setAccessible(true);

        $result = $method->invoke($this->encryptor, random_bytes(32), self::KEY_EXPANSION_LENGTH, self::MEDIA_TYPE);

        $this->assertEquals(self::KEY_EXPANSION_LENGTH, mb_strlen($result, '8bit'));
    }

    public function testSplitExpandedKeyReturnsValidParts(): void
    {
        $method = new ReflectionMethod(WhatsAppMediaEncryptor::class, 'splitExpandedKey');
        $method->setAccessible(true);

        $expandedKey = random_bytes(self::KEY_EXPANSION_LENGTH);
        [$iv, $cipherKey, $macKey] = $method->invoke($this->encryptor, $expandedKey);

        $this->assertEquals(16, mb_strlen($iv, '8bit'));
        $this->assertEquals(32, mb_strlen($cipherKey, '8bit'));
        $this->assertEquals(32, mb_strlen($macKey, '8bit'));
    }

    public function testFinishAddsMacAtTheEnd(): void
    {
        $data = random_bytes(32);
        $final = $this->encryptor->update($data);
        $final .= $this->encryptor->finish();

        $mac = substr($final, -10);
        $this->assertEquals(10, mb_strlen($mac, '8bit'));

        $otherData = str_repeat('X', mb_strlen($data, '8bit'));
        $otherEncrypted = new WhatsAppMediaEncryptor(random_bytes(32), MediaType::VIDEO);
        $otherFinal = $otherEncrypted->update($otherData);
        $otherFinal .= $otherEncrypted->finish();

        $this->assertNotSame($final, $otherFinal);
    }

    public function testMultipleUpdatesWorkCorrectly(): void
    {
        $part1 = str_repeat("A", 1024);
        $part2 = str_repeat("B", 2048);
        $part3 = str_repeat("C", 4096);

        $out1 = $this->encryptor->update($part1);
        $out2 = $this->encryptor->update($part2);
        $out3 = $this->encryptor->finish($part3);

        $this->assertNotEmpty($out1);
        $this->assertNotEmpty($out2);
        $this->assertNotEmpty($out3);
    }

    public function testFinishWithEmptyChunkAddsPadding(): void
    {
        $result = $this->encryptor->finish();
        $encrypted = substr($result, 0, -self::MAC_SIZE);

        $this->assertEquals(0, mb_strlen($encrypted, '8bit'));
    }

    public function testFinalizeOnlyOnce(): void
    {
        $mediaKey = random_bytes(32);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);

        $this->assertFalse($this->isFinalized($encryptor));

        $encrypted = $encryptor->update('test');
        $mac = $encryptor->finish();
        $this->assertTrue($this->isFinalized($encryptor));

        $this->assertSame('', $encryptor->finish());
    }

    public function testFinalizedEncryptor(): void
    {
        $encryptor = new WhatsAppMediaEncryptor(random_bytes(32), MediaType::IMAGE);
        $encryptor->finish();

        $this->expectException(EncryptionException::class);
        $encryptor->update('test');
    }

    protected function isFinalized(object $object): bool
    {
        $reflection = new \ReflectionClass($object);
        $property = $reflection->getProperty('finalized');
        $property->setAccessible(true);

        return $property->getValue($object);
    }
}
