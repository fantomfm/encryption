<?php

namespace EncryptionTest\Units;

use Encryption\Enum\MediaType;
use Encryption\Interface\EncryptorInterface;
use Encryption\WhatsAppEncryptor;
use PHPUnit\Framework\TestCase;

class WhatsAppEncryptorTest extends TestCase
{
    private const MEDIA_TYPE = MediaType::IMAGE;

    private EncryptorInterface $encryptor;

    protected function setUp(): void
    {
        $this->encryptor = new WhatsAppEncryptor();
    }

    public function testEncryptSuccess()
    {
        $mediaKey = random_bytes(32);
        $data = "test data";

        $encrypted = $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);

        $this->assertIsString($encrypted);
        $this->assertNotEmpty($encrypted);
        $this->assertEquals(42, strlen($encrypted));
    }

    public function testEncryptWithEmptyData()
    {
        $mediaKey = random_bytes(32);
        $data = "";

        $encrypted = $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);

        $this->assertIsString($encrypted);
        $this->assertNotEmpty($encrypted);
    }

    public function testEncryptThrowsExceptionOnInvalidMediaKeyLengthTooShort()
    {
        $mediaKey = random_bytes(31);
        $data = "test data";

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mediaKey must be 32 bytes long');

        $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);
    }

    public function testEncryptThrowsExceptionOnInvalidMediaKeyLengthTooLong()
    {
        $mediaKey = random_bytes(33); // 33 байта — слишком много
        $data = "test data";

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mediaKey must be 32 bytes long');

        $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);
    }

    public function testEncryptWithExactBlockSize()
    {
        $mediaKey = random_bytes(32);
        $data = "1234567890ABCDEF"; // 16 bytes

        $encrypted = $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);

        $this->assertIsString($encrypted);
        $this->assertNotEmpty($encrypted);
    }

    public function testEncryptWithNonMultipleBlockSize()
    {
        $mediaKey = random_bytes(32);
        $data = "non multiple text"; // non multiple 16 bytes

        $encrypted = $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);

        $this->assertIsString($encrypted);
        $this->assertNotEmpty($encrypted);
    }

    public function testEncryptWithLargeData()
    {
        $mediaKey = random_bytes(32);
        $data = str_repeat("A", 1024 * 1024); // 1 МБ

        $encrypted = $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);

        $expectedMinLength = strlen($data) + 10; // mac 10 bytes

        $this->assertIsString($encrypted);
        $this->assertNotEmpty($encrypted);
        $this->assertGreaterThanOrEqual($expectedMinLength, strlen($encrypted)); // encrypted more because padding + mac
    }

    public function testRoundTripEncryptionDecryption()
    {
        $data = "1234567890ABCDEF";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);
        $decrypted = $this->encryptor->decrypt($encrypted, $mediaKey, self::MEDIA_TYPE);

        $this->assertEquals($data, $decrypted);
    }
}
