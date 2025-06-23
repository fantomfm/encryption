<?php

namespace EncryptionTest;

use Encryption\Enum\MediaType;
use Encryption\Exception\DecryptionException;
use Encryption\Exception\InvalidMacException;
use Encryption\Interface\EncryptorInterface;
use Encryption\WhatsAppEncryptor;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class WhatsAppEncryptorTest extends TestCase
{
    private const MEDIA_TYPE = MediaType::IMAGE;
    private const MAC_LENGTH = 10;

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

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('mediaKey must be 32 bytes long');

        $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);
    }

    public function testEncryptThrowsExceptionOnInvalidMediaKeyLengthTooLong()
    {
        $mediaKey = random_bytes(33); // 33 байта — слишком много
        $data = "test data";

        $this->expectException(InvalidArgumentException::class);
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
        $data = "1234567890ABCDEF"; // 16 bytes
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($data, $mediaKey, self::MEDIA_TYPE);
        $decrypted = $this->encryptor->decrypt($encrypted, $mediaKey, self::MEDIA_TYPE);

        $this->assertEquals($data, $decrypted);
    }

    public function testDecryptThrowsExceptionOnTooShortData()
    {
        $data = random_bytes(9); // less 10 bytes
        $mediaKey = random_bytes(32);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The data is too short to extract MAC');

        $this->encryptor->decrypt($data, $mediaKey, self::MEDIA_TYPE);
    }

    public function testDecryptThrowsInvalidMacExceptionOnInvalidSignature()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);

        $corrupted = substr($encrypted, 0, -1) . chr(ord(substr($encrypted, -1)) ^ 1);

        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC validation failed');

        $this->encryptor->decrypt($corrupted, $mediaKey, self::MEDIA_TYPE);
    }

    public function testDecryptWithEmptyData()
    {
        $original = "";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);
        $decrypted = $this->encryptor->decrypt($encrypted, $mediaKey, self::MEDIA_TYPE);

        $this->assertEquals($original, $decrypted);
    }

    public function testDecryptHandlesNonMultipleBlockSize()
    {
        $original = "Short text"; // 10 bytes
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);
        $decrypted = $this->encryptor->decrypt($encrypted, $mediaKey, self::MEDIA_TYPE);

        $this->assertEquals($original, $decrypted);
    }

    public function testDecryptFailsIfEncryptedLengthNotMultipleOfBlock()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);

        $validEncrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);
        $invalidEncrypted = substr($validEncrypted, 0, -1); // decrease 1 byte

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Encrypted data length must be a multiple of block size');

        $this->encryptor->decrypt($invalidEncrypted, $mediaKey, self::MEDIA_TYPE);
    }

    public function testDecryptFailsWithWrongMediaKey()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);
        $wrongMediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);

        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC validation failed');

        $this->encryptor->decrypt($encrypted, $wrongMediaKey, self::MEDIA_TYPE);
    }

    public function testDecryptFailsWithWrongMediaType()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);
        
        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC validation failed');

        $this->encryptor->decrypt($encrypted, $mediaKey, MediaType::VIDEO);
    }

    public function testDecryptFailsIfMacIsModified()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);

        $file = substr($encrypted, 0, -self::MAC_LENGTH);
        $badMac = random_bytes(self::MAC_LENGTH);
        $corrupted = $file . $badMac;

        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC validation failed');

        $this->encryptor->decrypt($corrupted, $mediaKey, self::MEDIA_TYPE);
    }

    public function testDecryptFailsIfIVIsModified()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);

        $corrupted = random_bytes(16) . substr($encrypted, 16);

        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC validation failed');

        $this->encryptor->decrypt($corrupted, $mediaKey, self::MEDIA_TYPE);
    }

    public function testDecryptFailsIfEncryptedDataIsModified()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);

        $position = 16 + 5; // after IV and before MAC
        $corrupted = substr_replace($encrypted, 'X', $position, 1);

        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC validation failed');

        $this->encryptor->decrypt($corrupted, $mediaKey, self::MEDIA_TYPE);
    }

    public function testDecryptThrowsDecryptionExceptionIfEncryptedDataIsCorruptedButMacIsValid()
    {
        $original = "test data";
        $mediaKey = random_bytes(32);

        $encrypted = $this->encryptor->encrypt($original, $mediaKey, self::MEDIA_TYPE);

        $macLength = self::MAC_LENGTH;
        $mac = substr($encrypted, -$macLength);
        $file = substr($encrypted, 0, -$macLength);

        $position = 20; // inside enc
        $corruptedFile = substr_replace($file, 'X', $position, 1);

        $corrupted = $corruptedFile . $mac;

        $this->expectException(DecryptionException::class);

        $this->encryptor->decrypt($corrupted, $mediaKey, self::MEDIA_TYPE);
    }
}
