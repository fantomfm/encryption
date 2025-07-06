<?php

namespace EncryptionTest\WhatsApp;

use Encryption\Enum\MediaType;
use Encryption\Exception\DecryptionException;
use Encryption\Exception\InvalidMacException;
use Encryption\WhatsApp\WhatsAppMediaDecryptor;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class WhatsAppMediaEncryptorDecryptorTest extends TestCase
{
    private const MAC_SIZE = 10;
    private const BLOCK_SIZE = 16;

    private const MEDIA_KEY = '0123456789abcdef0123456789abcdef'; // 32 bytes
    private const TEST_DATA = 'This is a test message for WhatsApp media encryption/decryption';
    private const MEDIA_TYPE = MediaType::IMAGE;

    public function testEncryptionAndDecryption(): void
    {
        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $iv = $encryptor->start();

        $firstChunk = substr(self::TEST_DATA, 0, 10);
        $secondChunk = substr(self::TEST_DATA, 10);

        $encryptedPart1 = $encryptor->update($firstChunk);
        $encryptedPart2 = $encryptor->update($secondChunk);
        $finalEncrypted = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();

        $mac = substr($finalEncrypted, -self::MAC_SIZE);
        $encryptedContent = substr($finalEncrypted, 0, -self::MAC_SIZE);

        $decryptedPart1 = $decryptor->update($encryptedPart1);
        $decryptedPart2 = $decryptor->update($encryptedPart2);
        $decryptedFinal = $decryptor->finish($encryptedContent . $mac);

        $fullDecrypted = $decryptedPart1 . $decryptedPart2 . $decryptedFinal;

        $this->assertEquals(self::TEST_DATA, $fullDecrypted);
    }

    public function testEmptyData(): void
    {
        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $encryptor->start();

        $finalEncrypted = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();

        $mac = substr($finalEncrypted, -self::MAC_SIZE);
        $encryptedContent = substr($finalEncrypted, 0, -self::MAC_SIZE);

        $decryptedFinal = $decryptor->finish($encryptedContent . $mac);

        $this->assertEquals('', $decryptedFinal);
    }

    public function testDataSmallerThanBlock(): void
    {
        $testData = 'small';

        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $iv = $encryptor->start();

        $encrypted = $encryptor->update($testData);
        $finalEncrypted = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();

        $mac = substr($finalEncrypted, -self::MAC_SIZE);
        $encryptedContent = substr($finalEncrypted, 0, -self::MAC_SIZE);

        $decrypted = $decryptor->update($encrypted);
        $decryptedFinal = $decryptor->finish($encryptedContent . $mac);

        $fullDecrypted = $decrypted . $decryptedFinal;

        $this->assertEquals($testData, $fullDecrypted);
    }

    public function testDataExactlyOneBlock(): void
    {
        $testData = str_repeat('A', self::BLOCK_SIZE);

        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $iv = $encryptor->start();

        $encrypted = $encryptor->update($testData);
        $finalEncrypted = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();

        $mac = substr($finalEncrypted, -self::MAC_SIZE);
        $encryptedContent = substr($finalEncrypted, 0, -self::MAC_SIZE);

        $decrypted = $decryptor->update($encrypted);
        $decryptedFinal = $decryptor->finish($encryptedContent . $mac);

        $fullDecrypted = $decrypted . $decryptedFinal;

        $this->assertEquals($testData, $fullDecrypted);
    }

    public function testBinaryData(): void
    {
        $testData = random_bytes(100);

        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $iv = $encryptor->start();

        $encryptedPart1 = $encryptor->update($testData);
        $finalEncrypted = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();

        $mac = substr($finalEncrypted, -self::MAC_SIZE);
        $encryptedContent = substr($finalEncrypted, 0, -self::MAC_SIZE);

        $decryptedPart1 = $decryptor->update($encryptedPart1);
        $decryptedFinal = $decryptor->finish($encryptedContent . $mac);

        $fullDecrypted = $decryptedPart1 . $decryptedFinal;

        $this->assertEquals($testData, $fullDecrypted);
    }

    public function testStreamingEncryptionDecryption(): void
    {
        $data = str_repeat('a', self::BLOCK_SIZE * 3 + 5);
        $chunkSizes = [16, 16, 16, 5];

        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $encrypted = '';
        foreach ($chunkSizes as $size) {
            $chunk = substr($data, strlen($encrypted), $size);
            $encrypted .= $encryptor->update($chunk);
        }
        $finalEncrypted = $encryptor->finish();
        $fullEncryptedData = $encrypted . $finalEncrypted;

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);

        $decrypted = '';
        $offset = 0;
        $totalLength = mb_strlen($fullEncryptedData, '8bit');

        $safeEndIndex = $totalLength - (self::BLOCK_SIZE + self::MAC_SIZE);

        foreach ($chunkSizes as $size) {
            if ($offset + $size > $safeEndIndex) {
                break;
            }

            $chunk = substr($fullEncryptedData, $offset, $size);
            $decrypted .= $decryptor->update($chunk);
            $offset += $size;
        }

        $remaining = substr($fullEncryptedData, $offset);
        $decrypted .= $decryptor->finish($remaining);

        $this->assertEquals($data, $decrypted);
    }

    public function testHmacVerificationFailsOnModifiedData(): void
    {
        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $encryptor->start();
        $encrypted = $encryptor->update(self::TEST_DATA);
        $final = $encryptor->finish();

        $modified = substr($encrypted, 0, 10)
                . chr(ord($encrypted[10]) ^ 0xFF)
                . substr($encrypted, 11);

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();

        $decryptor->update($modified);

        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC verification failed');

        $decryptor->finish($final);
    }

    public function testHmacVerificationFailsOnModifiedMac(): void
    {
        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $encryptor->start();
        $encrypted = $encryptor->update(self::TEST_DATA);
        $mac = $encryptor->finish();

        $modifiedMac = substr($mac, 0, 2) . chr(ord($mac[2]) ^ 0xFF) . substr($mac, 3);

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();
        $decryptor->update($encrypted);

        $this->expectException(InvalidMacException::class);
        $this->expectExceptionMessage('MAC verification failed');

        $decryptor->finish($modifiedMac);
    }

    public function testInvalidMacSize(): void
    {
        $encryptor = new WhatsAppMediaEncryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $encryptor->start();
        $encrypted = $encryptor->update(self::TEST_DATA);
        $mac = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor(self::MEDIA_KEY, self::MEDIA_TYPE);
        $decryptor->start();
        $decryptor->update($encrypted);

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Final chunk is too small to contain encrypted data and MAC');

        $decryptor->finish(substr($mac, 0, 5));
    }

    public function testRemovePaddingReturnsEmptyStringWhenGivenFullPaddingBlock(): void
    {
        $mediaKey = random_bytes(32);
        $mediaType = MediaType::DOCUMENT;

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, $mediaType);

        $blockWithPadding = str_repeat("\x10", 16);

        $method = new ReflectionMethod(WhatsAppMediaDecryptor::class, 'removePadding');
        $method->setAccessible(true);

        $decryptedBlock = $method->invoke($decryptor, $blockWithPadding);

        $this->assertEquals('', $decryptedBlock);
    }

    public function testDecryptionAfterFinalize(): void
    {
        $mediaKey = random_bytes(32);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);
        $iv = $encryptor->start();

        $final = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::DOCUMENT);
        $decryptor->start();

        $decrypted = $decryptor->finish($final);

        $this->expectException(DecryptionException::class);

        $decryptor->update('any data');
    }
}
