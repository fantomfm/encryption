<?php

namespace EncryptionTest;

use PHPUnit\Framework\TestCase;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use Encryption\WhatsApp\WhatsAppMediaDecryptor;
use Encryption\Enum\MediaType;
use Encryption\Exception\DecryptionException;
use Encryption\Exception\InvalidMacException;
use ReflectionMethod;

final class WhatsAppMediaEncryptorDecryptorTest extends TestCase
{
    private const MAC_SIZE = 10;
    private const BLOCK_SIZE = 16;

    public function testEncryptionAndDecryptionRound(): void
    {
        $mediaKey = random_bytes(32);
        $mediaType = MediaType::DOCUMENT;
        $original = "Data for WhatsApp decryptor test!";

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
        $iv = $encryptor->start();

        $encrypted = $encryptor->update($original);
        $final = $encryptor->finish(); // Содержит последний блок с padding + MAC

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, $mediaType);
        $decryptor->start();

        $decrypted = $decryptor->update($encrypted);
        $decrypted .= $decryptor->finish($final);

        $this->assertEquals($original, $decrypted);
    }

    public function testEmptyData(): void
    {
        $mediaKey = random_bytes(32);
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);
        $iv = $encryptor->start();

        $final = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::DOCUMENT);
        $decryptor->start();

        $decrypted = $decryptor->finish($final);

        $this->assertEquals('', $decrypted);
    }

    public function testDataSmallerThanBlock(): void
    {
        $mediaKey = random_bytes(32);
        $original = "small";

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);
        $iv = $encryptor->start();
        $encrypted = $encryptor->update($original);
        $final = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::DOCUMENT);
        $decryptor->start();
        $decrypted = $decryptor->update($encrypted);
        $decrypted .= $decryptor->finish($final);

        $this->assertEquals($original, $decrypted);
    }

    public function testDataExactlyOneBlock(): void
    {
        $mediaKey = random_bytes(32);
        $original = str_repeat('A', self::BLOCK_SIZE);

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);
        $iv = $encryptor->start();
        $encrypted = $encryptor->update($original);
        $final = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::DOCUMENT);
        $decryptor->start();
        $decrypted = $decryptor->update($encrypted);
        $decrypted .= $decryptor->finish($final);

        $this->assertEquals($original, $decrypted);
    }

    public function testBinaryData(): void
    {
        $mediaKey = random_bytes(32);
        $original = random_bytes(100);

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);
        $iv = $encryptor->start();
        $encrypted = $encryptor->update($original);
        $final = $encryptor->finish();

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::DOCUMENT);
        $decryptor->start();
        $decrypted = $decryptor->update($encrypted);
        $decrypted .= $decryptor->finish($final);

        $this->assertEquals($original, $decrypted);
    }

    public function testHmacVerificationFailsOnModifiedData(): void
    {
        $mediaKey = random_bytes(32);
        $original = "Data for WhatsApp decryptor test!";

        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);
        $iv = $encryptor->start();

        $encrypted = $encryptor->update($original);
        $mac = $encryptor->finish();

        $fullEncrypted = $iv . $encrypted . $mac;

        $tampered = substr($fullEncrypted, 0, -10) . chr(ord(substr($fullEncrypted, -10, 1)) ^ 1) . substr($fullEncrypted, -9);

        $decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::DOCUMENT);
        $decryptor->start();

        $macOffset = mb_strlen($tampered, '8bit') - self::MAC_SIZE;

        $this->expectException(InvalidMacException::class);

        $decryptor->update(substr($tampered, mb_strlen($iv, '8bit'), $macOffset - mb_strlen($iv, '8bit')));
        $decryptor->finish(substr($tampered, $macOffset));
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
