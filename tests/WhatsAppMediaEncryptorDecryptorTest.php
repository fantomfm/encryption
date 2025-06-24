<?php

namespace EncryptionTest;

use PHPUnit\Framework\TestCase;
use Encryption\WhatsApp\WhatsAppMediaEncryptor;
use Encryption\WhatsApp\WhatsAppMediaDecryptor;
use Encryption\Enum\MediaType;
use Encryption\Exception\DecryptionException;
use Encryption\Exception\InvalidMacException;

final class WhatsAppMediaEncryptorDecryptorTest extends TestCase
{
    private const TEST_DATA = "Data for WhatsApp decryptor test!";
    private const CHUNK_SIZE = 8;
    private const MAC_SIZE = 10;

    public function testEncryptionAndDecryptionRound(): void
    {
        $mediaKey = random_bytes(32);
        $mediaType = MediaType::DOCUMENT;

        $original = "Data for WhatsApp decryptor test!";

        // Шифруем
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, $mediaType);
        $iv = $encryptor->start();

        $encrypted = $encryptor->update($original);
        $mac = $encryptor->finish();

        $fullEncrypted = $iv . $encrypted . $mac;

        // Расшифровываем
        $decryptor = new WhatsAppMediaDecryptor($mediaKey, $mediaType);
        $decryptor->start(); // проверяет iv

        $macOffset = mb_strlen($fullEncrypted, '8bit') - self::MAC_SIZE;
        $dataWithoutMac = substr($fullEncrypted, mb_strlen($iv, '8bit'), $macOffset - mb_strlen($iv, '8bit'));
        $receivedMac = substr($fullEncrypted, $macOffset);

        $decrypted = '';
        $decrypted .= $decryptor->update($dataWithoutMac);
        $decrypted .= $decryptor->finish($receivedMac);

        file_put_contents(__DIR__ . '/debug_decrypted.bin', $decrypted);
        file_put_contents(__DIR__ . '/debug_original.bin', $original);

        $this->assertEquals($original, $decrypted);
    }

    public function testHmacVerificationFailsOnModifiedData(): void
    {
        $mediaKey = random_bytes(32);

        // Шифруем
        $encryptor = new WhatsAppMediaEncryptor($mediaKey, MediaType::DOCUMENT);
        $iv = $encryptor->start();

        $encrypted = $encryptor->update(self::TEST_DATA);
        $mac = $encryptor->finish();

        $fullEncrypted = $iv . $encrypted . $mac;

        // Изменяем один байт в зашифрованных данных
        $tampered = substr($fullEncrypted, 0, -10) . chr(ord(substr($fullEncrypted, -10, 1)) ^ 1) . substr($fullEncrypted, -9);

        // Расшифровываем
        $decryptor = new WhatsAppMediaDecryptor($mediaKey, MediaType::DOCUMENT);
        $decryptor->start();

        $macOffset = mb_strlen($tampered, '8bit') - self::MAC_SIZE;

        $this->expectException(InvalidMacException::class);

        $decryptor->update(substr($tampered, mb_strlen($iv, '8bit'), $macOffset - mb_strlen($iv, '8bit')));
        $decryptor->finish(substr($tampered, $macOffset));
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

    protected function isFinalized(object $object): bool
    {
        $reflection = new \ReflectionClass($object);
        $property = $reflection->getProperty('finalized');
        $property->setAccessible(true);
        return $property->getValue($object);
    }
}