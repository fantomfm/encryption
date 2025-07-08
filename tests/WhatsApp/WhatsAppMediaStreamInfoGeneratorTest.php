<?php

declare(strict_types=1);

namespace EncryptionTest\WhatsApp;

use Encryption\Exception\StreamInfoException;
use Encryption\Interface\MediaStreamInfoGeneratorInterface;
use Encryption\WhatsApp\WhatsAppMediaStreamInfoGenerator;
use PHPUnit\Framework\TestCase;

class WhatsAppMediaStreamInfoGeneratorTest extends TestCase
{
    private const MAC_KEY = 's3s6qootolalrf556q0xj4d9y1lwv57o';
    private const IV = 'zm5my6c4pwd4xkm1';

    private MediaStreamInfoGeneratorInterface $generator;

    public function setUp(): void
    {
        $this->generator = new WhatsAppMediaStreamInfoGenerator(self::MAC_KEY, self::IV);
    }

    public function testConstructorValidatesKeyAndIvLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new WhatsAppMediaStreamInfoGenerator('short_key', self::IV);

        $this->expectException(\InvalidArgumentException::class);
        new WhatsAppMediaStreamInfoGenerator(self::MAC_KEY, 'short_iv');
    }

    public function testFirstChunkSignature(): void
    {
        $smallChunk = hex2bin('1234567890abcdef');
        $this->generator->update($smallChunk);

        $sidecar = $this->generator->finish();
        $this->assertNotEmpty($sidecar);
        $this->assertSame(10, strlen($sidecar));
    }

    public function testChunkProcessingWithExactSize(): void
    {
        $chunk = random_bytes(65536);
        $this->generator->update($chunk);

        $this->assertSame(10, strlen($this->generator->getSidecar()));
    }

    public function testMultipleChunksProcessing(): void
    {
        $this->generator->update(random_bytes(65536));
        $signatureAfterFirst = $this->generator->getSidecar();

        $this->generator->update(random_bytes(65536));
        $signatureAfterSecond = $this->generator->getSidecar();

        $this->assertSame(20, strlen($signatureAfterSecond));
        $this->assertSame(
            $signatureAfterFirst,
            substr($signatureAfterSecond, 0, 10),
            'First part of signature should remain unchanged'
        );
        $this->assertNotEquals(
            $signatureAfterFirst,
            substr($signatureAfterSecond, 10, 10),
            'New part of signature should differ'
        );
    }

    public function testFinishCanBeCalledMultipleTimes(): void
    {
        $this->generator->update(random_bytes(100));

        $signature1 = $this->generator->finish();
        $signature2 = $this->generator->finish();

        $this->assertSame($signature1, $signature2);
    }

    public function testUpdateAfterFinishThrowsException(): void
    {
        $this->generator->finish();

        $this->expectException(StreamInfoException::class);
        $this->generator->update(random_bytes(100));
    }

    public function testEmptyDataProducesEmptySignature(): void
    {
        $signature = $this->generator->finish();

        $this->assertEmpty($signature);
    }

    public function testVerySmallChunks(): void
    {
        $this->generator->update(random_bytes(16));
        $this->generator->update(random_bytes(16));
        $signature = $this->generator->finish();

        $this->assertSame(10, strlen($signature));
    }

    public function testExactMultiplesOfChunkSize(): void
    {
        $this->generator->update(random_bytes(65536 * 2));
        $signature = $this->generator->finish();

        $this->assertSame(20, strlen($signature));
    }

    public function testPrecomputedSignatureMatches(): void
    {
        $testData = '4c2c00b52885318e7249daf777bfbb7fa50b8139ff26bb6eb9c1fcfffdc8c955';

        $this->generator->update($testData);

        $signature = $this->generator->finish();

        $this->assertSame(
            '02f6c67baf22187fbe6a',
            bin2hex(substr($signature, 0, 10)),
            'Generated signature does not match the expected value. Check macKey, IV, and test data.'
        );
    }
}
