<?php

namespace Encryption\Interface;

interface MediaCipherInterface
{
    public function start(): string;
    public function update(string $chunk): string;
    public function finish(string $chunk = ''): string;

    public function getBlockSize(): int;
    public function getMacSize(): int;
}
