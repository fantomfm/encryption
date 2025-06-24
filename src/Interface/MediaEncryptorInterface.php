<?php

namespace Encryption\Interface;

interface MediaEncryptorInterface
{
    public function start(): string;
    public function update(string $chunk): string;
    public function finish(string $chunk = ''): string;
}
