<?php

namespace Encryption\Interface;

interface MediaCipherInterface
{
    public function start(): string;
    public function update(string $chunk): string;
    public function finish(string $chunk = ''): string;
}
