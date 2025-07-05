<?php

namespace Encryption\Interface;

interface MediaStreamInfoGeneratorInterface
{
    public function update(string $chunk): string;
    public function finish(string $chunk = ''): string;
    public function getSidecar(): string;
}
