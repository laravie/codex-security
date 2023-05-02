<?php

namespace Laravie\Codex\Security\Signature;

class Verify
{
    /**
     * Construct a new signature verifier.
     */
    public function __construct(
        protected string $secret,
        protected string $hasher = 'sha256'
    ) { }

    /**
     * Verify signature.
     */
    public function __invoke(string $payload, string $signed): bool
    {
        $expected = hash_hmac($this->hasher, $payload, $this->secret);

        return hash_equals($expected, $signed);
    }
}
