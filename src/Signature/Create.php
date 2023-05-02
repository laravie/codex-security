<?php

namespace Laravie\Codex\Security\Signature;

class Create
{
    /**
     * Construct a new signature creator.
     */
    public function __construct(
        protected string $secret,
        protected string $hasher = 'sha256'
    ) { }

    /**
     * Create signature.
     */
    public function __invoke(string $payload): string
    {
        return hash_hmac($this->hasher, $payload, $this->secret);
    }
}
