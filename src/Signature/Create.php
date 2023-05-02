<?php

namespace Laravie\Codex\Security\Signature;

class Create
{
    /**
     * Signature secret.
     *
     * @var string
     */
    protected $secret;

    /**
     * Hasher used.
     *
     * @var string
     */
    protected $hasher;

    /**
     * Construct a new signature creator.
     */
    public function __construct(string $secret, string $hasher = 'sha256')
    {
        $this->secret = $secret;
        $this->hasher = $hasher;
    }

    /**
     * Create signature.
     */
    public function __invoke(string $payload): string
    {
        return hash_hmac($this->hasher, $payload, $this->secret);
    }
}
