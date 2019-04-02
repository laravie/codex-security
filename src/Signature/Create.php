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
     *
     * @param string  $secret
     * @param int  $timestamp
     * @param string  $hasher
     */
    public function __construct(string $secret, string $hasher = 'sha256')
    {
        $this->secret = $secret;
        $this->hasher = $hasher;
    }

    /**
     * Create signature.
     *
     * @param  string  $payload
     * @return string
     */
    public function __invoke(string $payload): string
    {
        return \hash_hmac($this->hasher, $payload, $this->secret);
    }
}
