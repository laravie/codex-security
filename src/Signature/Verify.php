<?php

namespace Laravie\Codex\Security\Signature;

class Verify
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
     * Construct a new signature verifier.
     *
     * @param string  $secret
     * @param string  $hasher
     * @param int  $expiredIn
     */
    public function __construct(string $secret, string $hasher = 'sha256')
    {
        $this->secret = $secret;
        $this->hasher = $hasher;
    }

    /**
     * Verify signature.
     *
     * @param  string  $payload
     * @param  string  $signed
     *
     * @return bool
     */
    public function __invoke(string $payload, string $signed): bool
    {
        $expected = hash_hmac($this->hasher, $payload, $this->secret);

        return hash_equals($expected, $signed);
    }
}
