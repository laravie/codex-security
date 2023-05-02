<?php

namespace Laravie\Codex\Security\TimeLimitSignature;

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
    public function __invoke(string $payload, int $timestamp): string
    {
        $timestamp = (string) $timestamp;
        $signature = hash_hmac(
            $this->hasher, "{$timestamp}.{$payload}", $this->secret
        );

        return "t={$timestamp},v1={$signature}";
    }
}
