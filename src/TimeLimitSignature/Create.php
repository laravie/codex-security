<?php

namespace Laravie\Codex\Security\TimeLimitSignature;

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
    public function __invoke(string $payload, int $timestamp): string
    {
        $timestamp = (string) $timestamp;
        $signature = hash_hmac(
            $this->hasher, "{$timestamp}.{$payload}", $this->secret
        );

        return "t={$timestamp},v1={$signature}";
    }
}
