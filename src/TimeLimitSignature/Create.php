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
     * @param  int  $timestamp
     *
     * @return string
     */
    public function __invoke(string $payload, int $timestamp): string
    {
        $timestamp = (string) $timestamp;
        $signature = \hash_hmac(
            $this->hasher, "{$timestamp}.{$payload}", $this->secret
        );

        return "t={$timestamp},v1={$signature}";
    }
}
