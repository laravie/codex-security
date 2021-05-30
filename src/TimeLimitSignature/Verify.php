<?php

namespace Laravie\Codex\Security\TimeLimitSignature;

use Carbon\Carbon;

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
     * Amount of seconds before signature is considered expired.
     *
     * @var int
     */
    protected $expiredIn;

    /**
     * Construct a new signature verifier.
     *
     * @param string  $secret
     * @param string  $hasher
     * @param int  $expiredIn
     */
    public function __construct(string $secret, string $hasher = 'sha256', int $expiredIn = 300)
    {
        $this->secret = $secret;
        $this->hasher = $hasher;
        $this->expiredIn = $expiredIn;
    }

    /**
     * Verify signature.
     *
     * @param  string  $payload
     * @param  string  $signed
     * @param  int  $currentTimestamp
     *
     * @return bool
     */
    public function __invoke(string $payload, string $signed, ?int $currentTimestamp = null): bool
    {
        if (! preg_match('/^t=(\d+),v1=([A-Za-z\d]+)/', $signed, $matches)) {
            return false;
        }

        $timestamp = $matches[1];
        $signature = $matches[2];

        $expected = hash_hmac($this->hasher, "{$timestamp}.{$payload}", $this->secret);

        $expiry = Carbon::createFromTimestamp($timestamp)->addSeconds($this->expiredIn);
        $now = \is_null($currentTimestamp) ? Carbon::now() : Carbon::createFromTimestamp($currentTimestamp);

        return hash_equals($expected, $signature) && $now->lessThanOrEqualTo($expiry);
    }
}
