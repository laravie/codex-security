<?php

namespace Laravie\Codex\Security\TimeLimitSignature;

use Carbon\Carbon;

class Verify
{
    /**
     * Construct a new signature verifier.
     */
    public function __construct(
        protected string $secret,
        protected string $hasher = 'sha256',
        protected int $expiredIn = 300
    ) { }

    /**
     * Verify signature.
     *
     * @param  int  $currentTimestamp
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
