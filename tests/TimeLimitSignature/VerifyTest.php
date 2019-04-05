<?php

namespace Laravie\Codex\Security\Tests\TimeLimitSignature;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use Laravie\Codex\Security\TimeLimitSignature\Verify;

class VerifyTest extends TestCase
{
    /** @test */
    public function it_can_validate_signature()
    {
        Carbon::setTestNow($now = Carbon::createFromTimestamp(1546300800));

        $stub = new Verify('secret');

        $this->assertTrue($stub('hello world', 't=1546300800,v1=99f58c8afc5bd7c61d7d509687224c8db8f300874b6471f85bcd0d34b5bd70fa'));
    }

    /** @test */
    public function it_can_validate_signature_with_custom_timestamp()
    {
        Carbon::setTestNow($now = Carbon::createFromTimestamp(1546300810));

        $stub = new Verify('secret');

        $this->assertTrue(
            $stub('hello world', 't=1546300800,v1=99f58c8afc5bd7c61d7d509687224c8db8f300874b6471f85bcd0d34b5bd70fa', $now->timestamp)
        );
    }

    /** @test */
    public function it_cant_validate_invalid_signature()
    {
        Carbon::setTestNow($now = Carbon::createFromTimestamp(1546300810));

        $stub = new Verify('secret!!!');

        $this->assertFalse(
            $stub('hello world', 't=1546300800,v1=99f58c8afc5bd7c61d7d509687224c8db8f300874b6471f85bcd0d34b5bd70fa')
        );
    }

    /** @test */
    public function it_cant_validate_signature_after_timestamp_expired()
    {
        Carbon::setTestNow($now = Carbon::createFromTimestamp(1546301300));

        $stub = new Verify('secret');

        $this->assertFalse(
            $stub('hello world', 't=1546300800,v1=99f58c8afc5bd7c61d7d509687224c8db8f300874b6471f85bcd0d34b5bd70fa')
        );
    }

    /** @test */
    public function it_cant_validate_signature_with_invalid_signed_value()
    {
        Carbon::setTestNow($now = Carbon::createFromTimestamp(1546301300));

        $stub = new Verify('secret');

        $this->assertFalse(
            $stub('hello world', '99f58c8afc5bd7c61d7d509687224c8db8f300874b6471f85bcd0d34b5bd70fa')
        );
    }
}
