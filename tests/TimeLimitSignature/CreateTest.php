<?php

namespace Laravie\Codex\Security\Tests\TimeLimitSignature;

use Carbon\Carbon;
use Laravie\Codex\Security\TimeLimitSignature\Create;
use PHPUnit\Framework\TestCase;

class CreateTest extends TestCase
{
    /** @test */
    public function it_can_generate_correct_signature()
    {
        Carbon::setTestNow($now = Carbon::createFromTimestamp(1546300800));

        $stub = new Create('secret');

        $this->assertSame(
            't=1546300800,v1=99f58c8afc5bd7c61d7d509687224c8db8f300874b6471f85bcd0d34b5bd70fa', $stub('hello world', $now->timestamp)
        );
    }
}
