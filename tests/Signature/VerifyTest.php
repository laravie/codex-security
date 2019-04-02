<?php

namespace Laravie\Codex\Security\Tests\Signature;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use Laravie\Codex\Security\Signature\Verify;

class VerifyTest extends TestCase
{
    /** @test */
    public function it_can_validate_signature()
    {
        $stub = new Verify('secret');

        $this->assertTrue($stub('hello world', '734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a'));
    }

    /** @test */
    public function it_cant_validate_invalid_signature()
    {
        Carbon::setTestNow($now = Carbon::createFromTimestamp(1546300810));

        $stub = new Verify('secret!!!');

        $this->assertFalse(
            $stub('hello world', '734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a')
        );
    }
}
