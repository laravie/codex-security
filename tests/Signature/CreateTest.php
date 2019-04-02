<?php

namespace Laravie\Codex\Security\Tests\Signature;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use Laravie\Codex\Security\Signature\Create;

class CreateTest extends TestCase
{
    /** @test */
    public function it_can_generate_correct_signature()
    {
        $stub = new Create('secret');

        $this->assertSame(
            '734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a', $stub('hello world')
        );
    }
}
