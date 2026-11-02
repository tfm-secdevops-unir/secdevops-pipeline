<?php

use PHPUnit\Framework\TestCase;

final class SumaTest extends TestCase
{
    public function testSuma(): void
    {
        $this->assertSame(2, 1 + 1);
    }
}
