<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * RLP encoder — vectors from the Ethereum RLP specification.
 * https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
 *
 * evmRlpEncode() returns raw binary, so every assertion compares bin2hex().
 */
final class RlpTest extends TestCase
{
    /** A single byte below 0x80 encodes as itself — no length prefix. */
    public function testSingleLowByteIsItself(): void
    {
        $this->assertSame('61', bin2hex(evmRlpEncode('a')));
        $this->assertSame('7f', bin2hex(evmRlpEncode("\x7f")));
    }

    /** 0x80 is the boundary: it needs a prefix even though it is one byte. */
    public function testSingleHighByteGetsPrefix(): void
    {
        $this->assertSame('8180', bin2hex(evmRlpEncode("\x80")));
    }

    public function testShortString(): void
    {
        // "dog" -> 0x83 ('d','o','g')
        $this->assertSame('83646f67', bin2hex(evmRlpEncode('dog')));
    }

    public function testEmptyString(): void
    {
        $this->assertSame('80', bin2hex(evmRlpEncode('')));
    }

    public function testEmptyList(): void
    {
        $this->assertSame('c0', bin2hex(evmRlpEncode([])));
    }

    public function testListOfStrings(): void
    {
        // ["cat","dog"] -> payload is 8 bytes, so 0xc0+8 = 0xc8
        $this->assertSame('c88363617483646f67', bin2hex(evmRlpEncode(['cat', 'dog'])));
    }

    /**
     * 55 bytes is the last length that fits the short form (0x80+len).
     * 56 flips to the long form: 0xb7+lenOfLen, then the length itself.
     */
    public function testShortFormBoundaryAt55Bytes(): void
    {
        $s = str_repeat('a', 55);
        $out = bin2hex(evmRlpEncode($s));
        $this->assertSame('b7', substr($out, 0, 2), '55 bytes should use short form 0x80+55 = 0xb7');
        $this->assertSame(2 + 55 * 2, strlen($out));
    }

    public function testLongFormAt56Bytes(): void
    {
        $s = str_repeat('a', 56);
        $out = bin2hex(evmRlpEncode($s));
        // 0xb8 = 0xb7 + 1 length byte, then 0x38 = 56
        $this->assertSame('b838', substr($out, 0, 4));
        $this->assertSame(4 + 56 * 2, strlen($out));
    }

    /**
     * Zero must encode as the empty string (0x80), NOT as a zero byte (0x00).
     * Nodes reject the non-canonical form with an opaque
     * "unmarshal transaction failed" — this cost real debugging time, so it
     * gets its own regression test.
     */
    public function testIntegerZeroEncodesAsEmptyString(): void
    {
        $this->assertSame('80', bin2hex(evmRlpEncode(0)));
    }

    public function testSmallIntegers(): void
    {
        $this->assertSame('0f', bin2hex(evmRlpEncode(15)));
        $this->assertSame('820400', bin2hex(evmRlpEncode(1024)));
    }

    public function testNestedList(): void
    {
        // [ [], [[]], [ [], [[]] ] ] — the spec's "set theoretic" example
        $this->assertSame('c7c0c1c0c3c0c1c0', bin2hex(evmRlpEncode([[], [[]], [[], [[]]]])));
    }

    public function testNegativeIntegerRejected(): void
    {
        $this->expectException(Exception::class);
        evmRlpEncode(-1);
    }
}
