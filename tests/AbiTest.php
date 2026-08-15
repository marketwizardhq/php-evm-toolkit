<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ABI encoding/decoding and amount conversion.
 *
 * Function selectors below are the canonical ERC-20 values — the first 4
 * bytes of keccak256 of the signature. They're fixed public constants, so
 * they double as a check that our calldata layout is right.
 */
final class AbiTest extends TestCase
{
    private const ALICE = '0x5B38Da6a701c568545dCfcB03FcB875f56beddC4';

    public function testErc20TransferSelectorAndLayout(): void
    {
        // transfer(address,uint256) = 0xa9059cbb
        $data = evmTokenTransferData(self::ALICE, '1000000000000000000');

        $this->assertSame('a9059cbb', substr($data, 0, 8), 'wrong function selector');
        // selector (8 hex) + 2 words of 64 hex each
        $this->assertSame(8 + 64 + 64, strlen($data));

        // Address is left-padded to 32 bytes, lowercased, no 0x
        $expectedAddr = str_pad(strtolower(substr(self::ALICE, 2)), 64, '0', STR_PAD_LEFT);
        $this->assertSame($expectedAddr, substr($data, 8, 64));

        // 1e18 = 0xDE0B6B3A7640000
        $this->assertSame(
            str_pad('de0b6b3a7640000', 64, '0', STR_PAD_LEFT),
            substr($data, 72, 64)
        );
    }

    public function testApproveSelector(): void
    {
        // approve(address,uint256) = 0x095ea7b3
        $data = evmApproveData(self::ALICE, '1');
        $this->assertSame('095ea7b3', substr($data, 0, 8));
        $this->assertSame(8 + 64 + 64, strlen($data));
    }

    public function testToWeiExactness(): void
    {
        $this->assertSame('1000000000000000000', evmToWei('1', 18));
        $this->assertSame('10500000', evmToWei('10.5', 6));
        $this->assertSame('1', evmToWei('0.000001', 6));
        // Fractions beyond the token's decimals are truncated, not rounded up
        $this->assertSame('1', evmToWei('0.0000019', 6));
    }

    /**
     * Large supplies must not go through floats. 1 billion tokens at 18
     * decimals is 1e27 — far past PHP's integer range, and a float would
     * silently lose precision on the low-order digits.
     */
    public function testToWeiHandlesHugeSupplyWithoutPrecisionLoss(): void
    {
        $this->assertSame(
            '1000000000000000000000000000',
            evmToWei('1000000000', 18)
        );
    }

    public function testToWeiRejectsInvalid(): void
    {
        $this->expectException(Exception::class);
        evmToWei('0', 18);
    }

    public function testNormalizeAddress(): void
    {
        $this->assertSame(
            strtolower(substr(self::ALICE, 2)),
            evmNormalizeAddress(self::ALICE)
        );
        // Accepts input without the 0x prefix too
        $this->assertSame(
            strtolower(substr(self::ALICE, 2)),
            evmNormalizeAddress(substr(self::ALICE, 2))
        );
    }

    public function testNormalizeAddressRejectsGarbage(): void
    {
        $this->expectException(Exception::class);
        evmNormalizeAddress('0xnothex');
    }

    public function testAbiDecodeString(): void
    {
        // ABI string: [32-byte offset][32-byte length][data padded to 32]
        $hex = '0x'
             . str_pad('20', 64, '0', STR_PAD_LEFT)          // offset 32
             . str_pad('3', 64, '0', STR_PAD_LEFT)           // length 3
             . str_pad(bin2hex('ABC'), 64, '0', STR_PAD_RIGHT);
        $this->assertSame('ABC', evmAbiDecodeString($hex));
    }

    public function testAbiDecodeStringRejectsTruncated(): void
    {
        $this->assertNull(evmAbiDecodeString('0x1234'));
        $this->assertNull(evmAbiDecodeString('0x'));
        $this->assertNull(evmAbiDecodeString(null));
    }

    public function testAbiDecodeUint(): void
    {
        $this->assertSame(18, evmAbiDecodeUint('0x' . str_pad('12', 64, '0', STR_PAD_LEFT)));
        $this->assertSame(0, evmAbiDecodeUint('0x' . str_repeat('0', 64)));
    }

    public function testHexToDec(): void
    {
        $this->assertSame('255', hexToDec('ff'));
        $this->assertSame('255', hexToDec('0xff'));
        $this->assertSame('0', hexToDec('0'));
        // Beyond 64-bit, so this proves we're not falling back to float math
        $this->assertSame('18446744073709551616', hexToDec('10000000000000000'));
    }

    public function testDivByPow10(): void
    {
        $this->assertSame('1', divByPow10('1000000000000000000', 18));
        $this->assertSame('1.5', divByPow10('1500000', 6));
        $this->assertSame('0.000001', divByPow10('1', 6));
    }
}
