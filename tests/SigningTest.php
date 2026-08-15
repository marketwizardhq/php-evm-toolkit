<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * EIP-155 transaction signing, checked against the worked example in the EIP
 * itself: https://eips.ethereum.org/EIPS/eip-155
 *
 * This is the highest-value test in the suite. It exercises the whole chain
 * at once — RLP encoding, Keccak hashing, secp256k1 recoverable signing, and
 * the v = chainId*2 + 35 + recoveryId calculation. If the produced bytes
 * match the EIP byte-for-byte, the signing path is correct.
 *
 * Requires the crypto dependencies (composer install); skipped without them.
 */
final class SigningTest extends TestCase
{
    // EIP-155 example transaction
    private const PRIV     = '4646464646464646464646464646464646464646464646464646464646464646';
    private const ADDRESS  = '0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f';
    private const TO       = '0x3535353535353535353535353535353535353535';
    private const NONCE    = 9;
    private const GAS_PRICE = '20000000000';   // 20 gwei
    private const GAS_LIMIT = 21000;
    private const VALUE    = '1000000000000000000'; // 1 ETH
    private const CHAIN_ID = 1;

    private const EXPECTED_SIGNED_TX =
        '0xf86c098504a817c800825208943535353535353535353535353535353535353535' .
        '880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71' .
        'ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc6421' .
        '4b297fb1966a3b6d83';

    protected function setUp(): void
    {
        if (!class_exists(\FurqanSiddiqui\ECDSA\Curves\Secp256k1::class)) {
            $this->markTestSkipped('Crypto dependencies not installed — run `composer install`.');
        }
    }

    public function testPrivateKeyDerivesExpectedAddress(): void
    {
        $this->assertSame(self::ADDRESS, strtolower(evmPrvToAddress(self::PRIV)));
    }

    /** The full EIP-155 example, byte for byte. */
    public function testSignsEip155ExampleExactly(): void
    {
        [$rawHex, $txHash] = evmSignTx(
            self::CHAIN_ID,
            self::PRIV,
            self::NONCE,
            self::GAS_PRICE,
            self::GAS_LIMIT,
            self::TO,
            self::VALUE
        );

        $this->assertSame(self::EXPECTED_SIGNED_TX, strtolower($rawHex));
        $this->assertMatchesRegularExpression('/^0x[0-9a-f]{64}$/', strtolower($txHash));
    }

    /**
     * v encodes the chain id, which is the entire point of EIP-155 (replay
     * protection). Chain id 1 gives v = 37 (0x25) or 38 (0x26) depending on
     * the recovery id; BSC (56) gives 147 (0x93) or 148 (0x94).
     */
    public function testChainIdIsEncodedInV(): void
    {
        [$mainnetRaw] = evmSignTx(1, self::PRIV, self::NONCE, self::GAS_PRICE, self::GAS_LIMIT, self::TO, self::VALUE);
        [$bscRaw]     = evmSignTx(56, self::PRIV, self::NONCE, self::GAS_PRICE, self::GAS_LIMIT, self::TO, self::VALUE);

        $this->assertNotSame(
            strtolower($mainnetRaw),
            strtolower($bscRaw),
            'Same transaction on different chains must not produce identical bytes — that is the replay protection EIP-155 exists to provide.'
        );
    }

    /** Signing is deterministic: same inputs must always give the same bytes. */
    public function testSigningIsDeterministic(): void
    {
        [$a] = evmSignTx(56, self::PRIV, 3, '5000000000', 65000, self::TO, '0');
        [$b] = evmSignTx(56, self::PRIV, 3, '5000000000', 65000, self::TO, '0');
        $this->assertSame($a, $b);
    }

    /** keccak256("") — the canonical empty-input digest. */
    public function testKeccakEmptyInput(): void
    {
        $this->assertSame(
            'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
            bin2hex(\FurqanSiddiqui\Ethereum\Packages\Keccak\Keccak::hash('', 256, true))
        );
    }

    /**
     * The ERC-20 Transfer event topic, computed rather than pasted.
     * evmVerifyPayment() derives this at runtime to match Transfer logs, so
     * if it were wrong every token payment verification would silently fail
     * to find its match.
     */
    public function testTransferEventTopic(): void
    {
        $this->assertSame(
            'ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
            bin2hex(\FurqanSiddiqui\Ethereum\Packages\Keccak\Keccak::hash('Transfer(address,address,uint256)', 256, true))
        );
    }

    /** Contract addresses are deterministic from (deployer, nonce). */
    public function testContractAddressDerivationIsDeterministic(): void
    {
        $a = evmDeriveContractAddress(self::ADDRESS, 0);
        $b = evmDeriveContractAddress(self::ADDRESS, 0);
        $c = evmDeriveContractAddress(self::ADDRESS, 1);

        $this->assertMatchesRegularExpression('/^0x[0-9a-f]{40}$/', $a);
        $this->assertSame($a, $b, 'same deployer + nonce must give the same address');
        $this->assertNotSame($a, $c, 'a different nonce must give a different address');
    }
}
