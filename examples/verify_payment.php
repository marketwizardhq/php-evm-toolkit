<?php
/**
 * Verify that a transaction hash really paid what it claims.
 *
 * The point of this example: a transaction hash on its own proves nothing.
 * eth_sendTransaction returns a valid hash the moment a transaction is
 * BROADCAST — if it later reverts on-chain (insufficient token balance is the
 * common case), that hash still exists and still looks legitimate. Any server
 * that credits a user on hash format alone can be drained.
 *
 * Usage: php examples/verify_payment.php <chain> <txhash> <expected_to> <amount>
 */

require_once __DIR__ . '/../src/EvmHelpers.php';

$chain      = $argv[1] ?? 'BSC';
$txhash     = $argv[2] ?? '';
$expectedTo = $argv[3] ?? '';
$amount     = (float)($argv[4] ?? 0);

// USDT contracts. Pass '' as the contract to verify a native-coin payment.
$USDT = [
    'BSC'     => ['0x55d398326f99059ff775485246999027b3197955', 18],
    'ETH'     => ['0xdac17f958d2ee523a2206206994597c13d831ec7', 6],
    'POLYGON' => ['0xc2132d05d31c914a87c6611c10748aeb04b58e8f', 6],
];

if ($txhash === '' || $expectedTo === '' || $amount <= 0) {
    fwrite(STDERR, "Usage: php examples/verify_payment.php <chain> <txhash> <expected_to> <amount>\n");
    exit(1);
}

[$contract, $decimals] = $USDT[strtoupper($chain)] ?? ['', 18];

$result = evmVerifyPayment($chain, $txhash, $expectedTo, $amount, $contract, $decimals);

if (!empty($result['ok'])) {
    echo "VERIFIED — {$amount} confirmed on-chain to {$expectedTo}\n";
    echo "It is safe to credit this payment.\n";
    exit(0);
}

echo "REJECTED — {$result['error']}\n";
echo "Do NOT credit this payment.\n";
exit(2);
