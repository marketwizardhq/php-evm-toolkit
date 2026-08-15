<?php
/**
 * EvmHelpers — build, sign and broadcast raw EVM transactions from PHP.
 *
 * No web3 wrapper: the RLP encoder, EIP-155 signing payload, ABI codec and
 * contract-address derivation are all implemented here directly. External
 * dependencies are limited to the two primitives worth not writing by hand:
 *   - furqansiddiqui/ecdsa-php     — secp256k1 recoverable signatures
 *   - furqansiddiqui/ethereum-php  — Keccak-256
 *
 * Chains: Ethereum, BSC, Polygon, Arbitrum (see evmChainConfig).
 *
 * Covers:
 *   RLP + signing    evmRlpEncode, evmSignTx, evmSignContractTx
 *   Sending          evmSendNative, evmSendToken, evmSendContractTx
 *   Verification     evmVerifyPayment — confirms a tx really paid, on-chain
 *   Reads            evmGetNativeBalance, evmGetTokenBalance, evmTokenName/Symbol
 *   Deployment       evmDeployContract, evmDeriveContractAddress
 *   DEX              evmApproveToken, evmAddLiquidity (PancakeSwap / Uniswap V2)
 *
 * Transactions are legacy (type-0) only — no EIP-1559. Fine on BSC and
 * Polygon; on Ethereum mainnet this overpays relative to a type-2 tx.
 */

// Standalone checkout: load Composer's autoloader from this repo.
// Installed AS a dependency: the consumer's autoloader has already run and
// this path does not exist (it would resolve inside vendor/<vendor>/<pkg>/),
// so requiring it unconditionally would fatal. Load only if present.
$__evmAutoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($__evmAutoload)) require_once $__evmAutoload;

/**
 * TLS verification. ON by default, and it must stay that way.
 *
 * An earlier version disabled peer verification because some shared hosts
 * ship without a CA bundle. That is never an acceptable default for a library
 * that signs transactions and verifies payments: with verification off, a
 * man-in-the-middle can forge an eth_getTransactionReceipt response and
 * convince evmVerifyPayment() that a payment succeeded when no funds ever
 * moved — turning a TLS convenience setting into a financial exploit. It can
 * also feed back a wrong nonce or gas price.
 *
 * If your host has no CA bundle, point EVM_CA_BUNDLE at a cacert.pem
 * (https://curl.se/ca/cacert.pem) instead of disabling checks.
 * EVM_INSECURE_TLS is a dev-only escape hatch for self-signed local nodes.
 */
if (!defined('EVM_INSECURE_TLS')) define('EVM_INSECURE_TLS', false);

/** cURL TLS options applied to every outbound request in this library. */
function evmApplyTls($ch): void {
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, !EVM_INSECURE_TLS);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, EVM_INSECURE_TLS ? 0 : 2);
    if (defined('EVM_CA_BUNDLE') && EVM_CA_BUNDLE !== '') {
        curl_setopt($ch, CURLOPT_CAINFO, EVM_CA_BUNDLE);
    }
}

use FurqanSiddiqui\ECDSA\Curves\Secp256k1;
use FurqanSiddiqui\ECDSA\KeyPair;
use FurqanSiddiqui\Ethereum\Packages\Keccak\Keccak;
use Comely\Buffer\Bytes32;

/* ───────────────────────── RPC helpers ───────────────────────── */

function evmRpcCall(string $url, string $method, array $params = [], int $timeout = 12) {
    if (!function_exists('curl_init')) return null;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => 1, CURLOPT_POST => 1,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => $method, 'params' => $params]),
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'Mozilla/5.0',
    ]);
    evmApplyTls($ch);
    $res = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($http !== 200 || !$res) return null;
    $data = json_decode($res, true);
    // Record the RPC error message (e.g. "insufficient funds", "nonce too low")
    // so callers can surface the REAL reason instead of a generic failure.
    if (!empty($data['error']['message'])) {
        $GLOBALS['__evm_last_rpc_error'] = $data['error']['message'];
        return null;
    }
    return $data['result'] ?? null;
}

/** Last RPC error message captured by evmRpcCall ('' if none). */
function evmLastRpcError(): string {
    return $GLOBALS['__evm_last_rpc_error'] ?? '';
}

function evmChainConfig(string $chain): array {
    switch (strtoupper($chain)) {
        case 'ETH':
            return [
                'rpc' => 'https://eth.llamarpc.com',
                'rpcs' => ['https://eth.llamarpc.com', 'https://cloudflare-eth.com', 'https://ethereum-rpc.publicnode.com'],
                'chainId' => 1,
                'explorer' => 'https://etherscan.io/tx/',
            ];
        case 'BSC':
            return [
                'rpc' => 'https://bsc-dataseed1.binance.org',
                // Reliable public endpoints FIRST — Binance dataseeds are often
                // blocked/unreachable from shared hosts (causes timeouts).
                'rpcs' => ['https://bsc-rpc.publicnode.com', 'https://rpc.ankr.com/bsc', 'https://bsc-dataseed1.binance.org', 'https://bsc-dataseed2.binance.org'],
                'chainId' => 56,
                'explorer' => 'https://bscscan.com/tx/',
            ];
        case 'POLYGON':
            return [
                'rpc' => 'https://polygon-rpc.com',
                'rpcs' => ['https://polygon-rpc.com', 'https://polygon-bor-rpc.publicnode.com', 'https://rpc.ankr.com/polygon'],
                'chainId' => 137,
                'explorer' => 'https://polygonscan.com/tx/',
            ];
        case 'ARBITRUM':
            return [
                'rpc' => 'https://arb1.arbitrum.io/rpc',
                'rpcs' => ['https://arb1.arbitrum.io/rpc', 'https://arbitrum-one-rpc.publicnode.com'],
                'chainId' => 42161,
                'explorer' => 'https://arbiscan.io/tx/',
            ];
        default:
            throw new Exception("Unsupported chain: $chain");
    }
}

/** Try a list of RPC endpoints until one returns a valid result (fallback-friendly) */
function evmRpcCallAny(array $rpcs, string $method, array $params = [], int $timeout = 10) {
    $GLOBALS['__evm_last_rpc_error'] = '';
    foreach ($rpcs as $url) {
        $res = evmRpcCall($url, $method, $params, $timeout);
        if ($res !== null) return $res;
    }
    return null;
}

/* ─────────────────────── RLP encoder ─────────────────────────── */

function evmRlpEncode(mixed $item): string {
    if (is_int($item)) {
        if ($item < 0) throw new Exception("RLP: negative int not allowed");
        if ($item === 0) return "\x80";
        $hex = gmp_strval(gmp_init($item, 10), 16);
        if (strlen($hex) % 2 !== 0) $hex = "0" . $hex;
        $bin = hex2bin($hex);
        return evmRlpEncodeString($bin);
    }
    if (is_string($item)) {
        return evmRlpEncodeString($item);
    }
    if (is_array($item)) {
        $payload = "";
        foreach ($item as $sub) $payload .= evmRlpEncode($sub);
        $len = strlen($payload);
        if ($len <= 55) return chr(0xc0 + $len) . $payload;
        $lenHex = gmp_strval(gmp_init($len, 10), 16);
        if (strlen($lenHex) % 2 !== 0) $lenHex = "0" . $lenHex;
        $lenBin = hex2bin($lenHex);
        return chr(0xf7 + strlen($lenBin)) . $lenBin . $payload;
    }
    throw new Exception("RLP: unsupported type " . gettype($item));
}

function evmRlpEncodeString(string $bin): string {
    $len = strlen($bin);
    if ($len === 0) return "\x80";
    if ($len === 1 && ord($bin[0]) < 0x80) return $bin;
    if ($len <= 55) return chr(0x80 + $len) . $bin;
    $lenHex = gmp_strval(gmp_init($len, 10), 16);
    if (strlen($lenHex) % 2 !== 0) $lenHex = "0" . $lenHex;
    $lenBin = hex2bin($lenHex);
    return chr(0xb7 + strlen($lenBin)) . $lenBin . $bin;
}

/* ─────────────────────── BigNumber helpers ───────────────────── */

/**
 * Convert a decimal amount string to wei (integer string).
 * Uses gmp (arbitrary precision, ALWAYS available with this lib) so large
 * supplies (e.g. 1,000,000,000 × 10^18) never overflow. Falls back to bcmath,
 * then float as a last resort.
 */
function evmToWei(string $amount, int $decimals = 18): string {
    $amount = trim($amount);
    if ($amount === '' || (float)$amount <= 0) throw new Exception("Invalid amount");
    if (function_exists('gmp_init') && function_exists('gmp_pow') && function_exists('gmp_mul') && function_exists('gmp_add')) {
        $parts = explode('.', $amount);
        $intPart = $parts[0];
        $fracPart = $parts[1] ?? '';
        $fracPart = substr($fracPart, 0, $decimals);
        $fracPart = str_pad($fracPart, $decimals, '0');
        $wei = gmp_add(
            gmp_mul(gmp_init($intPart, 10), gmp_pow(10, $decimals)),
            gmp_init($fracPart === '' ? '0' : $fracPart, 10)
        );
        return gmp_strval($wei);
    }
    if (function_exists('bcmul')) {
        $parts = explode('.', $amount);
        $intPart = $parts[0];
        $fracPart = $parts[1] ?? '';
        $fracPart = substr($fracPart, 0, $decimals);
        $fracPart = str_pad($fracPart, $decimals, '0');
        return bcadd(bcmul($intPart, bcpow('10', (string)$decimals, 0), 0), $fracPart, 0);
    }
    // last-resort float fallback (only for very small amounts)
    $weiFloat = (float)$amount * pow(10, $decimals);
    return (string)(int)round($weiFloat);
}

/* ─────────────────────── Address / data helpers ──────────────── */

function evmNormalizeAddress(string $addr): string {
    $addr = strtolower(trim($addr));
    if (str_starts_with($addr, '0x')) $addr = substr($addr, 2);
    if (!preg_match('/^[0-9a-f]{40}$/', $addr)) {
        throw new Exception("Invalid EVM address");
    }
    return $addr;
}

/** ERC20/BEP20 transfer(address,uint256) calldata */
function evmTokenTransferData(string $toAddress, string $amountWei): string {
    $to = evmNormalizeAddress($toAddress);
    $selector = 'a9059cbb'; // keccak("transfer(address,uint256)")[0..3]
    $toPadded = str_pad($to, 64, '0', STR_PAD_LEFT);
    $amountPadded = str_pad(gmp_strval(gmp_init($amountWei, 10), 16), 64, '0', STR_PAD_LEFT);
    return $selector . $toPadded . $amountPadded;
}

/* ─────────────────────── Tx signing ──────────────────────────── */

/**
 * Sign a raw legacy transaction (EIP-155).
 * @return array [rawTxHex (0x...), txHashHex (0x...)]
 */
function evmSignTx(int $chainId, string $fromPrvHex, int $nonce, string $gasPriceWei, int $gasLimit, string $toAddress, string $valueWei, string $dataHex = ''): array {
    $ecc = new Secp256k1();
    $privKey = new Bytes32(hex2bin($fromPrvHex));
    $keyPair = new KeyPair($ecc, $privKey);

    // Build tx fields as byte strings
    $nonceBin   = evmRlpDecodeIntBytes($nonce);
    $gasPriceBin = evmRlpDecodeHex(gmp_strval(gmp_init($gasPriceWei, 10), 16));
    $gasLimitBin = evmRlpDecodeIntBytes($gasLimit);
    $toBin      = hex2bin(evmNormalizeAddress($toAddress));
    // Zero value MUST be the empty string (RLP 0x80). A single 0x00 byte is
    // non-canonical and nodes reject it with "unmarshal transaction failed".
    $valueWeiHex = gmp_strval(gmp_init($valueWei, 10), 16);
    $valueBin   = ($valueWeiHex === '' || $valueWeiHex === '0') ? '' : evmRlpDecodeHex($valueWeiHex);
    $dataBin    = $dataHex !== '' ? hex2bin(preg_replace('/^0x/i', '', $dataHex)) : '';

    // EIP-155 signing payload includes chainId, 0, 0
    $signingPayload = evmRlpEncode([$nonceBin, $gasPriceBin, $gasLimitBin, $toBin, $valueBin, $dataBin, $chainId, '', '']);
    $msgHash = Keccak::hash($signingPayload, 256, true);

    $signature = $keyPair->signRecoverable(new Bytes32($msgHash));
    $r = $signature->r->raw();
    $s = $signature->s->raw();
    $recoveryId = $signature->recoveryId; // 0 or 1
    $v = $chainId * 2 + 35 + $recoveryId;

    // Serialized tx
    $raw = evmRlpEncode([$nonceBin, $gasPriceBin, $gasLimitBin, $toBin, $valueBin, $dataBin, $v, $r, $s]);
    $rawHex = '0x' . bin2hex($raw);
    $txHash = '0x' . bin2hex(Keccak::hash($raw, 256, true));
    return [$rawHex, $txHash];
}

/** Convert int to minimal big-endian bytes (RLP int encoding) */
function evmRlpDecodeIntBytes(int $val): string {
    if ($val === 0) return '';
    return evmRlpDecodeHex(gmp_strval(gmp_init($val, 10), 16));
}

/** Convert hex string (no 0x) to bytes, left-padded to even length */
function evmRlpDecodeHex(string $hex): string {
    if ($hex === '') return '';
    if (strlen($hex) % 2 !== 0) $hex = '0' . $hex;
    return hex2bin($hex);
}

/* ─────────────────────── High-level send ─────────────────────── */

/**
 * Send native coin (ETH / BNB / MATIC / ETH-Arbitrum).
 * @return array ['ok'=>bool, 'txhash'=>string|null, 'error'=>string|null]
 */
function evmSendNative(string $chain, string $fromPrvHex, string $toAddress, string $amount, int $decimals = 18): array {
    $cfg = evmChainConfig($chain);
    $chainId = $cfg['chainId'];

    try {
        $valueWei = evmToWei($amount, $decimals);
        $fromAddr = evmPrvToAddress($fromPrvHex);

        $nonceHex = evmRpcCallAny($cfg['rpcs'], 'eth_getTransactionCount', [$fromAddr, 'pending']);
        if ($nonceHex === null) throw new Exception("Cannot fetch nonce (RPC unreachable)");
        $nonce = gmp_intval(gmp_init(preg_replace('/^0x/', '', $nonceHex), 16));

        $gasPriceHex = evmRpcCallAny($cfg['rpcs'], 'eth_gasPrice', []);
        $gasPriceWei = $gasPriceHex ? gmp_strval(gmp_init(preg_replace('/^0x/', '', $gasPriceHex), 16)) : '5000000000';

        // Estimate gas: eth_estimateGas with a temporary from
        $estGas = evmRpcCallAny($cfg['rpcs'], 'eth_estimateGas', [[
            'from' => $fromAddr, 'to' => $toAddress, 'value' => '0x' . gmp_strval(gmp_init($valueWei, 10), 16),
        ]]);
        $gasLimit = $estGas ? gmp_intval(gmp_init(preg_replace('/^0x/', '', $estGas), 16)) : 21000;
        $gasLimit = max(21000, $gasLimit + 2000); // safety buffer

        [$rawHex, $txHash] = evmSignTx($chainId, $fromPrvHex, $nonce, $gasPriceWei, $gasLimit, $toAddress, $valueWei);
        $sent = evmRpcCallAny($cfg['rpcs'], 'eth_sendRawTransaction', [$rawHex], 30);
        if (!$sent) throw new Exception("Broadcast failed: " . (evmLastRpcError() ?: 'rejected by network (no RPC error returned)'));
        return ['ok' => true, 'txhash' => $sent, 'explorer' => $cfg['explorer'] . $sent, 'nonce' => $nonce, 'gasPriceWei' => $gasPriceWei, 'gasLimit' => $gasLimit];
    } catch (\Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Send an ERC20/BEP20 token (including custom tokens).
 * @return array ['ok'=>bool, 'txhash'=>string|null, 'error'=>string|null]
 */
function evmSendToken(string $chain, string $fromPrvHex, string $toAddress, string $contractAddress, string $amount, int $decimals = 18): array {
    $cfg = evmChainConfig($chain);
    $chainId = $cfg['chainId'];

    try {
        $valueWei = evmToWei($amount, $decimals);
        $data = evmTokenTransferData($toAddress, $valueWei);
        $fromAddr = evmPrvToAddress($fromPrvHex);
        $contract = evmNormalizeAddress($contractAddress);

        $nonceHex = evmRpcCallAny($cfg['rpcs'], 'eth_getTransactionCount', [$fromAddr, 'pending']);
        if ($nonceHex === null) throw new Exception("Cannot fetch nonce (RPC unreachable)");
        $nonce = gmp_intval(gmp_init(preg_replace('/^0x/', '', $nonceHex), 16));

        $gasPriceHex = evmRpcCallAny($cfg['rpcs'], 'eth_gasPrice', []);
        $gasPriceWei = $gasPriceHex ? gmp_strval(gmp_init(preg_replace('/^0x/', '', $gasPriceHex), 16)) : '5000000000';

        $estGas = evmRpcCallAny($cfg['rpcs'], 'eth_estimateGas', [[
            'from' => $fromAddr, 'to' => '0x' . $contract, 'data' => '0x' . $data,
        ]]);
        $gasLimit = $estGas ? gmp_intval(gmp_init(preg_replace('/^0x/', '', $estGas), 16)) : 65000;
        $gasLimit = max(65000, $gasLimit + 5000);

        [$rawHex, $txHash] = evmSignTx($chainId, $fromPrvHex, $nonce, $gasPriceWei, $gasLimit, '0x' . $contract, '0', '0x' . $data);
        $sent = evmRpcCallAny($cfg['rpcs'], 'eth_sendRawTransaction', [$rawHex], 30);
        if (!$sent) throw new Exception("Broadcast failed: " . (evmLastRpcError() ?: 'rejected by network (no RPC error returned)'));
        return ['ok' => true, 'txhash' => $sent, 'explorer' => $cfg['explorer'] . $sent, 'nonce' => $nonce, 'gasPriceWei' => $gasPriceWei, 'gasLimit' => $gasLimit];
    } catch (\Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

/* ─────────────────────── DEX liquidity (real on-chain pools) ── */

/** DEX V2 Router for a chain (PancakeSwap on BSC, Uniswap on ETH). */
function evmDexRouter(string $chain): string {
    switch (strtoupper($chain)) {
        case 'BSC': return '0x10ED43C718714eb63d5aA57B78B54704E256024E'; // PancakeSwap V2 Router
        case 'ETH': return '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'; // Uniswap V2 Router
        default: return '';
    }
}

/**
 * Send an arbitrary EVM transaction to a contract (with optional value + data).
 * Used for approve() and addLiquidityETH() on DEX routers.
 * @return array ['ok'=>bool, 'txhash'=>string|null, 'explorer'=>string|null, 'error'=>string|null]
 */
function evmSendContractTx(string $chain, string $fromPrvHex, string $toAddress, string $valueWei, string $dataHex, int $gasCap = 600000): array {
    $cfg = evmChainConfig($chain);
    $chainId = $cfg['chainId'];
    try {
        $fromAddr = evmPrvToAddress($fromPrvHex);
        $to = evmNormalizeAddress($toAddress);

        $nonceHex = evmRpcCallAny($cfg['rpcs'], 'eth_getTransactionCount', [$fromAddr, 'pending']);
        if ($nonceHex === null) throw new Exception("Cannot fetch nonce (RPC unreachable)");
        $nonce = gmp_intval(gmp_init(preg_replace('/^0x/', '', $nonceHex), 16));

        $gasPriceHex = evmRpcCallAny($cfg['rpcs'], 'eth_gasPrice', []);
        $gasPriceWei = $gasPriceHex ? gmp_strval(gmp_init(preg_replace('/^0x/', '', $gasPriceHex), 16)) : '5000000000';

        $estGas = evmRpcCallAny($cfg['rpcs'], 'eth_estimateGas', [[
            'from' => $fromAddr,
            'to' => '0x' . $to,
            'value' => '0x' . gmp_strval(gmp_init($valueWei, 10), 16),
            'data' => '0x' . $dataHex,
        ]]);
        $gasLimit = $estGas ? gmp_intval(gmp_init(preg_replace('/^0x/', '', $estGas), 16)) : $gasCap;
        $gasLimit = max($gasCap, $gasLimit + 20000);

        [$rawHex, $txHash] = evmSignTx($chainId, $fromPrvHex, $nonce, $gasPriceWei, $gasLimit, '0x' . $to, $valueWei, '0x' . $dataHex);
        $sent = evmRpcCallAny($cfg['rpcs'], 'eth_sendRawTransaction', [$rawHex], 30);
        if (!$sent) throw new Exception("Broadcast failed: " . (evmLastRpcError() ?: 'rejected by network (no RPC error returned)'));
        return ['ok' => true, 'txhash' => $sent, 'explorer' => $cfg['explorer'] . $sent, 'nonce' => $nonce, 'gasPriceWei' => $gasPriceWei, 'gasLimit' => $gasLimit];
    } catch (\Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

/** ERC20 approve(address spender,uint256 amount) calldata */
function evmApproveData(string $spender, string $amountWei): string {
    $sp = evmNormalizeAddress($spender);
    return '095ea7b3' . str_pad($sp, 64, '0', STR_PAD_LEFT) . str_pad(gmp_strval(gmp_init($amountWei, 10), 16), 64, '0', STR_PAD_LEFT);
}

/** Approve a token so the DEX router can move it (needed before adding liquidity). */
function evmApproveToken(string $chain, string $fromPrvHex, string $tokenAddress, string $spender, string $amount, int $decimals = 18): array {
    try {
        $amountWei = evmToWei($amount, $decimals);
        $data = evmApproveData($spender, $amountWei);
        return evmSendContractTx($chain, $fromPrvHex, $tokenAddress, '0', $data, 150000);
    } catch (\Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Add REAL on-chain liquidity: pairs the deployed token with the chain's native
 * coin (BNB on BSC / ETH on ETH) via PancakeSwap V2 / Uniswap V2, using the
 * deployer wallet. This creates an actual pool so the token gets a price and
 * shows up with a value in Trust Wallet / DeFi wallets.
 * @return array ['ok'=>bool, 'approve_tx'=>string, 'liq_tx'=>string, 'explorer'=>string, 'error'=>string]
 */
function evmAddLiquidity(string $chain, string $fromPrvHex, string $tokenAddress, string $amountToken, string $amountNative, int $decimals = 18): array {
    $router = evmDexRouter($chain);
    if ($router === '') return ['ok' => false, 'error' => 'Liquidity is only supported on BSC (PancakeSwap) or ETH (Uniswap).'];
    try {
        $fromAddr = evmPrvToAddress($fromPrvHex);
        $token = evmNormalizeAddress($tokenAddress);
        $tokenWei = evmToWei($amountToken, $decimals);
        $nativeWei = evmToWei($amountNative, 18);
        $deadline = dechex(time() + 1200); // 20 minutes

        // 1) approve the router to spend the token
        $approve = evmApproveToken($chain, $fromPrvHex, '0x' . $token, $router, $amountToken, $decimals);
        if (empty($approve['ok'])) return ['ok' => false, 'error' => 'Approve failed: ' . ($approve['error'] ?? 'unknown')];

        // 2) addLiquidityETH(token, amountTokenDesired, amountTokenMin, amountETHMin, to, deadline)
        $data = 'f305d719'
            . str_pad($token, 64, '0', STR_PAD_LEFT)
            . str_pad(gmp_strval(gmp_init($tokenWei, 10), 16), 64, '0', STR_PAD_LEFT)  // amountTokenDesired
            . str_pad(gmp_strval(gmp_init($tokenWei, 10), 16), 64, '0', STR_PAD_LEFT)  // amountTokenMin
            . str_pad(gmp_strval(gmp_init($nativeWei, 10), 16), 64, '0', STR_PAD_LEFT) // amountETHMin
            . str_pad(evmNormalizeAddress($fromAddr), 64, '0', STR_PAD_LEFT)           // to = deployer (owns LP)
            . str_pad($deadline, 64, '0', STR_PAD_LEFT);                               // deadline
        $result = evmSendContractTx($chain, $fromPrvHex, $router, $nativeWei, $data, 600000);
        if (empty($result['ok'])) return ['ok' => false, 'error' => 'addLiquidityETH failed: ' . ($result['error'] ?? 'unknown')];

        return [
            'ok' => true,
            'approve_tx' => $approve['txhash'] ?? '',
            'liq_tx' => $result['txhash'] ?? '',
            'explorer' => $result['explorer'] ?? '',
            'router' => $router,
            'token' => '0x' . $token,
            'amountToken' => $amountToken,
            'amountNative' => $amountNative,
        ];
    } catch (\Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

/** Derive 0x address from a private key hex */
function evmPrvToAddress(string $prvHex): string {
    $ecc = new Secp256k1();
    $keyPair = new KeyPair($ecc, new Bytes32(hex2bin($prvHex)));
    $pub = $keyPair->public();
    $hash = Keccak::hash(hex2bin($pub->x . $pub->y), 256, true);
    return '0x' . bin2hex(substr($hash, -20));
}

/** Fetch native balance (ETH/BNB/MATIC) as decimal string */
function evmGetNativeBalance(string $chain, string $address): string {
    $cfg = evmChainConfig($chain);
    $bal = evmRpcCallAny($cfg['rpcs'], 'eth_getBalance', [$address, 'latest']);
    if ($bal === null) return '0';
    $wei = gmp_strval(gmp_init(preg_replace('/^0x/', '', $bal), 16));
    if (function_exists('bcdiv')) return bcdiv($wei, bcpow('10', '18', 0), 18);
    return (string)((float)$wei / 1e18);
}

/** Fetch ERC20/BEP20 token balance as decimal string */
function evmGetTokenBalance(string $chain, string $address, string $contractAddress, int $decimals = 18): string {
    $cfg = evmChainConfig($chain);
    $contract = evmNormalizeAddress($contractAddress);
    $addr = evmNormalizeAddress($address);
    $data = '0x70a08231000000000000000000000000' . $addr; // balanceOf(address)
    $bal = evmRpcCallAny($cfg['rpcs'], 'eth_call', [['to' => '0x' . $contract, 'data' => $data], 'latest']);
    if ($bal === null || $bal === '0x' || $bal === '0x0') return '0';
    $raw = gmp_strval(gmp_init(preg_replace('/^0x/', '', $bal), 16));
    if (function_exists('bcdiv')) return bcdiv($raw, bcpow('10', (string)$decimals, 0), $decimals);
    return (string)((float)$raw / pow(10, $decimals));
}

/** Convert hex string (no 0x) to a safe integer string (gmp with hexdec fallback) */
function evmHexToIntStr(string $hex): string {
    if ($hex === '' || preg_match('/^0+$/', $hex)) return '0';
    if (function_exists('gmp_init')) {
        return gmp_strval(gmp_init($hex, 16));
    }
    // fallback: hexdec returns float for big values, but caller casts to int for small fields
    return (string)(int)hexdec($hex);
}

/**
 * ABI-decode a string return value (e.g. name()/symbol()) from eth_call hex.
 * ABI string encoding: [32-byte offset][32-byte length][data padded to 32 bytes]
 * NOTE: deliberately avoids mbstring so it works on hosts without it.
 */
function evmAbiDecodeString(?string $hex): ?string {
    if (!$hex || $hex === '0x') return null;
    $hex = preg_replace('/^0x/', '', $hex);
    if (strlen($hex) < 128) return null;

    // offset word = position (in BYTES) of the string data, relative to data start
    $offsetWord = substr($hex, 0, 64);
    $offset = (int)evmHexToIntStr($offsetWord) * 2; // bytes -> hex chars
    if ($offset < 64 || $offset + 64 > strlen($hex)) return null;

    // length word
    $lenWord = substr($hex, $offset, 64);
    $strLen = (int)evmHexToIntStr($lenWord);
    if ($strLen <= 0 || $strLen > 200) return null;

    // string data (hex chars)
    $strStart = $offset + 64;
    if ($strStart + $strLen * 2 > strlen($hex)) return null;
    $strHex = substr($hex, $strStart, $strLen * 2);
    $str = @hex2bin($strHex);
    if ($str === false || $str === '') return null;

    // UTF-8 sanity check WITHOUT mbstring: preg_match with 'u' modifier
    if (!preg_match('//u', $str)) return null;

    return $str;
}

/** ABI-decode a uint return value (e.g. decimals()) from eth_call hex */
function evmAbiDecodeUint(?string $hex): ?int {
    if (!$hex || $hex === '0x') return null;
    $hex = preg_replace('/^0x/', '', $hex);
    if ($hex === '' || strlen($hex) > 64) return null;
    return (int)evmHexToIntStr($hex);
}

/* ─────────────────────── ABI encode helpers ─────────────────── */

/** 32-byte word, right-padded with zeros (for uint/address values) */
function evmAbiWord(string $hex, int $len = 64): string {
    return str_pad(substr($hex, 0, $len), $len, '0', STR_PAD_LEFT);
}

/**
 * ABI-encode the PlatformToken constructor:
 * constructor(string name, string symbol, uint8 decimals, uint256 totalSupply)
 * @return string hex (no 0x)
 */
function evmAbiEncodeTokenConstructor(string $name, string $symbol, int $decimals, string $totalSupply): string {
    $nameBytes = bin2hex($name);
    $symBytes = bin2hex($symbol);
    $nameLen = strlen($name);
    $symLen = strlen($symbol);

    $namePaddedLen = (int)(($nameLen + 31) / 32) * 32;
    $symPaddedLen = (int)(($symLen + 31) / 32) * 32;

    // Head: 4 words (128 bytes)
    $headOffset = 128;
    $symOffset = $headOffset + 32 + $namePaddedLen; // name data = length word + padded data

    $head =
        evmAbiWord(gmp_strval(gmp_init($headOffset, 10), 16)) . // offset of name
        evmAbiWord(gmp_strval(gmp_init($symOffset, 10), 16)) .  // offset of symbol
        evmAbiWord(gmp_strval(gmp_init($decimals, 10), 16)) .   // decimals as uint256
        evmAbiWord(gmp_strval(gmp_init($totalSupply, 10), 16)); // totalSupply

    $tail =
        evmAbiWord(gmp_strval(gmp_init($nameLen, 10), 16)) . $nameBytes . str_repeat('00', $namePaddedLen - $nameLen) .
        evmAbiWord(gmp_strval(gmp_init($symLen, 10), 16)) . $symBytes . str_repeat('00', $symPaddedLen - $symLen);

    return $head . $tail;
}

/* ─────────────────────── Contract deployment ────────────────── */

/**
 * Sign a raw contract-creation transaction (to = ''). Mirrors evmSignTx but
 * allows an empty recipient for contract deployment.
 * @return array [rawTxHex (0x...), txHashHex (0x...)]
 */
function evmSignContractTx(int $chainId, string $fromPrvHex, int $nonce, string $gasPriceWei, int $gasLimit, string $dataHex): array {
    $ecc = new Secp256k1();
    $privKey = new Bytes32(hex2bin($fromPrvHex));
    $keyPair = new KeyPair($ecc, $privKey);

    $nonceBin    = evmRlpDecodeIntBytes($nonce);
    $gasPriceBin = evmRlpDecodeHex(gmp_strval(gmp_init($gasPriceWei, 10), 16));
    $gasLimitBin = evmRlpDecodeIntBytes($gasLimit);
    $toBin       = ''; // contract creation
    $valueBin    = ''; // 0 value
    $dataBin     = $dataHex !== '' ? hex2bin(preg_replace('/^0x/i', '', $dataHex)) : '';

    $signingPayload = evmRlpEncode([$nonceBin, $gasPriceBin, $gasLimitBin, $toBin, $valueBin, $dataBin, $chainId, '', '']);
    $msgHash = Keccak::hash($signingPayload, 256, true);

    $signature = $keyPair->signRecoverable(new Bytes32($msgHash));
    $r = $signature->r->raw();
    $s = $signature->s->raw();
    $recoveryId = $signature->recoveryId;
    $v = $chainId * 2 + 35 + $recoveryId;

    $raw = evmRlpEncode([$nonceBin, $gasPriceBin, $gasLimitBin, $toBin, $valueBin, $dataBin, $v, $r, $s]);
    $rawHex = '0x' . bin2hex($raw);
    $txHash = '0x' . bin2hex(Keccak::hash($raw, 256, true));
    return [$rawHex, $txHash];
}

/** Derive the contract address created by [deployer, nonce] (keccak(rlp)[12:]) */
function evmDeriveContractAddress(string $fromAddress, int $nonce): string {
    $from = evmNormalizeAddress($fromAddress);
    $rlp = evmRlpEncode([hex2bin($from), evmRlpDecodeIntBytes($nonce)]);
    $hash = Keccak::hash($rlp, 256, true);
    return '0x' . bin2hex(substr($hash, -20));
}

/**
 * Deploy a compiled contract on-chain.
 *
 * $bytecodeHex is the compiler's creation bytecode (no 0x). Append
 * ABI-encoded constructor arguments to it if the constructor takes any —
 * evmAbiEncodeTokenConstructor() does this for the common ERC-20 shape of
 * constructor(string name, string symbol, uint8 decimals, uint256 supply).
 *
 * The contract address is read from the receipt once mined, falling back to
 * deriving it from (deployer, nonce) — those always agree for a CREATE
 * deployment, and the derivation is available immediately even if the
 * receipt is slow to appear.
 *
 * @return array ['ok'=>bool, 'address'=>?string, 'txhash'=>?string,
 *                'explorer'=>?string, 'error'=>?string]
 */
function evmDeployContract(string $chain, string $fromPrvHex, string $bytecodeHex, int $gasLimitFloor = 2500000): array {
    $cfg = evmChainConfig($chain);
    try {
        $dataHex = preg_replace('/^0x/i', '', $bytecodeHex);
        if ($dataHex === '' || !ctype_xdigit($dataHex)) {
            throw new Exception('Bytecode must be a non-empty hex string.');
        }
        $fromAddr = evmPrvToAddress($fromPrvHex);

        $nonceHex = evmRpcCallAny($cfg['rpcs'], 'eth_getTransactionCount', [$fromAddr, 'pending']);
        if ($nonceHex === null) throw new Exception('Cannot fetch nonce (RPC unreachable).');
        $nonce = gmp_intval(gmp_init(preg_replace('/^0x/', '', $nonceHex), 16));

        $gasPriceHex = evmRpcCallAny($cfg['rpcs'], 'eth_gasPrice', []);
        $gasPriceWei = $gasPriceHex ? gmp_strval(gmp_init(preg_replace('/^0x/', '', $gasPriceHex), 16)) : '5000000000';

        $estGas = evmRpcCallAny($cfg['rpcs'], 'eth_estimateGas', [['from' => $fromAddr, 'data' => '0x' . $dataHex]]);
        $gasLimit = $estGas ? gmp_intval(gmp_init(preg_replace('/^0x/', '', $estGas), 16)) : $gasLimitFloor;
        $gasLimit = max($gasLimitFloor, $gasLimit + 50000);

        [$rawHex] = evmSignContractTx($cfg['chainId'], $fromPrvHex, $nonce, $gasPriceWei, $gasLimit, $dataHex);
        $sent = evmRpcCallAny($cfg['rpcs'], 'eth_sendRawTransaction', [$rawHex], 30);
        if (!$sent) {
            throw new Exception('Broadcast failed: ' . (evmLastRpcError() ?: 'rejected by network. Check the deployer has enough native coin for gas.'));
        }

        $address = null;
        for ($i = 0; $i < 10; $i++) {
            $receipt = evmRpcCallAny($cfg['rpcs'], 'eth_getTransactionReceipt', [$sent], 10);
            if ($receipt && !empty($receipt['contractAddress'])) { $address = $receipt['contractAddress']; break; }
            sleep(3);
        }
        if (!$address) $address = evmDeriveContractAddress($fromAddr, $nonce);

        return ['ok' => true, 'address' => $address, 'txhash' => $sent,
                'explorer' => $cfg['explorer'] . $sent, 'error' => null];
    } catch (\Throwable $e) {
        return ['ok' => false, 'address' => null, 'txhash' => null, 'explorer' => null, 'error' => $e->getMessage()];
    }
}

/** Read a token's on-chain name() via eth_call (verifies deployment) */
function evmTokenName(string $chain, string $contract): ?string {
    $cfg = evmChainConfig($chain);
    $contract = evmNormalizeAddress($contract);
    $res = evmRpcCallAny($cfg['rpcs'], 'eth_call', [['to' => '0x' . $contract, 'data' => '0x06fdde03'], 'latest']);
    return evmAbiDecodeString($res);
}

/** Read a token's on-chain symbol() via eth_call */
function evmTokenSymbol(string $chain, string $contract): ?string {
    $cfg = evmChainConfig($chain);
    $contract = evmNormalizeAddress($contract);
    $res = evmRpcCallAny($cfg['rpcs'], 'eth_call', [['to' => '0x' . $contract, 'data' => '0x95d89b41'], 'latest']);
    return evmAbiDecodeString($res);
}

/** Read a token's on-chain totalSupply() via eth_call (wei string) */
function evmTokenTotalSupply(string $chain, string $contract): ?string {
    $cfg = evmChainConfig($chain);
    $contract = evmNormalizeAddress($contract);
    $res = evmRpcCallAny($cfg['rpcs'], 'eth_call', [['to' => '0x' . $contract, 'data' => '0x18160ddd'], 'latest']);
    if ($res === null || $res === '0x' || $res === '0x0') return null;
    return gmp_strval(gmp_init(preg_replace('/^0x/', '', $res), 16));
}

/** Generate a fresh random 64-hex private key */
function evmGeneratePrivateKey(): string {
    return bin2hex(random_bytes(32));
}

/* ─────────────────────── Payment verification ─────────────────── */

/**
 * Verify a client-submitted txhash is REAL proof of payment before crediting
 * anything server-side: confirmed on-chain, not reverted, and (for tokens)
 * an actual Transfer of at least $expectedAmount to $expectedTo. Pass
 * $contract = '' to verify a native-coin (ETH/BNB/MATIC) payment instead.
 *
 * Without this, a client can submit ANY well-formatted 0x… hash — including
 * a genuine transaction that simply reverted (e.g. insufficient token
 * balance, which still returns a txhash from eth_sendTransaction before
 * failing on-chain) — and the server would have no way to tell the
 * difference from a real payment.
 *
 * @return array ['ok'=>bool, 'error'=>string|null]
 */
function evmVerifyPayment(string $chain, string $txhash, string $expectedTo, float $expectedAmount, string $contract = '', int $decimals = 18): array {
    if (!preg_match('/^0x[0-9a-fA-F]{64}$/', $txhash)) {
        return ['ok' => false, 'error' => 'Invalid transaction hash.'];
    }
    if (!preg_match('/^0x[0-9a-fA-F]{40}$/', $expectedTo)) {
        return ['ok' => false, 'error' => 'Payment destination is not configured correctly.'];
    }
    try {
        $cfg = evmChainConfig($chain);
        $receipt = evmRpcCallAny($cfg['rpcs'], 'eth_getTransactionReceipt', [$txhash], 12);
        if (!$receipt) {
            return ['ok' => false, 'error' => 'Transaction not found yet — it may still be confirming. Please wait a few seconds and try again.'];
        }
        if (($receipt['status'] ?? '') !== '0x1') {
            return ['ok' => false, 'error' => 'That transaction failed on-chain — no funds were actually sent.'];
        }
        $toLower = strtolower($expectedTo);
        $expectedWei = gmp_init(evmToWei((string)$expectedAmount, $decimals), 10);

        if ($contract === '') {
            $tx = evmRpcCallAny($cfg['rpcs'], 'eth_getTransactionByHash', [$txhash], 12);
            if (!$tx) return ['ok' => false, 'error' => 'Could not look up that transaction.'];
            if (strtolower($tx['to'] ?? '') !== $toLower) {
                return ['ok' => false, 'error' => 'That transaction did not pay the expected address.'];
            }
            $valueWei = gmp_init(preg_replace('/^0x/', '', $tx['value'] ?? '0x0'), 16);
            if (gmp_cmp($valueWei, $expectedWei) < 0) {
                return ['ok' => false, 'error' => 'That transaction did not send enough.'];
            }
            return ['ok' => true, 'error' => null];
        }

        $contractLower = '0x' . evmNormalizeAddress($contract);
        // Computed live from the Keccak hasher already used for tx signing in
        // this file, rather than trusting a pasted/memorized constant.
        $transferTopic = '0x' . bin2hex(Keccak::hash('Transfer(address,address,uint256)', 256, true));
        foreach (($receipt['logs'] ?? []) as $log) {
            if (strtolower($log['address'] ?? '') !== $contractLower) continue;
            $topics = $log['topics'] ?? [];
            if (($topics[0] ?? '') !== $transferTopic || count($topics) < 3) continue;
            $logTo = '0x' . substr($topics[2], -40);
            if (strtolower($logTo) !== $toLower) continue;
            $raw = gmp_init(preg_replace('/^0x/', '', $log['data'] ?? '0x0'), 16);
            if (gmp_cmp($raw, $expectedWei) >= 0) return ['ok' => true, 'error' => null];
        }
        return ['ok' => false, 'error' => 'Could not find a matching payment of the expected token and amount in that transaction.'];
    } catch (\Throwable $e) {
        return ['ok' => false, 'error' => 'Could not verify that transaction right now (' . $e->getMessage() . '). Please try again shortly.'];
    }
}
