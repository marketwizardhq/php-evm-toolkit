<?php
/**
 * ChainScanner — read an address's transaction history from EVM chains.
 *
 * Free explorer APIs are unreliable in different ways, so lookups cascade
 * through several sources rather than trusting any single one:
 *   1. Etherscan V2 unified multichain API (one key covers ETH/BSC/Polygon)
 *   2. Legacy per-chain explorer keys
 *   3. Keyless Blockscout (ETH + Polygon)
 *   4. Chunked eth_getLogs over recent blocks — no key required at all
 *
 * Exposes:
 *   hexToDec / divByPow10  — arbitrary-precision helpers for token amounts
 *                            that exceed PHP's integer range
 *   httpGet                — thin cURL wrapper
 *   fetchEvmTxs            — native + token transfers for an address
 *   fetchEvmTokenLogs      — keyless RPC-only token transfer fallback
 *
 * Configure API keys via the $EXPLORER_KEYS global:
 *   $EXPLORER_KEYS = ['ETHERSCAN' => 'yourkey', 'ETH' => '', 'BSC' => '', 'POLY' => ''];
 */

if (!function_exists('hexToDec')) {
function hexToDec($hex) {
    $hex = preg_replace('/^0x/i', '', $hex);
    if ($hex === '' || $hex === '0') return '0';
    if (!function_exists('gmp_init')) {
        $val = 0;
        foreach (str_split($hex) as $c) { $val = $val * 16 + hexdec($c); }
        return (string)$val;
    }
    return gmp_strval(gmp_init($hex, 16));
}

function divByPow10($decStr, $decimals) {
    $decStr = ltrim($decStr, '0');
    if ($decStr === '') $decStr = '0';
    $neg = false;
    if (substr($decStr, 0, 1) === '-') { $neg = true; $decStr = substr($decStr, 1); }
    if (strlen($decStr) <= $decimals) {
        $decStr = str_pad($decStr, $decimals + 1, '0', STR_PAD_LEFT);
    }
    $intPart = substr($decStr, 0, -$decimals);
    $fracPart = rtrim(substr($decStr, -$decimals), '0');
    $result = $intPart . ($fracPart !== '' ? '.' . $fracPart : '');
    return $neg ? '-' . $result : $result;
}

function httpGet($url, $timeout = 6) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => 1, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_USERAGENT => 'Mozilla/5.0', CURLOPT_FOLLOWLOCATION => true,
    ]);
    $res = curl_exec($ch);
    curl_close($ch);
    return $res;
}

}

// evmRpcCall() intentionally lives in EvmHelpers.php only.
//
// Both files originally declared their own copy, guarded by
// `function_exists('hexToDec')` — a guard on a DIFFERENT function name, so
// loading EvmHelpers first and ChainScanner second would fatal with
// "Cannot redeclare evmRpcCall()". A single definition removes the whole
// class of problem, and EvmHelpers' version is the better one anyway
// (endpoint failover + captured RPC error messages).
require_once __DIR__ . '/EvmHelpers.php';

if (!function_exists('fetchEvmTxs')) {
function fetchEvmTxs($chain, $address) {
    global $EXPLORER_KEYS;
    $txs = [];
    if ($chain === 'ETH')   { $sym = 'ETH'; }
    elseif ($chain === 'BSC') { $sym = 'BNB'; }
    else                    { $sym = 'MATIC'; }

    $explMap = ['ETH' => 'etherscan.io', 'BSC' => 'bscscan.com', 'POLY' => 'polygonscan.com'];
    $chainIdMap = ['ETH' => 1, 'BSC' => 56, 'POLY' => 137];
    $rpcMap = ['ETH' => 'https://eth.llamarpc.com', 'BSC' => 'https://bsc-dataseed1.binance.org', 'POLY' => 'https://polygon-rpc.com'];

    // Multi-source fetching so deposits are found even without paid API keys:
    //   1. ONE Etherscan API key (free at etherscan.io/apis) now covers ETH + BSC +
    //      Polygon via the unified V2 multichain API — this is the recommended setup
    //      and the only way BSC gets reliably detected (there is no free keyless BSC
    //      explorer). Configure it as $EXPLORER_KEYS['ETHERSCAN'].
    //   2. Legacy per-chain keys (ETH/BSC/POLY) still work if that's what's configured.
    //   3. Keyless Blockscout (ETH + Polygon only) as a secondary source.
    //   4. Chunked RPC eth_getLogs as a last-resort keyless fallback for token
    //      transfers (recent blocks only — public nodes reject wide block ranges).
    $apiList = [];
    $unifiedKey = trim($EXPLORER_KEYS['ETHERSCAN'] ?? '');
    if ($unifiedKey !== '') {
        $apiList[] = ['url' => 'https://api.etherscan.io/v2/api', 'key' => $unifiedKey, 'chainid' => $chainIdMap[$chain] ?? 1, 'expl' => $explMap[$chain]];
    } else {
        $legacyUrlMap = ['ETH' => 'https://api.etherscan.io/api', 'BSC' => 'https://api.bscscan.com/api', 'POLY' => 'https://api.polygonscan.com/api'];
        $legacyKey = trim($EXPLORER_KEYS[$chain] ?? '');
        if ($legacyKey !== '') {
            $apiList[] = ['url' => $legacyUrlMap[$chain], 'key' => $legacyKey, 'chainid' => 0, 'expl' => $explMap[$chain]];
        }
        if ($chain === 'ETH')  $apiList[] = ['url' => 'https://eth.blockscout.com/api', 'key' => '', 'chainid' => 0, 'expl' => 'blockscout.com'];
        if ($chain === 'POLY') $apiList[] = ['url' => 'https://polygon.blockscout.com/api', 'key' => '', 'chainid' => 0, 'expl' => 'polygonscan.com'];
    }

    $seen = [];
    $recordTx = function ($tx) use (&$txs, &$seen) {
        if (empty($tx['txid'])) return;
        $k = $tx['txid'] . '|' . ($tx['coin'] ?? '');
        if (isset($seen[$k])) return;
        $seen[$k] = true;
        $txs[] = $tx;
    };

    foreach ($apiList as $api) {
        $apiCall = function ($action) use ($api, $address) {
            $url = "{$api['url']}?module=account&action=$action&sort=desc&page=1&offset=25&address=$address";
            if (!empty($api['chainid'])) $url .= "&chainid={$api['chainid']}";
            if ($api['key'] !== '') $url .= "&apikey={$api['key']}";
            $res = httpGet($url, 7);
            return json_decode($res, true);
        };

        $data = $apiCall('txlist');
        if (is_array($data) && !empty($data['result']) && is_array($data['result'])) {
            foreach (array_slice($data['result'], 0, 25) as $tx) {
                $val = (float)divByPow10(hexToDec($tx['value'] ?? '0'), 18);
                if ($val <= 0) continue;
                $type = strtolower($tx['to'] ?? '') === strtolower($address) ? 'in' : 'out';
                $recordTx([
                    'chain'=>$chain,'coin'=>$sym,'type'=>$type,'amount'=>$val,
                    'txid'=>$tx['hash'],
                    'from_addr'=>$tx['from'] ?? '', 'to_addr'=>$tx['to'] ?? '',
                    'time'=>(int)($tx['timeStamp'] ?? time()),
                    'url'=>"https://{$api['expl']}/tx/{$tx['hash']}"
                ]);
            }
        }

        $data = $apiCall('tokentx');
        if (is_array($data) && !empty($data['result']) && is_array($data['result'])) {
            foreach (array_slice($data['result'], 0, 25) as $tx) {
                $dec = (int)($tx['tokenDecimal'] ?? 18);
                $val = (float)divByPow10(hexToDec($tx['value'] ?? '0'), $dec);
                if ($val <= 0) continue;
                $type = strtolower($tx['to'] ?? '') === strtolower($address) ? 'in' : 'out';
                $recordTx([
                    'chain'=>$chain,'coin'=>$tx['tokenSymbol'] ?? 'TOKEN','type'=>$type,'amount'=>$val,
                    'txid'=>$tx['hash'],
                    'from_addr'=>$tx['from'] ?? '', 'to_addr'=>$tx['to'] ?? '',
                    'time'=>(int)($tx['timeStamp'] ?? time()),
                    'url'=>"https://{$api['expl']}/tx/{$tx['hash']}"
                ]);
            }
        }
    }

    if (count($txs) < 3 && !empty($rpcMap[$chain])) {
        $rpcTxs = fetchEvmTokenLogs($rpcMap[$chain], $chain, $address);
        foreach ($rpcTxs as $tx) $recordTx($tx);
    }

    return $txs;
}

/**
 * Keyless token-transfer fallback via RPC eth_getLogs. Public nodes reject
 * wide block ranges (or silently time out), which is why the old single
 * 500,000-block call almost always returned nothing — this scans the most
 * recent blocks in small provider-safe chunks instead, stopping early once
 * enough results are found.
 */
function fetchEvmTokenLogs($rpc, $chain, $address) {
    $txs = [];
    $addrLower = strtolower($address);
    $addrPadded = substr($addrLower, 2);
    $transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
    $expl = $chain === 'ETH' ? 'etherscan.io' : ($chain === 'BSC' ? 'bscscan.com' : 'polygonscan.com');
    $addrTopic = '0x' . str_pad($addrPadded, 64, '0', STR_PAD_LEFT);

    try {
        $latestHex = evmRpcCall($rpc, 'eth_blockNumber', []);
        if (!$latestHex) return $txs;
        $latest = gmp_intval(gmp_init(preg_replace('/^0x/', '', $latestHex), 16));

        $chunkSize = 3000;
        $maxChunks = 10; // ~30,000 most-recent blocks per call, in safe chunks
        $to = $latest;
        for ($c = 0; $c < $maxChunks && $to > 0; $c++) {
            $from = max(0, $to - $chunkSize + 1);
            $fromHex = '0x' . gmp_strval(gmp_init($from, 10), 16);
            $toHex = '0x' . gmp_strval(gmp_init($to, 10), 16);

            foreach ([
                ['from' => null, 'to' => $addrTopic],   // incoming
                ['from' => $addrTopic, 'to' => null],   // outgoing
            ] as $t) {
                $topics = [$transferTopic];
                $topics[] = $t['from'] ?: null;
                if ($t['to']) $topics[] = $t['to'];
                $logs = evmRpcCall($rpc, 'eth_getLogs', [[
                    'fromBlock' => $fromHex,
                    'toBlock' => $toHex,
                    'topics' => $topics,
                ]], 10);

                if (!is_array($logs)) continue; // this chunk was rejected/timed out — skip, keep scanning
                foreach ($logs as $log) {
                    $txid = $log['transactionHash'] ?? '';
                    if (!$txid) continue;
                    $from = isset($log['topics'][1]) ? '0x' . substr($log['topics'][1], -40) : '';
                    $to   = isset($log['topics'][2]) ? '0x' . substr($log['topics'][2], -40) : '';
                    $amountHex = isset($log['data']) ? preg_replace('/^0x/', '', $log['data']) : '0';
                    $amount = $amountHex ? (float)divByPow10(hexToDec($amountHex), 18) : 0;
                    if ($amount <= 0) continue;
                    $type = strtolower($to) === $addrLower ? 'in' : 'out';
                    $txs[] = [
                        'chain' => $chain, 'coin' => 'TOKEN', 'type' => $type, 'amount' => $amount,
                        'txid' => $txid, 'from_addr' => $from, 'to_addr' => $to,
                        'time' => time(), 'url' => "https://$expl/tx/$txid"
                    ];
                }
            }
            $to = $from - 1;
            if (count($txs) >= 10) break;
        }
    } catch (\Throwable $e) {}
    return $txs;
}

}
