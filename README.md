# PHP EVM Toolkit

[![tests](https://github.com/marketwizardhq/php-evm-toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/marketwizardhq/php-evm-toolkit/actions/workflows/tests.yml)
[![PHP 8.1+](https://img.shields.io/badge/php-8.1%2B-777bb4)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Low-level Ethereum/EVM utilities for PHP with **no web3 library**. RLP encoding, EIP-155 transaction signing, the ABI codec and contract-address derivation are implemented here directly; the only runtime dependencies are the three cryptographic/byte primitives worth not writing by hand (secp256k1, Keccak-256, and a byte buffer).

Extracted from components built for a crypto wallet platform, where shared hosting ruled out running a Node or Geth process and the available PHP web3 wrappers were either abandoned or too heavy. This repository is new — the code has been exercised against BSC and Polygon, but treat it as `0.x` and read the [scope and limitations](#scope-and-limitations) before using it with real funds.

## What's in it

### Transaction signing (`src/EvmHelpers.php`)

Raw EIP-155 transactions built and signed entirely in PHP:

- **RLP encoder** — recursive, handles nested arrays and the canonical short/long-form length prefixes
- **EIP-155 signing** — Keccak-256 over the RLP payload, secp256k1 recoverable signature, `v = chainId * 2 + 35 + recoveryId`
- **Native + ERC-20 transfers** with gas estimation and nonce management
- **Contract deployment** including deriving the resulting contract address from `keccak(rlp([sender, nonce]))[12:]`
- **ABI codec** — encode constructor arguments (including dynamic strings with correct head/tail offsets), decode `string`/`uint` return values

One detail that cost real debugging time: a zero `value` field must RLP-encode as the empty string (`0x80`), not a zero byte (`0x00`). Nodes reject the non-canonical form with an opaque `unmarshal transaction failed`.

### On-chain payment verification (`evmVerifyPayment`)

Verifies a client-submitted transaction hash actually paid what it claims, before any server-side credit:

- Transaction is mined and `status == 0x1` (**not** reverted)
- For ERC-20: a `Transfer` log from the right contract, to the right address, for at least the expected amount
- For native coin: correct recipient and value

This matters more than it sounds. `eth_sendTransaction` returns a valid-looking hash the moment a transaction is *broadcast* — a transfer that later reverts on-chain (insufficient token balance, for example) still produced that hash. Trusting a well-formed hash as proof of payment is a real vulnerability, and this closes it.

The `Transfer(address,address,uint256)` topic is computed through Keccak at runtime rather than pasted as a magic constant.

### Contract deployment

`evmDeployContract()` broadcasts compiler creation bytecode and returns the deployed address — read from the receipt, falling back to `keccak(rlp([sender, nonce]))[12:]`, which is available immediately even when the receipt lags. `evmAbiEncodeTokenConstructor()` encodes arguments for the common ERC-20 `constructor(string, string, uint8, uint256)` shape, including correct head/tail offsets for the dynamic string parameters.

### Transaction scanning (`src/ChainScanner.php`)

Address history across Ethereum, BSC and Polygon with layered fallbacks, because free-tier explorer APIs are unreliable in different ways:

1. Etherscan V2 unified multichain API (one key covers ETH + BSC + Polygon)
2. Legacy per-chain explorer keys
3. Keyless Blockscout
4. Chunked `eth_getLogs` over recent blocks as a last resort

Includes arbitrary-precision hex→decimal and decimal-shift helpers (GMP with a pure-PHP fallback), since token amounts routinely exceed PHP's integer range.

## Usage

> ⚠️ **This library signs real transactions with real private keys.** Never hard-code, commit, or log a private key. Load it from an environment variable or a secrets manager, and keep it out of version control and error logs. The examples below use placeholders.
>
> **Amount units:** functions taking a human amount (`evmSendToken`, `evmSendNative`, `evmVerifyPayment`) expect a *decimal string* — `'10.5'`, not wei. Functions ending in `Wei` (`evmTokenTransferData`, `evmSignTx`) expect the *integer wei string* — `'10500000'`. Passing one where the other is expected is silent and expensive; `evmToWei()` converts between them.

```php
require_once 'src/EvmHelpers.php';

// Send 10 USDT on BSC
$result = evmSendToken(
    'BSC',
    $privateKeyHex,
    '0xRecipient...',
    '0x55d398326f99059ff775485246999027b3197955', // USDT (BEP20)
    '10.0',
    18
);
// => ['ok' => true, 'txhash' => '0x...', 'explorer' => 'https://bscscan.com/tx/0x...']

// Verify an incoming payment before crediting anything
$check = evmVerifyPayment('BSC', $txhash, $expectedTo, 10.0, $usdtContract, 18);
if ($check['ok']) { /* safe to credit */ }
```

See [`examples/`](examples/) for runnable scripts.

## Install

```bash
composer install
```

Requires PHP 8.0+, `ext-curl`, and `ext-gmp` (or `ext-bcmath` as a fallback) — token amounts routinely exceed PHP's native integer range.

## TLS

Certificate verification is **on by default** and should stay that way. This library signs transactions and verifies payments, so an unverified connection is not a cosmetic issue: a man-in-the-middle able to forge an `eth_getTransactionReceipt` response can convince `evmVerifyPayment()` that a payment succeeded when no funds ever moved.

If your host has no CA bundle, point the library at one rather than disabling checks:

```php
define('EVM_CA_BUNDLE', '/path/to/cacert.pem'); // https://curl.se/ca/cacert.pem
```

`EVM_INSECURE_TLS` exists only for local development against a self-signed node.

## Trust model

Worth stating plainly, because it decides how much this library can promise:

**`evmVerifyPayment()` is only as trustworthy as the RPC endpoint answering it.** It re-derives nothing from consensus — it asks a node for a receipt and reads the reply. A node that lies (compromised, malicious, or impersonated over an unverified connection) can report a successful transfer that never happened, and this library will believe it. TLS verification closes the impersonation route; it does not make an untrustworthy node trustworthy.

Practical consequences:

- The defaults in `evmChainConfig()` are **public community endpoints**. They are fine for reads and for development. For anything holding real value, run your own node or use a provider you have an agreement with.
- Verification reflects **one node's view at one moment**. It does not wait for finality. For high-value payments, require a confirmation depth appropriate to the chain before treating a payment as settled.
- Multiple endpoints are tried in order until one answers (`evmRpcCallAny`); results are **not** cross-checked between them. That is failover, not consensus.

None of this is unusual — every off-chain payment integration inherits it — but a library that decides whether money arrived should say so out loud rather than let you assume otherwise.

## Scope and limitations

Being straightforward about what this is:

- **Legacy (type-0) transactions only.** No EIP-1559 (`maxFeePerGas`/`maxPriorityFeePerGas`). Fine on BSC and Polygon; on Ethereum mainnet you'll overpay relative to a type-2 transaction.
- **No local mempool or nonce queue.** Nonce comes from `eth_getTransactionCount(..., 'pending')`, so rapid concurrent sends from one address can collide.
- **Function files, not PSR-4 classes.** Loaded via Composer's `files` autoloader. Namespacing is on the roadmap.
- Key handling is the caller's responsibility. Nothing here manages or protects private keys.

## Tests

```bash
composer install
composer test
```

The suite checks the hand-rolled encoders against published vectors rather than against itself:

- **RLP** — vectors from the Ethereum RLP specification: short/long form boundaries at 55 and 56 bytes, nested lists, and the zero-encodes-as-`0x80` rule that nodes reject if you get it wrong.
- **EIP-155 signing** — the worked example from [EIP-155](https://eips.ethereum.org/EIPS/eip-155), asserted byte for byte. This one test exercises RLP, Keccak, secp256k1 recoverable signing and the `v = chainId*2 + 35 + recoveryId` calculation together; if the output matches, the signing path is correct.
- **ABI** — ERC-20 selectors (`transfer`, `approve`) and calldata layout, dynamic string decoding, and the `Transfer(address,address,uint256)` event topic computed rather than pasted.
- **Amount conversion** — arbitrary-precision correctness, including a 1e27 supply that would lose precision through a float.

Signing tests skip cleanly if the crypto dependencies aren't installed.

## Roadmap

- [ ] EIP-1559 (type-2) transaction support
- [ ] PSR-4 namespacing (currently function files via Composer `files` autoloading)
- [ ] Nonce management for concurrent sends
- [ ] Testnet integration tests against a live node

## License

MIT — see [LICENSE](LICENSE).
