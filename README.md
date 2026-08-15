# PHP EVM Toolkit

Low-level Ethereum/EVM utilities for PHP, written from scratch — **no web3 library, no ethers, no Composer dependencies** beyond a secp256k1 signer and a Keccak implementation.

Built while shipping a production crypto wallet platform, where shared hosting ruled out running a Node/Geth process and the available PHP web3 wrappers were either abandoned or too heavy. Everything here is the part that had to be written by hand.

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
