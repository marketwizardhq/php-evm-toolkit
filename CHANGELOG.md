# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-08-15

First public release.

### Added

- **RLP encoder** — recursive, with canonical short/long-form length prefixes and the empty-string encoding for zero
- **EIP-155 transaction signing** — Keccak-256 over the RLP payload, secp256k1 recoverable signatures, `v = chainId * 2 + 35 + recoveryId`
- **Native and ERC-20 transfers** (`evmSendNative`, `evmSendToken`) with gas estimation and nonce lookup
- **On-chain payment verification** (`evmVerifyPayment`) — confirms a transaction is mined, succeeded, and actually transferred the expected amount to the expected address before any credit is issued
- **Contract deployment** (`evmDeployContract`) with address derivation from `keccak(rlp([sender, nonce]))[12:]`
- **ABI codec** — constructor argument encoding with correct head/tail offsets for dynamic types, and `string`/`uint` return decoding
- **DEX helpers** — `evmApproveToken`, `evmAddLiquidity` for PancakeSwap / Uniswap V2 routers
- **Multi-source transaction scanning** (`ChainScanner`) — Etherscan V2 unified API, legacy per-chain keys, keyless Blockscout, and chunked `eth_getLogs` as fallbacks
- **Arbitrary-precision helpers** — `evmToWei`, `hexToDec`, `divByPow10`, using GMP with a bcmath fallback, so token amounts beyond PHP's integer range keep full precision
- PHPUnit suite covering RLP, ABI and signing against published vectors, including the EIP-155 worked example asserted byte for byte
- GitHub Actions CI across PHP 8.1, 8.2 and 8.3

### Security

- TLS certificate verification is enabled by default on all outbound RPC and API calls, with `EVM_CA_BUNDLE` for hosts lacking a CA bundle. An earlier internal version disabled verification for shared-hosting convenience; that is unsafe in a library which decides payment validity from RPC responses, and is no longer possible without explicitly opting in via `EVM_INSECURE_TLS`.

### Known limitations

- Legacy (type-0) transactions only — no EIP-1559 support
- No nonce queue; concurrent sends from one address can collide
- Function files rather than PSR-4 classes

[Unreleased]: https://github.com/marketwizardhq/php-evm-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/marketwizardhq/php-evm-toolkit/releases/tag/v0.1.0
