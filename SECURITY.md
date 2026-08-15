# Security Policy

This library signs blockchain transactions and verifies payments. Bugs here can cost real money, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately — **do not open a public issue** for anything exploitable.

Use [GitHub's private vulnerability reporting](https://github.com/marketwizardhq/php-evm-toolkit/security/advisories/new) on this repository.

Helpful to include:

- affected version or commit
- PHP version and which of `gmp` / `bcmath` is installed
- chain and, if relevant, contract address
- a minimal reproduction
- what you believe the impact is

**Never include a private key, seed phrase, or mnemonic in a report.** If a key may have been exposed, move the funds first and report afterwards. Use a throwaway testnet key in any reproduction.

Expect an initial response within about a week.

## Supported versions

`0.x` — pre-1.0. Fixes land on `main`; there is no backport policy yet.

## Security model and assumptions

Understanding these matters more than any single bug report:

**Key handling is entirely the caller's responsibility.** This library never stores, encrypts or manages private keys — it accepts a hex key, signs with it, and discards it. Storage, access control and rotation are yours to design.

**TLS verification is on by default and must stay that way.** `evmVerifyPayment()` decides whether a payment is real by reading an `eth_getTransactionReceipt` response. With verification disabled, a man-in-the-middle can forge that response and convince your application a payment succeeded when no funds moved. `EVM_INSECURE_TLS` exists only for local development against a self-signed node — never set it in production. If your host lacks a CA bundle, set `EVM_CA_BUNDLE` instead.

**A transaction hash is not proof of payment.** `eth_sendTransaction` returns a valid-looking hash the moment a transaction is *broadcast*. A transfer that later reverts on-chain still produced that hash. Always verify with `evmVerifyPayment()` before crediting anything — checking hash *format* alone is exploitable.

**Public RPC endpoints are third parties.** The defaults in `evmChainConfig()` are public nodes. They see your requests, can rate-limit you, and can return wrong data. For anything with real value, use your own node or a provider you have an agreement with.

**Nonces are read live, not queued.** Concurrent sends from the same address can collide and produce failed transactions. Serialise sends per address at the application level.

## Out of scope

- Vulnerabilities in the upstream dependencies (report those to their maintainers)
- Loss of funds from keys stored insecurely by the calling application
- Public RPC endpoints being unavailable or rate-limiting
