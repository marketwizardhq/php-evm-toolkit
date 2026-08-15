<?php
/**
 * Test bootstrap.
 *
 * The library ships as plain function files rather than PSR-4 classes, so
 * they're required directly. EvmHelpers loads Composer's autoloader itself
 * when present; tests needing secp256k1/Keccak skip themselves if it isn't.
 */
declare(strict_types=1);

require_once __DIR__ . '/../src/EvmHelpers.php';
require_once __DIR__ . '/../src/ChainScanner.php';
