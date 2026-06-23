<?php
// Test bootstrap. Loads the engine WITHOUT Composer (manual requires in dependency order) and
// aliases the legacy global class names the ported suite uses (XmrPay_Util / XmrPay_Scanner) to
// the namespaced classes, so the tests run essentially unchanged.

$root = dirname(__DIR__);
require_once $root . '/third-party/monero/base58.php';
require_once $root . '/third-party/monero/Varint.php';
require_once $root . '/third-party/monero/Keccak.php';
require_once $root . '/third-party/monero/ed25519.php';
require_once $root . '/third-party/monero/Cryptonote.php';
require_once $root . '/src/Util.php';
require_once $root . '/src/Scanner.php';

if (!class_exists('XmrPay_Util', false)) {
    class_alias('XmrPay\\Util', 'XmrPay_Util');
}
if (!class_exists('XmrPay_Scanner', false)) {
    class_alias('XmrPay\\Scanner', 'XmrPay_Scanner');
}
