<?php
// Copy to stagenet.config.php (gitignored) and fill from your stagenet test wallet.
// Only the PRIVATE VIEW KEY is sensitive — and on stagenet the coins are worthless test XMR.
// The txids + expectedTotalXmr are the real payments the integration test verifies on-chain.
return [
    'node'                => 'http://node.monerodevs.org:38089',
    'primaryAddress'      => '5...your stagenet primary address...',
    'orderSubaddress'     => '7...the funded order subaddress...',
    'orderSubaddressIndex' => 1,
    'viewKey'             => '...your 64-hex PRIVATE view key...',
    'txids'               => [
        // 64-hex txids of the real payments to the order subaddress
    ],
    'expectedTotalXmr'    => '0.12',
];
