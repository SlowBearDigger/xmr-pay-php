<?php
// Exercise real HTTP Basic/Digest transport, node agreement and response limits locally.
if (PHP_SAPI === 'cli-server') {
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $kind = explode('/', trim($path, '/'))[0];
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($kind === 'basic' && $authorization !== 'Basic ' . base64_encode('merchant:test-password')) {
        header('WWW-Authenticate: Basic realm="node"', true, 401);
        echo 'authentication required';
        return;
    }
    if ($kind === 'digest') {
        preg_match_all('/(\w+)=(?:"([^"]*)"|([^,\s]+))/', $authorization, $matches, PREG_SET_ORDER);
        $values = [];
        foreach ($matches as $match) { $values[$match[1]] = $match[2] !== '' ? $match[2] : ($match[3] ?? ''); }
        $expected = isset($values['nc'], $values['cnonce'], $values['uri'])
            ? md5(md5('merchant:node:test-password') . ':test-nonce:' . $values['nc'] . ':' . $values['cnonce'] . ':auth:' . md5($_SERVER['REQUEST_METHOD'] . ':' . $values['uri'])) : '';
        if (($values['username'] ?? '') !== 'merchant' || $expected === '' || !hash_equals($expected, $values['response'] ?? '')) {
            header('WWW-Authenticate: Digest realm="node", nonce="test-nonce", algorithm=MD5, qop="auth"', true, 401);
            echo 'authentication required';
            return;
        }
    }
    if ($kind === 'redirect') { header('Location: /public/get_height', true, 307); return; }
    if ($kind === 'oversized') { echo str_repeat(' ', 5 * 1024 * 1024); return; }
    header('Content-Type: application/json');
    if (substr($path, -17) === '/get_transactions') {
        echo json_encode(['txs' => [['tx_hash' => str_repeat('a', 64), 'as_json' => '{"extra":[],"vout":[]}', 'block_height' => 99, 'in_pool' => false]]]);
    } else {
        echo '{"height":100}';
    }
    return;
}
require_once __DIR__ . '/bootstrap.php';
if (!extension_loaded('curl')) { throw new RuntimeException('The transport test requires ext-curl.'); }
$socket = stream_socket_server('tcp://127.0.0.1:0');
$address = stream_socket_get_name($socket, false);
fclose($socket);
$server = proc_open([PHP_BINARY, '-S', $address, __FILE__], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
$checks = 0;
$check = function ($condition, $message) use (&$checks) {
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
};
try {
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $ready = @stream_socket_client('tcp://' . $address, $errno, $error, 0.05);
        if ($ready) { fclose($ready); break; }
        usleep(20000);
    }
    $check((bool)$ready, 'local node did not start');
    $node = function ($kind, $password = 'test-password') use ($address) {
        return ['url' => 'http://' . $address . '/' . $kind, 'auth' => in_array($kind, ['basic', 'digest'], true) ? $kind : 'none', 'username' => 'merchant', 'password' => $password, 'allow_insecure_http' => true];
    };
    foreach (['basic', 'digest'] as $auth) {
        $scanner = new XmrPay\Scanner([$node($auth)], 'stagenet', 2);
        $check($scanner->tip_height() === 100, $auth . ' height');
        $check(count($scanner->fetch_txs([str_repeat('a', 64)])) === 1, $auth . ' transactions');
        $scanner = new XmrPay\Scanner([$node($auth, 'wrong-password')], 'stagenet', 2);
        $check($scanner->tip_height() === null, $auth . ' rejects wrong password');
        $check($scanner->last_node_error()['code'] === 'authentication-rejected', $auth . ' error code');
        $check(strpos(json_encode($scanner->last_node_error()), 'wrong-password') === false, 'redacted error');
    }
    $scanner = new XmrPay\Scanner([$node('basic'), $node('digest')], 'stagenet', 2);
    $check($scanner->tip_height() === 100, 'agreeing authenticated nodes');
    $check(count($scanner->fetch_txs([str_repeat('a', 64)])) === 1, 'agreeing transaction evidence');
    $scanner = new XmrPay\Scanner([$node('basic', 'wrong-password'), $node('digest')], 'stagenet', 2);
    $check($scanner->tip_height() === null, 'unavailable configured node pauses settlement');
    $check($scanner->fetch_txs([str_repeat('a', 64)]) === null, 'partial node agreement is insufficient');
    $scanner = new XmrPay\Scanner([$node('redirect')], 'stagenet', 2);
    $check($scanner->tip_height() === null, 'redirects are not followed');
    $scanner = new XmrPay\Scanner([$node('oversized')], 'stagenet', 2);
    $check($scanner->tip_height() === null, 'oversized response rejected');
    $check($scanner->last_node_error()['code'] === 'response-too-large', 'response stopped at byte limit');
    echo "HTTP node authentication and limits: $checks checks passed\n";
} finally {
    proc_terminate($server);
    proc_close($server);
}
