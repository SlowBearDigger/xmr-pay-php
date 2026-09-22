<?php
// Verify scan checkpoints against interrupted and conflicting local RPC responses.
if (PHP_SAPI === 'cli-server') {
    header('Content-Type: application/json');
    $kind = explode('/', trim($_SERVER['REQUEST_URI'], '/'))[0];
    if (strpos($_SERVER['REQUEST_URI'], 'get_height') !== false) { echo '{"height":1003}'; return; }
    $body = json_decode(file_get_contents('php://input'), true);
    $height = (int) ($body['params']['height'] ?? 1000);
    if ($kind === 'offline' || ($kind === 'interrupted' && $height > 1000)) { http_response_code(503); echo '{}'; return; }
    if (strpos($_SERVER['REQUEST_URI'], 'get_transactions') !== false) { echo '{"txs":[]}'; return; }
    $hashes = $kind === 'missing-transactions' ? [str_repeat('a', 64)] : [];
    echo json_encode(['result' => ['block_header' => ['height' => $height, 'hash' => str_repeat($kind === 'conflict' ? 'b' : 'a', 64), 'num_txes' => count($hashes), 'orphan_status' => $kind === 'orphan'], 'tx_hashes' => $hashes]]);
    return;
}
require __DIR__ . '/bootstrap.php';
$socket = stream_socket_server('tcp://127.0.0.1:0');
$address = stream_socket_get_name($socket, false); fclose($socket);
$server = proc_open([PHP_BINARY, '-S', $address, __FILE__], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
$check = function ($condition, $name) { if (!$condition) throw new RuntimeException($name); echo "PASS $name\n"; };
try {
    for ($i=0; $i<50; $i++) { $ready=@stream_socket_client('tcp://'.$address,$errno,$error,.05); if($ready){fclose($ready);break;} usleep(20000); }
    $check((bool)$ready, 'RPC fixture ready');
    $node = function ($kind) use ($address) { return 'http://'.$address.'/'.$kind; };
    foreach (['offline'=>999, 'interrupted'=>1000, 'missing-transactions'=>999, 'orphan'=>999, 'healthy'=>1002] as $kind=>$last) {
        $scanner = new XmrPay\Scanner($node($kind), 'stagenet', 1);
        $check($scanner->tip_height() === 1003, $kind.' height is available');
        $r = $scanner->scan_all('unused', 'unused', 1000, 1002, ['tip'=>1003]);
        $check($r['scanned_to'] === $last && $r['matches'] === [], $kind.' checkpoint only advances over complete blocks');
    }
    $scanner = new XmrPay\Scanner([$node('healthy'),$node('conflict')], 'stagenet', 1);
    $r=$scanner->scan_all('unused','unused',1000,1002,['tip'=>1003]);
    $check($r['scanned_to'] === 999, 'conflicting block hashes stop progress');
    $scanner = new XmrPay\Scanner($node('healthy'), 'stagenet', 1);
    $r=$scanner->scan_all('unused','unused',1001,1002,['tip'=>1003]);
    $check($r['scanned_to'] === 1002, 'retry resumes at the first incomplete block');
    $r=$scanner->scan_all('unused','unused',1000,1002,['tip'=>1003,'max_blocks'=>1]);
    $check($r['scanned_to'] === 1000, 'block budget does not skip unscanned heights');
} finally { proc_terminate($server); proc_close($server); }
