<?php
// Proves the package resolves through its OWN composer.json autoload config (PSR-4 + classmap),
// NOT the test bootstrap's manual requires — i.e. a real `composer require` consumer gets every
// class. Builds a loader straight from composer.json so this fails if the config ever drifts.

$root = dirname(__DIR__);
$composer = json_decode(file_get_contents("$root/composer.json"), true);
$psr4 = $composer['autoload']['psr-4'] ?? [];
$classmapDirs = $composer['autoload']['classmap'] ?? [];

// classmap: tokenize the configured dirs for `namespace`/`class`, the way Composer does.
$classmap = [];
foreach ($classmapDirs as $d) {
    foreach (glob(rtrim("$root/$d", '/') . '/*.php') as $f) {
        $src = file_get_contents($f);
        $ns = preg_match('/namespace\s+([^;]+);/', $src, $m) ? trim($m[1]) . '\\' : '';
        if (preg_match_all('/(?:final\s+)?(?:abstract\s+)?class\s+(\w+)/', $src, $cm)) {
            foreach ($cm[1] as $c) { $classmap[$ns . $c] = $f; }
        }
    }
}

spl_autoload_register(function ($class) use ($root, $psr4, $classmap) {
    if (isset($classmap[$class])) { require $classmap[$class]; return; }
    foreach ($psr4 as $prefix => $dir) {
        if (strpos($class, $prefix) === 0) {
            $rel = str_replace('\\', '/', substr($class, strlen($prefix)));
            $file = rtrim("$root/$dir", '/') . "/$rel.php";
            if (is_file($file)) { require $file; return; }
        }
    }
});

$pass = 0; $fail = 0;
function ok($n, $c) { global $pass, $fail; if ($c) { $pass++; echo "PASS  $n\n"; } else { $fail++; echo "FAIL  $n\n"; } }

ok('PSR-4: XmrPay\\Util autoloads', class_exists('XmrPay\\Util'));
ok('PSR-4: XmrPay\\NodeConfig autoloads', class_exists('XmrPay\\NodeConfig'));
ok('PSR-4: XmrPay\\Scanner autoloads', class_exists('XmrPay\\Scanner'));
ok('classmap: MoneroIntegrations\\MoneroPhp\\Cryptonote autoloads', class_exists('MoneroIntegrations\\MoneroPhp\\Cryptonote'));
ok('classmap: MoneroIntegrations\\MoneroPhp\\base58 autoloads', class_exists('MoneroIntegrations\\MoneroPhp\\base58'));
ok('classmap: kornrunner\\Keccak autoloads', class_exists('kornrunner\\Keccak'));
// instantiate the engine through real autoload (Scanner news up Cryptonote via classmap)
$s = new XmrPay\Scanner('http://node.example:38089', 'stagenet', 5);
ok('Scanner instantiates via autoload (no manual require)', $s instanceof XmrPay\Scanner);
ok('Util money math works via autoload', (string) XmrPay\Util::xmr_to_pico('0.1') === '100000000000');

echo "\n" . ($fail ? 'FAILED' : 'ALL GREEN') . "  $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
