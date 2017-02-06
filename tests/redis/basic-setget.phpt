--TEST--
Testing php-cp platform

--SKIPIF--
<?php
require(__DIR__ . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try {
    $now = time();
    $key = "time_stamp";
    $db = new redisProxy();
    $db->connect("127.0.0.1");
    $db->select(1);
    $db->set($key, $now);
    $stored = $db->get($key);
    $db->release();
    var_dump($stored === $now);
} catch (\Exception $e) {
    var_dump($e);
}
?>

--EXPECTF--
bool(true)

--CLEAN--
<?php
?>

