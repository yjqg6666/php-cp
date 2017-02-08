--TEST--
Testing php-cp redis set&get

--SKIPIF--
<?php
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try {
    $now = time();
    $key = "time_stamp";
    $db = new redisProxy();
    $db->connect("localhost");
    $db->select(1);
    $db->set($key, $now);
    $stored = $db->get($key);
    $db->release();
    var_dump($stored == $now);
    var_dump($stored);
} catch (\Exception $e) {
    var_dump($e);
}
?>

--EXPECTF--
bool(true)
string(%d) "%d"

--CLEAN--
<?php
?>

