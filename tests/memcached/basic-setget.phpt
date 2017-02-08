--TEST--
Testing php-cp memcached set&get

--SKIPIF--
<?php
if (PHP_MAJOR_VERSION == 7) {
    exit("Skip this test, php7 will timeout");
}
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
if (extension_loaded("memcached") === false) {
    exit("Skip this test, memcached extension NOT loaded");
}
?>

--FILE--
<?php
try {
    $now = time();
    $key = "time_stamp";
    $db = new memcachedProxy();
    $db->setOption(Memcached::OPT_PREFIX_KEY, "phpcp_");
    if (!count($db->getServerList())) {
        $db->addServers(array(
            array('localhost',11211)
        ));
    }
    $result_set = $db->set($key, $now);
    $stored = $db->get($key);
    //$db->release();
    var_dump($result_set !== false);
    var_dump($stored == $now);
    var_dump($stored);
} catch (\Exception $e) {
    var_dump($e);
}
?>

--EXPECTF--
bool(true)
bool(true)
int(%d)
