--TEST--
Testing php-cp memcached set&get

--SKIPIF--
<?php
require(__DIR__ . DIRECTORY_SEPARATOR . "environment.php");
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
    //$db->setOption(Memcached::OPT_LIBKETAMA_COMPATIBLE, true);
    $db->setOption(Memcached::OPT_RECV_TIMEOUT, 1000);
    $db->setOption(Memcached::OPT_SEND_TIMEOUT, 3000);
    $db->setOption(Memcached::OPT_TCP_NODELAY, true);
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
string(%d) "%d"

--CLEAN--
<?php
?>

