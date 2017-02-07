<?php
$php_test_exit = function($code, $msg) {
    echo $msg . PHP_EOL;
    exit($code);
};

if (!stristr(PHP_OS, "Linux")) {
    $php_test_exit(1, "Skip this test, Linux platforms only");
}
if (extension_loaded("connect_pool") === false) {
    $php_test_exit(2, "Skip this test, connection pool extension NOT loaded");
}
if (extension_loaded("redis") === false) {
    $php_test_exit(2, "Skip this test, redis extension NOT loaded");
}
