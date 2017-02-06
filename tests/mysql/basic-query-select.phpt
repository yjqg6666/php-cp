--TEST--
Testing php-cp mysql select

--SKIPIF--
<?php
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try {
    $db = new pdoProxy('mysql:dbname=test;host=127.0.0.1;port=3306;charset=utf8', "root", "password");
    $sql = 'SELECT `user_id`,`nickname` FROM `test_user` WHERE `email`="user2@example.com"';
    $result = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    $result_check = isset($result[0]) && is_array($result[0]) && $result[0]["user_id"] == 2
        && $result[0]["nickname"] == "user2";
    $db->release();
    var_dump($result_check);
} catch (\Exception $e) {
    var_dump($e);
}
?>
--EXPECT--
bool(true)

--CLEAN--
<?php
?>

