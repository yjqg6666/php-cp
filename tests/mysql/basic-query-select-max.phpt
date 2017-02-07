--TEST--
Testing php-cp mysql query select max

--SKIPIF--
<?php
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try {
    $db = new pdoProxy('mysql:dbname=test;host=127.0.0.1;port=3306;charset=utf8', "root", "password");
    $sql = 'SELECT MAX(`street`) as max_street FROM `test_post_address` WHERE `user_id`=1 ORDER BY `pa_id` ASC LIMIT 0,1';
    $result = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    $result_check = isset($result[0]) && is_array($result[0]) && $result[0]["max_street"] == "30120";
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

