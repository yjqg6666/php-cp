--TEST--
Testing php-cp mysql show tables

--SKIPIF--
<?php
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try{
    $db = new pdoProxy('mysql:dbname=test;host=127.0.0.1;port=3306;charset=utf8', "root", "password");
    $tables = $db->query("SHOW TABLES")->fetchAll(PDO::FETCH_ASSOC);
    $db->release();
    var_dump((bool) $tables);
} catch (\Exception $e) {
    var_dump($e);
}
?>
--EXPECT--
bool(true)

--CLEAN--
<?php
?>

