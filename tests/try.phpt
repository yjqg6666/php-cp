--TEST--
Testing php-cp platform

--SKIPIF--
<?php
require(__DIR__ . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
$s = '123';
var_dump(time());
?>

--EXPECTF--
int(%d)

--CLEAN--
<?php
?>

