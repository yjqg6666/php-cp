--TEST--
Testing php-cp mysql delete

--SKIPIF--
<?php
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try {
    $db = new pdoProxy('mysql:dbname=test;host=127.0.0.1;port=3306;charset=utf8', "root", "password");
    $sql = 'DELETE FROM `test_user` WHERE `user_id`= :user_id';
    $stmt = $db->prepare($sql);
    $user_id = 3;
    $stmt->bindValue(":user_id", $user_id, PDO::PARAM_INT);
    $exec_result = $stmt->execute();
    $affected_rows = null;
    if ($exec_result) {
        $affected_rows = $stmt->rowCount();
    }

    $sql_select = "SELECT `user_id` FROM `test_user` WHERE `user_id`=\"${user_id}\" LIMIT 0,1";
    $result = $db->query($sql_select)->fetchAll(PDO::FETCH_ASSOC);
    $result_check = is_array($result) && count($result) === 0;
    $db->release();
    var_dump($exec_result);
    var_dump($affected_rows);
    var_dump($result_check);
} catch (\Exception $e) {
    var_dump($e);
}
?>
--EXPECTF--
bool(true)
int(1)
bool(true)

--CLEAN--
<?php
?>

