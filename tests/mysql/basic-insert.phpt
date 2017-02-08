--TEST--
Testing php-cp mysql insert

--SKIPIF--
<?php
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try {
    $db = new pdoProxy('mysql:dbname=test;host=127.0.0.1;port=3306;charset=utf8', "root", "password");
    $sql = 'INSERT INTO `test_user` SET `nickname`= :nickname,`email`= :email,`register_datetime`= :reg_datetime';
    $stmt = $db->prepare($sql);
    $seq = time();
    $nickname = "user_reg_time_${seq}";
    $stmt->bindValue(":nickname", $nickname, PDO::PARAM_STR);
    $stmt->bindValue(":email", "user_reg_time_${seq}@example.com", PDO::PARAM_STR);
    $stmt->bindValue(":reg_datetime", date("Y-m-d H:i:s"), PDO::PARAM_STR);
    $exec_result = $stmt->execute();
    $insert_id = $affected_rows = null;
    if ($exec_result) {
        $insert_id = $db->lastInsertId();
        $affected_rows = $stmt->rowCount();
    }

    $sql_select = "SELECT `user_id` FROM `test_user` WHERE `nickname`=\"${nickname}\" LIMIT 0,1";
    $result = $db->query($sql_select)->fetchAll(PDO::FETCH_ASSOC);
    $result_check = isset($result[0]) && is_array($result[0]) && $result[0]["user_id"] == $insert_id;
    $db->release();
    var_dump($exec_result);
    var_dump($result_check);
    var_dump($insert_id);
    var_dump($affected_rows);
} catch (\Exception $e) {
    var_dump($e);
}
?>
--EXPECTF--
bool(true)
bool(true)
string(%d) "%d"
int(1)

--CLEAN--
<?php
?>

