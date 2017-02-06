--TEST--
Testing php-cp mysql basic-update

--SKIPIF--
<?php
require(dirname(__DIR__) . DIRECTORY_SEPARATOR . "environment.php");
?>

--FILE--
<?php
try {
    $db = new pdoProxy('mysql:dbname=test;host=127.0.0.1;port=3306;charset=utf8', "root", "password");
    $now = time();
    $new_email = "email_updated_at_{$now}@example.com";
    $sql = 'UPDATE `test_user` SET `email`=:email WHERE `user_id`=:user_id';
    $stmt = $db->prepare($sql);
    $user_id = 1;
    $stmt->bindValue(":email", $new_email, PDO::PARAM_STR);
    $stmt->bindValue(":user_id", $user_id, PDO::PARAM_INT);
    $exec_result = $stmt->execute();
    $affected_rows = null;
    if ($exec_result) {
        $affected_rows = $stmt->rowCount();
    }

    $sql_select = "SELECT `email` FROM `test_user` WHERE `user_id`=\"${user_id}\" LIMIT 0,1";
    $result = $db->query($sql_select)->fetch(PDO::FETCH_ASSOC);
    $result_check = is_array($result) && isset($result["email"]) && $result["email"] == $new_email;
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

