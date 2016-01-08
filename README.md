## php-cp(php-connect-pool),redis and pdo sync connect pool
[中文简介] http://blog.sina.com.cn/s/blog_9eaa0f400102v9fd.html

Provide local connection pool like java

## Requirement

- PHP 5.3 + (no zts)
- linux 2.6+
- pdo and redis extension install

## Install

phpize=>./configure=>make install=>echo "extensions=xx/connect_pool.so">php.ini


##Technical characteristics:

- After each time fetchAll (set/get)  call release() method, release the connection to the pool, avoid that the script jammed causing connection occupy high problem.
- The maximum and minimum number of connections configuration support.
- Support  small pressure automatic recovery connection.
- Support graceful restart (reload).
- Do a lot of optimization, although the request through the connection pool process forward, but no loss of QPS.
- When the connection use out,support queue.
- Simple! just change the new method and add release function (see demon),you used the tcp pool.
- The connection proxy will start the ping process to monitor down list, if available will reflect to the return value of the get_disable_list(), use this function you can do some fun things,like LB.
- support Read / write separate and slave load balancing

## Example
step 1 move the pool.ini file to /etc/ and modify it as you need.

step 2 start the pool_server process：
```./pool_server start
```support "start" "stop" "restart" "reload"

step 3 modify you php script:
```
<?php
$db = new PDO(xxxxx);
=> $db = new pdo_connect_pool(xxxx);//dont use persistent

$redis = new Redis();
=》$redis = new redis_connect_pool();//dont use pconnect

tips:use $db/$redis->release() to release the connection  as early as you can;


//*******************use master slave(最新版本支持了读写分离和从库的负载均衡 用法如下)***********************/
$config = array(
    'master' => array(
        'data_source' => "mysql:host=192.168.1.19;dbname=db1",
        'username' => "public_user",
        'pwd' => "1qa2ws3ed",
        'options' => array(
            PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => 3,
            PDO::ATTR_CASE =>PDO::CASE_UPPER,
        ),
    ),
    'slave' => array(
        "0" => array(
            'data_source' => "mysql:host=192.168.1.20;dbname=db2",
            'username' => "public_user",
            'pwd' => "1qa2ws3ed",
            'options' => array(
                PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 3,
                PDO::ATTR_CASE =>PDO::CASE_UPPER,
            ),
        ),
        "1" => array(
            'data_source' => "mysql:host=192.168.1.21;dbname=db3",
            'username' => "public_user",
            'pwd' => "1qa2ws3ed",
            'options' => array(
                PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 3,
                PDO::ATTR_CASE =>PDO::CASE_LOWER,
            ),
        ),
    ),
);
/***************************"select"和"show"开头的语句 走随机从库***********/
$obj1 = new pdo_connect_pool($config);
$rs = $obj1->query("select * from test limit 1");
var_dump($rs->fetchAll());//走随机从库
$obj1->release();

/****************************读强行走主库****************************/
$obj1->enable_slave = false;
$rs = $obj1->query("select * from test limit 1");
var_dump($rs->fetchAll());//读主库
$obj1->release();

/***************************除了"select"和"show"开头的语句 都走主库***********/
$sql = "insert into `test` (tid) values (5)";
$rs = $obj1->exec($sql);//走主库
$obj1->release();

?>
```

## 提示
- pool_server 必须以root用户启动
- redis不支持pub/sub方法

## contact us
- http://weibo.com/u/2661945152
- 83212019@qq.com
