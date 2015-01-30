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
?>
```
##API
get_disable_list($pdo_config,CP_DEFAULT_PDO_PORT);// get the pdo disable ips;
get_disable_list($redis_conf,CP_DEFAULT_REDIS_PORT); // get the redis disable ips;

- first param is you ip list.
- if the first param changed,the disable list will be clear.
- this function will return the fail ips.

## contact me
http://weibo.com/u/2661945152
http://weibo.com/u/2661945152 test commit
