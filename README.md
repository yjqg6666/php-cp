## redis and pdo connect pool, just for PHP

provied php connect pool like java


## Requirement

- PHP 5.3 +
- linux 2.6+
- pdo and redis extension

## Install

phpize=>./configure=>make install=>echo "extensions=xx/connect_pool.so">php.ini


## 技术特性

1.在model框架里面做集成，每次fetchAll（set/get）后执行release方法，释放所占用的连接，防止因为脚本卡住导致的连接占用过高问题。
2.支持最大最小连接数配置。
3.支持压力小自动回收连接（可配置）。
4.支持平滑重启。
5.减少php短连接对db层的压力。
6.做了大量优化，虽然请求经过连接池进程转发，但是基本无qps损耗。

## Example
step 1 move the pool.ini file to /etc/ and modify it as you need.

step 2 start the pool_server process：
./pool_server start
support "start" "stop" "restart" "reload"

step 3 modify you php script:
<?php
$db = new PDO(xxxxx);
=> $db = new pdo_connect_pool(xxxx);

$redis = new Redis();
=》$redis = new redis_connect_pool();

tips:use $db($redis)->release() to release the connection  as early as you can;
?>
