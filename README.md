## redis and pdo sync connect pool, just for PHP

Provide local connection pool like java


## Requirement

- PHP 5.3 +(no zts 编译php时不要加 --enable-maintainer-zts)
- linux 2.6+
- pdo and redis extension install

## Install

phpize=>./configure=>make install=>echo "extensions=xx/connect_pool.so">php.ini


## 解决的问题

- 1.php的短链接对mysql和redis造成了大量的资源消耗。
- 2.想象一个这样的业务：请求过来连了一次redis，又去连了mysql，之后去调用其他的rpc请求，而某种原因导致请求非常慢，那么之前的tcp连接就会一直占用。
- 3.现有开源产品（Atlas,TDDL等）需要单独部署集群，在架构上引入了外部依赖，经过中间网络转发效率变低，没法同时支持redis和pdo。


## 技术特性

- 1.在model框架里面做集成，每次fetchAll（set/get）后执行release方法，释放所占用的连接，防止因为脚本卡住导致的连接占用过高问题。
- 2.支持最大最小连接数配置。
- 3.支持压力小自动回收连接（可配置）。
- 4.支持平滑重启。
- 5.减少php短连接对db层的压力。
- 6.做了大量优化，虽然请求经过连接池进程转发，但是基本无qps损耗。
- 7.支持连接用光的排队机制。
- 8.框架简单整合后（修改new 方法），现有业务一行代码都不用改即可用上连接池。
- 9.提供了get_disable_list函数，来获得不可用的宕机ip列表，这样负载均衡也可以做在客户端避免lvs转发。
-10.连接池进程会启动ping进程来监听宕机列表，如果可用会反映到get_disable_list函数的返回值上。

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

tips:use $db($redis)->release() to release the connection  as early as you can;
?>
```
##API
get_disable_list($config,CP_DEFAULT_PDO_PORT);
get_disable_list($config,CP_DEFAULT_REDIS_PORT);

$config is you ip list;
this function will return the fail ips;

## contact me
http://weibo.com/u/2661945152