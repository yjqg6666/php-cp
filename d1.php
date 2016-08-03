<?php
$pid = getmypid(); echo "$pid\n";
$obj1 = new pdoProxy('mysql:host=192.168.1.19;dbname=mz_gay_group2;charset=utf8', "public_user", "1qa2ws3ed");
// sleep(50);
$rs = $obj1->query("select * from test limit 2");
//var_dump($rs);// die;
var_dump($rs->fetchAll());
$obj1->release();
die;

/* tips：
 * 1、The relase() method will release the connections to the pool that the process holds.
 * 2、after rshutdown/mshutdown will trigger the release() function.
 */


/* 说明：
 * 1、relase方法：通知中间件,可以将这个进程持有的链接放回连接池
 * 2、请求结束（rshutdown/mshutdown阶段）会调用自动调用release
 */
