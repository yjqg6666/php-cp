<?php

$redis_host = "172.17.0.2";


/**
 * 使用普通的连接方式
 */
$obj = new Redis();
$rs = $obj->connect($redis_host);
$obj->select(5);
$obj->set("test", '1111');
var_dump($obj->get("test"));

/**
 * 使用连接池
 */
$obj = new redisProxy();
$rs = $obj->connect($redis_host);
$obj->select(5);
$obj->set("test", '1111');
var_dump($obj->get("test"));
$obj->release();
