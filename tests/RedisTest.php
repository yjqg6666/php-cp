<?php

defined("PHPCP_TESTRUN") or die("使用 RunTest.php 运行测试!");

require_once(dirname($_SERVER["PHP_SELF"])."/TestSuite.php");

class RedisTest extends TestSuite {
    public $redis;

    public function setup()
    {
        $this->redis = new redisProxy();
        $this->redis->connect($this->getHost());
        $this->redis->select(5);
    }

    public function test_class_exists()
    {
        $this->assertTrue(class_exists("redisProxy"));
    }

    public function test_set_get()
    {
        $this->redis->set("phpcp", "hello world");
        $this->assertEquals("hello world", $this->redis->get("phpcp"));
    }
}

?>
