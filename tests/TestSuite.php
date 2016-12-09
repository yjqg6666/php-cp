<?php

defined("PHPCP_TESTRUN") or die("使用 RunTest.php 运行测试!");

class TestSuite {
    private $host;

    private static $colorize = false;

    private static $BOLD_ON = "\033[1m";
    private static $BOLD_OFF = "\033[0m";
    private static $BLACK = "\033[0;30m";
    private static $DARKGRAY = "\033[1;30m";
    private static $BLUE = "\033[0;34m";
    private static $PURPLE = "\033[0;35m";
    private static $GREEN = "\033[0;32m";
    private static $YELLOW = "\033[0;33m";
    private static $RED = "\033[0;31m";

    public static $errors = array();
    public static $warnings = array();

    public function __construct($host) {
        $this->host = $host;
    }

    public function getHost() {
        return $this->host;
    }

    public static function make_bold($msg) {
        return self::$colorize
            ? self::$BOLD_ON . $msg . self::$BOLD_OFF
            : $msg;
    }

    public static function make_success($str) {
        return self::$colorize
            ? self::$GREEN . $str . self::$BOLD_OFF
            : $str;
    }

    public static function make_fail($str) {
        return self::$colorize
            ? self::$RED . $str . self::$BOLD_OFF
            : $str;
    }

    public static function make_warning($str) {
        return self::$colorize
            ? self::$YELLOW . $str . self::$BOLD_OFF
            : $str;
    }

    protected function assertFalse($bool) {
        $this->assertTrue(!$bool);
    }

    protected function assertTrue($bool)
    {
        if ($bool) {
            return;
        }

        $bt = debug_backtrace(false);
        self::$errors[] = sprintf("断言失败: %s:%d (%s)\n",
            $bt[0]["file"], $bt[0]["line"], $bt[1]["function"]);
    }

    protected function assertLess($a, $b) {
        if($a < $b)
            return;
        $bt = debug_backtrace(false);
        self::$errors[] = sprintf("断言失败 (%s >= %s): %s: %d (%s\n",
            print_r($a, true), print_r($b, true),
            $bt[0]["file"], $bt[0]["line"], $bt[1]["function"]);
    }

    protected function assertEquals($a, $b) {
        if($a === $b)
            return;
        $bt = debug_backtrace(false);
        self::$errors []= sprintf("断言失败 (%s !== %s): %s:%d (%s)\n",
            print_r($a, true), print_r($b, true),
            $bt[0]["file"], $bt[0]["line"], $bt[1]["function"]);
    }

    protected function markTestSkipped($msg="") {
        $bt = debug_backtrace(false);
        self::$warnings []= sprintf("跳过测试: %s:%d (%s) %s\n",
            $bt[0]["file"], $bt[0]["line"], $bt[1]["function"], $msg);
        throw new Exception($msg);
    }

    private static function getMaxTestLen($methods, $limit) {
        $rv = 0;
        $limit = strtolower($limit);
        foreach ($methods as $method) {
            $name = strtolower($method->name);
            if (substr($name, 0, 4) != "test")
                continue;
            if ($limit && !strstr($name, $limit))
                continue;
            if (strlen($name) > $rv) {
                $rv = strlen($name);
            }
        }
        return $rv;
    }

    /* Flag colorization */
    public static function flagColorization($override) {
        self::$colorize = $override && function_exists("posix_isatty") &&
            posix_isatty(STDOUT);
    }

    public static function run($className, $limit = NULL, $host = NULL) {
        $limit = $limit ? strtolower($limit) : $limit;

        $rc = new ReflectionClass($className);
        $methods = $rc->getMethods(ReflectionMethod::IS_PUBLIC);
        $max_len = self::getMaxTestLen($methods, $limit);

        foreach ($methods as $method) {
            $name = $method->name;

            if (substr($name, 0, 4) !== "test") {
                continue;
            }

            if ($limit && strstr(strtolower($name), $limit) === false) {
                continue;
            }

            $out_name = str_pad($name, $max_len + 1);
            echo self::make_bold($out_name);

            $count = count($className::$errors);
            $rt = new $className($host);

            try {
                $rt->setup();
                $rt->$name();

                if ($count === count($className::$errors)) {
                    $msg = self::make_success("成功");
                } else {
                    $msg = self::make_fail("失败");
                }
            } catch (Exception $e) {
                $className::$errors[] = "Uncaught exception '".$e->getMessage()."' ($name)\n";
                $msg = self::make_fail("失败");
            }

            echo "[" . $msg . "]\n";
        }

        echo implode("", $className::$warnings) . "\n";

        if (empty($className::$errors)) {
            $msg = self::make_success("通过所有测试");
            echo $msg . "\n\n";
            return 0;
        }

        echo implode("", $className::$errors) . "\n";
        return 1;
    }
}

?>
