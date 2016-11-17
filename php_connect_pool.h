/*
  +----------------------------------------------------------------------+
  | common con pool                                                      |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Xinhua Guo  <woshiguo35@sina.com>                            |
  +----------------------------------------------------------------------+
 */

/* $Id$ */

#ifndef PHP_CON_PROXY_H
#define PHP_CON_PROXY_H

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//#ifdef HAVE_EPOLL
#include <sys/epoll.h> //todo
#ifndef EPOLLRDHUP
#define EPOLLRDHUP   0x2000
#define NO_EPOLLRDHUP
#endif
//#endif

#if defined(__GNUC__)
#if __GNUC__ >= 3
#define CPINLINE inline __attribute__((always_inline))
#else
#define CPINLINE inline
#endif
#elif defined(_MSC_VER)
#define CPINLINE __forceinline
#else
#define CPINLINE inline
#endif


#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#include <sys/poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "cpConfig.h"
#include <ext/standard/php_string.h>
#include "include/php7_wrapper.h"
#include "cpMemory.h"
#include "cpFunction.h"
#include "cpWorker.h"
#include "cpServer.h"
#include "cpNetWork.h"
#include "cpClientNet.h"
#include "cpPingWorker.h"

#include <ext/pdo/php_pdo_driver.h>
#include <ext/standard/php_var.h>
#include <zend_exceptions.h>
#if PHP_MAJOR_VERSION < 7
#include "msgpack/php_msgpack.h"
#else
#include "msgpack7/php_msgpack.h"
#endif
#ifdef ZTS
#include "TSRM.h"
#endif

/**
 * PHP5.2
 */
#ifndef PHP_FE_END
#define PHP_FE_END {NULL,NULL,NULL}
#endif

#ifndef ZEND_MOD_END
#define ZEND_MOD_END {NULL,NULL,NULL}
#endif

#define CP_HOST_SIZE  128


extern zend_module_entry connect_pool_module_entry;
#define phpext_connect_pool_ptr &connect_pool_module_entry

#ifdef PHP_WIN32
#define PHP_CONNECT_POOL_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#define PHP_CONNECT_POOL_API __attribute__ ((visibility("default")))
#else
#define PHP_CONNECT_POOL_API
#endif

typedef struct _cpRecvEvent {
    zval *ret_value;
    uint8_t type;
} cpRecvEvent;


//#define CP_GROUP_LEN 1000 //
//#define CP_GROUP_NUM 100 //the max group num of proxy process . todo  check it

extern int le_cli_connect_pool;

extern zend_class_entry *redis_connect_pool_class_entry_ptr;
extern zend_class_entry *pdo_connect_pool_class_entry_ptr;
extern zend_class_entry *pdo_connect_pool_PDOStatement_class_entry_ptr;

PHP_MINIT_FUNCTION(connect_pool);
PHP_MSHUTDOWN_FUNCTION(connect_pool);
PHP_RINIT_FUNCTION(connect_pool);
PHP_RSHUTDOWN_FUNCTION(connect_pool);
PHP_MINFO_FUNCTION(connect_pool);

PHP_FUNCTION(pool_server_create);
PHP_FUNCTION(pool_server_shutdown);
PHP_FUNCTION(pool_server_reload);
PHP_FUNCTION(pool_server_version);




PHP_METHOD(pdo_connect_pool, __construct);
PHP_METHOD(pdo_connect_pool, __destruct);
PHP_METHOD(pdo_connect_pool, __call);
PHP_METHOD(pdo_connect_pool, release);
PHP_METHOD(pdo_connect_pool, msConfig);
PHP_METHOD(pdo_connect_pool, forceMaster);
PHP_METHOD(pdo_connect_pool, close);
PHP_METHOD(pdo_connect_pool, setAsync);
PHP_METHOD(pdo_connect_pool, done);

PHP_METHOD(pdo_connect_pool_PDOStatement, __call);
PHP_METHOD(pdo_connect_pool_PDOStatement, setAsync);
PHP_METHOD(pdo_connect_pool_PDOStatement, release);
PHP_METHOD(pdo_connect_pool_PDOStatement, done);
PHP_METHOD(pdo_connect_pool_PDOStatement, rewind);
PHP_METHOD(pdo_connect_pool_PDOStatement, next);
PHP_METHOD(pdo_connect_pool_PDOStatement, current);
PHP_METHOD(pdo_connect_pool_PDOStatement, key);
PHP_METHOD(pdo_connect_pool_PDOStatement, valid);

PHP_METHOD(redis_connect_pool, __construct);
PHP_METHOD(redis_connect_pool, __destruct);
PHP_METHOD(redis_connect_pool, __call);
PHP_METHOD(redis_connect_pool, release);
PHP_METHOD(redis_connect_pool, select);
PHP_METHOD(redis_connect_pool, connect);
PHP_METHOD(redis_connect_pool, done);
PHP_METHOD(redis_connect_pool, close);
PHP_METHOD(redis_connect_pool, setAsync);


void send_oob2proxy(zend_resource *rsrc TSRMLS_DC);
extern void cp_serialize(smart_str *ser_data, zval *array);
extern zval * cp_unserialize(char *data, int len);
extern int redis_proxy_connect(zval *args, int flag);
extern int pdo_proxy_connect(zval *args, int flag);

int worker_onReceive(zval *data);
int CP_INTERNAL_SERIALIZE_SEND_MEM(zval *ret_value, uint8_t __type);
int CP_CLIENT_SERIALIZE_SEND_MEM(zval *ret_value, cpClient *, cpWorkerInfo*);
extern cpServerG ConProxyG;
extern cpServerGS *ConProxyGS;
extern cpWorkerG ConProxyWG;
extern FILE *cp_log_fn;

#endif	/* PHP_CON_PROXY_H */
