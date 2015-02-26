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

#include "php_connect_pool.h"
#include <ext/standard/info.h>
#include "zend_interfaces.h"
#include <ext/standard/php_string.h>
#include <sys/time.h>

static HashTable pdo_object_table;
static HashTable redis_object_table;
static zval* pdo_stmt = NULL;

cpServerG ConProxyG;
cpServerGS *ConProxyGS;
cpWorkerG ConProxyWG;

extern sapi_module_struct sapi_module;

static void cp_destory_client(zend_rsrc_list_entry *rsrc TSRMLS_DC);

static void pdo_dispatch(zval *args);
static void pdo_proxy_pdo(zval *args);
static void pdo_proxy_stmt(zval *args);
static void cp_add_fail_into_mem(zval *conf, zval *data_source);

#define CP_VERSION "1.1"

#define CP_INTERNAL_ERROR_SEND(send_data)\
                                ({         \
                                zval send_zval;\
                                ZVAL_STRING(&send_zval,send_data,0);\
                                CP_INTERNAL_SERIALIZE_SEND_MEM(&send_zval,CP_SIGEVENT_EXCEPTION);\
                                 })

#define CP_INTERNAL_NORMAL_SEND(send_data)\
                                ({         \
                                zval send_zval;\
                                ZVAL_STRING(&send_zval,send_data,0);\
                                CP_INTERNAL_SERIALIZE_SEND_MEM(&send_zval,CP_SIGEVENT_TURE);\
                                 })

#define CP_SEND_EXCEPTION_ARGS(str) do{   zval *exception = EG(exception);\
                                zend_class_entry *ce_exception = Z_OBJCE_P(exception);\
                                EG(exception) = NULL;\
                                zend_call_method_with_0_params(&exception, ce_exception, NULL, "__tostring", str);\
                                CP_INTERNAL_SERIALIZE_SEND_MEM(*str,CP_SIGEVENT_EXCEPTION);\
                                zval_ptr_dtor(&exception);\
                        }while(0);

#define CP_TEST_RETURN_FALSE(flag) ({if(flag==CP_CONNECT_PING){ \
                                          if(EG(exception)){ \
                                              zval *exception = EG(exception);\
                                              zval_ptr_dtor(&exception); \
                                              EG(exception) = NULL;\
                                           }\
                                          return CP_FALSE; \
                                      }});

#define CP_SEND_EXCEPTION do{zval *str;CP_SEND_EXCEPTION_ARGS(&str);zval_ptr_dtor(&str);}while(0);
#define CP_INTERNAL_NORMAL_SEND_RETURN(send_data)({CP_INTERNAL_NORMAL_SEND(send_data);return CP_TRUE;})
#define CP_INTERNAL_ERROR_SEND_RETURN(send_data) ({ CP_INTERNAL_ERROR_SEND(send_data);return CP_FALSE;})
#define CP_SEND_EXCEPTION_RETURN do{CP_SEND_EXCEPTION;return CP_FALSE;}while(0);
#define CP_TEST_RETURN_TRUE(flag) ({if(flag==CP_CONNECT_PING)return CP_TRUE;})

#include "zend_exceptions.h"

const zend_function_entry cp_functions[] = {
    PHP_FE(pool_server_create, NULL)
    PHP_FE(pool_server_shutdown, NULL)
    PHP_FE(pool_server_reload, NULL)
    PHP_FE(pool_server_version, NULL)
    PHP_FE(get_disable_list, NULL)
    PHP_FE(pdo_warning_function_handler, NULL)
    PHP_FE(client_close, NULL)
    PHP_FE_END /* Must be the last line in cp_functions[] */
};

ZEND_BEGIN_ARG_INFO_EX(__call_args, 0, 0, 2)
ZEND_ARG_INFO(0, function_name)
ZEND_ARG_INFO(0, arguments)
ZEND_END_ARG_INFO()

const zend_function_entry pdo_connect_pool_methods[] = {
    PHP_ME(pdo_connect_pool, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(pdo_connect_pool, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(pdo_connect_pool, __call, __call_args, ZEND_ACC_PUBLIC)
    //    PHP_ME(pdo_connect_pool, quote, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(pdo_connect_pool, release, NULL, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry pdo_connect_pool_PDOStatement_methods[] = {
    PHP_ME(pdo_connect_pool_PDOStatement, __call, __call_args, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

const zend_function_entry redis_connect_pool_methods[] = {
    PHP_ME(redis_connect_pool, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(redis_connect_pool, __destruct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(redis_connect_pool, __call, __call_args, ZEND_ACC_PUBLIC)
    PHP_ME(redis_connect_pool, release, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(redis_connect_pool, select, NULL, ZEND_ACC_PUBLIC)
    PHP_ME(redis_connect_pool, connect, NULL, ZEND_ACC_PUBLIC)
    PHP_MALIAS(redis_connect_pool, pconnect, connect, NULL, ZEND_ACC_PUBLIC) /* pconnect 别名指向connect */
    PHP_FE_END
};


int le_cp_server;
int le_cli_connect_pool;

zend_class_entry pdo_connect_pool_ce;
zend_class_entry *pdo_connect_pool_class_entry_ptr;

zend_class_entry redis_connect_pool_ce;
zend_class_entry *redis_connect_pool_class_entry_ptr;

zend_class_entry pdo_connect_pool_PDOStatement_ce;
zend_class_entry *pdo_connect_pool_PDOStatement_class_entry_ptr;

zend_module_entry connect_pool_module_entry = {
#if ZEND_MODULE_API_NO >= 20050922
    STANDARD_MODULE_HEADER_EX,
    NULL,
    NULL,
#else
    STANDARD_MODULE_HEADER,
#endif
    "connect_pool",
    cp_functions,
    PHP_MINIT(connect_pool),
    PHP_MSHUTDOWN(connect_pool),
    PHP_RINIT(connect_pool), //RINIT
    PHP_RSHUTDOWN(connect_pool), //RSHUTDOWN
    PHP_MINFO(connect_pool),
    CP_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_CONNECT_POOL

ZEND_GET_MODULE(connect_pool)
#endif

PHP_MINIT_FUNCTION(connect_pool)
{

    le_cli_connect_pool = zend_register_list_destructors_ex(send_oob2proxy, cp_destory_client, CP_RES_CLIENT_NAME, module_number); //持久

    INIT_CLASS_ENTRY(pdo_connect_pool_ce, "pdo_connect_pool", pdo_connect_pool_methods);
    pdo_connect_pool_class_entry_ptr = zend_register_internal_class(&pdo_connect_pool_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(redis_connect_pool_ce, "redis_connect_pool", redis_connect_pool_methods);
    redis_connect_pool_class_entry_ptr = zend_register_internal_class(&redis_connect_pool_ce TSRMLS_CC);

    INIT_CLASS_ENTRY(pdo_connect_pool_PDOStatement_ce, "pdo_connect_pool_PDOStatement", pdo_connect_pool_PDOStatement_methods);
    pdo_connect_pool_PDOStatement_class_entry_ptr = zend_register_internal_class(&pdo_connect_pool_PDOStatement_ce TSRMLS_CC);

    zend_hash_init(&pdo_object_table, 50, NULL, ZVAL_PTR_DTOR, 1);
    zend_hash_init(&redis_object_table, 50, NULL, ZVAL_PTR_DTOR, 1);

    REGISTER_LONG_CONSTANT("CP_DEFAULT_PDO_PORT", CP_PORT_PDO, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("CP_DEFAULT_REDIS_PORT", CP_PORT_REDIS, CONST_CS | CONST_PERSISTENT);

    bzero(&ConProxyG, sizeof (ConProxyG));
    bzero(&ConProxyWG, sizeof (ConProxyWG));

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(connect_pool)
{
    if (pdo_stmt) {
        zval_ptr_dtor(&pdo_stmt);
    }
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(connect_pool)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "connect_poll support", "enabled");
    php_info_print_table_row(2, "Version", CP_VERSION);
    php_info_print_table_row(2, "Author", "郭新华");
    php_info_print_table_row(2, "email", "woshiguo35@sina.com");
    php_info_print_table_end();
}

/* }}} */

PHP_RINIT_FUNCTION(connect_pool)
{
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(connect_pool)
{
    return SUCCESS;
}

static void cp_destory_client(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
    cpClient *cli = (cpClient *) rsrc->ptr;
    if (cli->sock > 0) {
        cpClient_close(cli);
        //        pefree(cli, 1); //长连接
    }
}

void send_oob2proxy(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
    cpClient *cli = (cpClient *) rsrc->ptr;
    if (cli->sock == 0) {
        pefree(cli, 1); //长连接
    } else if (cli->released == CP_FD_NRELEASED) {//防止release后rshutdown的重复释放
        //        ret = cpClient_send(cli->sock, CP_RELEASE_HEADER, CP_RELEASE_HEADER_LEN, MSG_OOB);
        cpTcpEvent event;
        event.type = CP_TCPEVENT_RELEASE;
        event.ClientPid = 0;
        int ret = cpClient_send(cli->sock, (char *) &event, sizeof (event), 0);
        if (ret >= 0) {
            cli->released = CP_FD_RELEASED;
        } else {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "pdo_connect_pool: release error. Error: %s [%d]", strerror(errno), errno);
        }
    }
}

PHP_FUNCTION(pdo_warning_function_handler)
{
    long errorno;
    char *errstr;
    int errlen;
    char * linstr;
    int linlen;
    char * filestr;
    int filelen;
    zval *what;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lsss|z", &errorno, &errstr, &errlen, &filestr, &filelen, &linstr, &linlen, &what) == FAILURE) {
        return;
    }
    char *p = strstr(errstr, "server has gone away");
    if (p) {
        ConProxyWG.warning_gone_away = 1;
    }

}

PHP_FUNCTION(pool_server_create)
{
    zval *conf = NULL;
    char *config_file = NULL;
    int file_len = 0;
    if (strcasecmp("cli", sapi_module.name) != 0) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "pool_server must run at php_cli environment.");
        RETURN_FALSE;
    }
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &config_file, &file_len) == FAILURE) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "config file error");
        RETURN_FALSE;
    }
    conf = cpGetConfig(config_file);
    int group_id = 0;
    for (zend_hash_internal_pointer_reset(Z_ARRVAL_P(conf)); zend_hash_has_more_elements(Z_ARRVAL_P(conf)) == SUCCESS; zend_hash_move_forward(Z_ARRVAL_P(conf))) {
        zval **config;
        zend_hash_get_current_data(Z_ARRVAL_P(conf), (void**) &config);
        char *name;
        int keylen;
        zend_hash_get_current_key_ex(Z_ARRVAL_P(conf), &name, &keylen, NULL, 0, NULL);
        int pid = fork();
        if (pid < 0) {
            php_printf("create fork error!\n");
        } else if (pid == 0) {
            cpServer_init(*config, name, config_file, group_id);

            int ret = cpServer_create();
            if (ret < 0) {
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "pool_server: create server fail. Error: %s [%d]", strerror(errno), errno);
            }

            ret = cpServer_start();
            if (ret < 0) {
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "pool_server: start server fail. Error: %s [%d]", strerror(errno), errno);
            }
        }
        group_id++;
    }
    zval_ptr_dtor(&conf);
}

PHP_FUNCTION(pool_server_reload)
{
    long pid;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &pid) == FAILURE) {
        return;
    }
    if (kill(pid, SIGUSR1) < 0) {
        php_printf("reload fail. kill -SIGUSR1 master_pid[%d] fail. Error: %s[%d]\n", (int) pid, strerror(errno), errno);
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

PHP_FUNCTION(pool_server_version)
{
    RETURN_STRING(CP_VERSION, 1);
}

PHP_FUNCTION(pool_server_shutdown)
{
    long pid;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &pid) == FAILURE) {
        return;
    }
    if (kill(pid, SIGTERM) < 0) {
        php_printf("shutdown fail. kill -SIGTERM master_pid[%d] fail. Error: %s[%d]\n", (int) pid, strerror(errno), errno);
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

CPINLINE int CP_INTERNAL_SERIALIZE_SEND_MEM(zval *ret_value, uint8_t __type)
{
    cpShareMemory *sm_obj = &(CPGS->workers[CPWG.id].sm_obj);
    instead_smart dest;
    dest.len = 0;
    dest.addr = sm_obj->mem;
    dest.max = CPGC.max_read_len;
    dest.exceed = '0';
    php_msgpack_serialize(&dest, ret_value);
    if (dest.exceed == '1') {
        zval exceed;
        ZVAL_STRING(&exceed, "data is exceed,increase max_read_len", 0);
        return CP_INTERNAL_SERIALIZE_SEND_MEM(&exceed, CP_SIGEVENT_EXCEPTION);
    } else {
        //        union sigval sigvalPara;
        //        CP_EVENTLEN_ADD_TYPE(dest.len,__type);//todo 2字节int 长度检查
        //        sigvalPara.sival_int = dest.len;
        //        if (sigqueue(pid, CP_SIG_EVENT, sigvalPara) == -1) {
        //            cpLog("sigqueue error %d", errno);
        //            return FAILURE;
        //        }
        cpWorkerInfo worker_event;
        worker_event.len = dest.len;
        worker_event.type = __type;
        worker_event.pid = CPWG.clientPid;
        int ret = write(CPGS->workers[CPWG.id].pipe_fd_write, &worker_event, sizeof (worker_event));
        if (ret == -1) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "write error Error: %s [%d]", strerror(errno), errno);
        }

        return SUCCESS;
    }
}

int pdo_proxy_connect(zval *args, int flag)
{
    zval **data_source;
    zval **object;

    if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("data_source"), (void **) &data_source) == SUCCESS) {
        if (zend_hash_find(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source), (void **) &object) == SUCCESS) {
            CP_INTERNAL_NORMAL_SEND_RETURN("CON_SUCCESS!");
        } else {
            zval **tmp_pass[4];
            zval *new_obj;
            MAKE_STD_ZVAL(new_obj);
            object_init_ex(new_obj, php_pdo_get_dbh_ce());
            tmp_pass[0] = data_source;
            zval **username;
            if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("username"), (void **) &username) == SUCCESS) {
                tmp_pass[1] = username;
            } else {
                CP_INTERNAL_ERROR_SEND_RETURN("username null!");
            }

            zval **password;
            if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("password"), (void **) &password) == SUCCESS) {
                tmp_pass[2] = password;
            } else {
                CP_INTERNAL_ERROR_SEND_RETURN("password null!");
            }

            zval **options;
            zval *null_arr = NULL;
            if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("options"), (void **) &options) == SUCCESS) {
                tmp_pass[3] = options;
            } else {
                MAKE_STD_ZVAL(null_arr);
                array_init(null_arr);
                tmp_pass[3] = &null_arr;
            }

            zval * ret_pdo_obj = NULL;
            zval con_fun_name;
            ZVAL_STRING(&con_fun_name, "__construct", 0);
            call_user_function_ex(NULL, &new_obj, &con_fun_name, &ret_pdo_obj, 4, tmp_pass, 0, NULL TSRMLS_CC);
            if (null_arr)
                zval_ptr_dtor(&null_arr);
            if (ret_pdo_obj)
                zval_ptr_dtor(&ret_pdo_obj);
            if (EG(exception)) {
                zval_ptr_dtor(&new_obj);
                CP_TEST_RETURN_FALSE(flag);
                cp_add_fail_into_mem(args, *data_source);
                CP_SEND_EXCEPTION_RETURN;
            } else {
                if (flag == CP_CONNECT_PING)
                    zval_ptr_dtor(&new_obj);
                CP_TEST_RETURN_TRUE(flag);
                //存起來
                if (zend_hash_add(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source), (void*) &new_obj, sizeof (zval *), NULL) == SUCCESS) {
                    if (flag == CP_CONNECT_NORMAL)
                        CP_INTERNAL_NORMAL_SEND_RETURN("CON_SUCCESS!");
                } else {
                    CP_INTERNAL_ERROR_SEND_RETURN("PDO obj add table fail!");
                }
            }
        }
    } else {
        CP_INTERNAL_ERROR_SEND_RETURN("PDO no datasource!");
    }
}

static int cp_call_user_function(zval **object, zval *fun, zval **ret_value, zval * args)
{
    zval **m_args;
    int count = 0;
    if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("args"), (void **) &m_args) == SUCCESS) {
        count = zend_hash_num_elements(Z_ARRVAL_PP(m_args));
        zval **tmp_pass[count];
        int i = 0;
        for (zend_hash_internal_pointer_reset(Z_ARRVAL_PP(m_args)); zend_hash_has_more_elements(Z_ARRVAL_PP(m_args)) == SUCCESS; zend_hash_move_forward(Z_ARRVAL_PP(m_args))) {
            zval **ppzval;
            zend_hash_get_current_data(Z_ARRVAL_PP(m_args), (void**) &ppzval);
            tmp_pass[i] = ppzval;
            i++;
        }
        return call_user_function_ex(NULL, object, fun, ret_value, count, tmp_pass, 0, NULL TSRMLS_CC);
    } else {
        return call_user_function_ex(NULL, object, fun, ret_value, count, NULL, 0, NULL TSRMLS_CC);
    }
}

static void pdo_proxy_pdo(zval * args)
{
    zval **data_source;
    zval **object;

    if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("data_source"), (void **) &data_source) == SUCCESS) {
        if (zend_hash_find(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source), (void **) &object) == FAILURE) {
            zval **con_args;
            zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("con_args"), (void **) &con_args);
            pdo_proxy_connect(*con_args, CP_CONNECT_RECONNECT);
        }//超过n次被kill

        if (zend_hash_find(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source), (void **) &object) == SUCCESS) {//con没返回值,这样判断
            zval **method;
            if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("method"), (void **) &method) == FAILURE) {
                CP_INTERNAL_ERROR_SEND("PDO no method!");
            }
            zval * ret_value = NULL;
            ConProxyWG.warning_gone_away = 0;
            if (cp_call_user_function(object, *method, &ret_value, args) == FAILURE) {
                CP_INTERNAL_ERROR_SEND("call pdo method error!");
            } else {
                if (EG(exception)) {
                    zval *str;
                    CP_SEND_EXCEPTION_ARGS(&str);
                    char *p = strstr(Z_STRVAL_P(str), "server has gone away");
                    char *p2 = strstr(Z_STRVAL_P(str), "There is already an active transaction");
                    if (p || p2) {
                        zend_hash_del(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source));
                    }
                    zval_ptr_dtor(&str);
                    if (ret_value)
                        zval_ptr_dtor(&ret_value);
                } else {
                    if (Z_TYPE_P(ret_value) == IS_OBJECT) {
                        char *name;
                        zend_uint name_len;
                        zend_get_object_classname(ret_value, &name, &name_len TSRMLS_CC);
                        if (strcmp(name, "PDOStatement") == 0) {
                            if (pdo_stmt) {
                                zval_ptr_dtor(&pdo_stmt);
                            }
                            pdo_stmt = ret_value;
                            zval send_zval;
                            ZVAL_STRING(&send_zval, "PDOStatement!", 0);
                            CP_INTERNAL_SERIALIZE_SEND_MEM(&send_zval, CP_SIGEVENT_PDO);
                        }
                        efree(name);
                    } else {//pdo
                        if (ConProxyWG.warning_gone_away) {//restart mysql will trigger this warning
                            zend_hash_del(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source));
                            CP_INTERNAL_ERROR_SEND("Server has gone away");
                        } else {
                            CP_INTERNAL_SERIALIZE_SEND_MEM(ret_value, CP_SIGEVENT_TURE);
                        }
                        if (ret_value)
                            zval_ptr_dtor(&ret_value);
                    }
                }
            }
        }
    } else {
        CP_INTERNAL_ERROR_SEND("PDO no datasource!");
    }
}

static void pdo_proxy_stmt(zval * args)
{
    zval **method;
    if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("method"), (void **) &method) == FAILURE) {
        CP_INTERNAL_ERROR_SEND("PDO no method!");
    }

    zval * ret_value = NULL;
    if (cp_call_user_function(&pdo_stmt, *method, &ret_value, args) == FAILURE) {
        MAKE_STD_ZVAL(ret_value);
        ZVAL_STRING(ret_value, "call pdo stmt method error!", 0);
        CP_INTERNAL_SERIALIZE_SEND_MEM(ret_value, CP_SIGEVENT_EXCEPTION);
    } else {
        zval **data_source;
        zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("data_source"), (void **) &data_source);
        if (EG(exception)) {
            zval *str;
            CP_SEND_EXCEPTION_ARGS(&str);
            char *p = strstr(Z_STRVAL_P(str), "server has gone away");
            char *p2 = strstr(Z_STRVAL_P(str), "There is already an active transaction");
            if (p || p2) {
                zend_hash_del(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source));
            }
            zval_ptr_dtor(&str);
            zval_ptr_dtor(&pdo_stmt);
            pdo_stmt = NULL;
        } else {
            if (ConProxyWG.warning_gone_away) {//restart mysql will trigger this warning
                zend_hash_del(&pdo_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source));
                CP_INTERNAL_ERROR_SEND("Server has gone away");
            } else {
                CP_INTERNAL_SERIALIZE_SEND_MEM(ret_value, CP_SIGEVENT_TURE);
            }
        }
    }
    if (ret_value) {
        zval_ptr_dtor(&ret_value);
    }
}

static void pdo_dispatch(zval * args)
{
    zval **m_type;
    if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("method_type"), (void **) &m_type) == SUCCESS) {
        if (strcmp(Z_STRVAL_PP(m_type), "connect") == 0) {
            pdo_proxy_connect(args, CP_CONNECT_NORMAL);
        } else if (strcmp(Z_STRVAL_PP(m_type), "PDOStatement") == 0) {
            pdo_proxy_stmt(args);
        } else {
            pdo_proxy_pdo(args);
        }
    } else {//操作pdo
        CP_INTERNAL_ERROR_SEND("PDO  method_type is none!");
    }
}

static int cp_redis_select(zval *new_obj, zval **db)
{
    //有db并且不0那么就select
    if (strcmp("0", Z_STRVAL_PP(db)) != 0) {
        zval **tmp_pass2[1];
        tmp_pass2[0] = db;
        zval * ret_redis_select = NULL;
        zval select_fun_name;
        ZVAL_STRING(&select_fun_name, "select", 0);
        call_user_function_ex(NULL, &new_obj, &select_fun_name, &ret_redis_select, 1, tmp_pass2, 0, NULL TSRMLS_CC);
        if (ret_redis_select)
            zval_ptr_dtor(&ret_redis_select);

        if (EG(exception)) {
            zval_ptr_dtor(&new_obj);
            CP_SEND_EXCEPTION_RETURN;
        }
    }
    return CP_TRUE;
}

int redis_proxy_connect(zval *data_source, zval *args, int flag)
{
    zval *ex_arr, zdelim, **ip, **port, **db;
    MAKE_STD_ZVAL(ex_arr);
    array_init(ex_arr);
    ZVAL_STRINGL(&zdelim, ":", 1, 0);
    php_explode(&zdelim, data_source, ex_arr, LONG_MAX);

    zval **tmp_pass[3];
    zval *new_obj;
    MAKE_STD_ZVAL(new_obj);
    zend_class_entry **redis_ce;

    if (zend_hash_find(CG(class_table), ZEND_STRS("redis"), (void **) &redis_ce) == FAILURE) {
        CP_INTERNAL_ERROR_SEND_RETURN("redis extension is not install");
    }
    object_init_ex(new_obj, *redis_ce);

    if (zend_hash_index_find(Z_ARRVAL_P(ex_arr), 0, (void**) &ip) == SUCCESS) {
        tmp_pass[0] = ip;
    } else {
        CP_INTERNAL_ERROR_SEND_RETURN("redis ip null!");
    }
    if (zend_hash_index_find(Z_ARRVAL_P(ex_arr), 1, (void**) &port) == SUCCESS) {
        tmp_pass[1] = port;
    } else {
        CP_INTERNAL_ERROR_SEND_RETURN("redis ip null!");
    }

    zval *timeout;
    MAKE_STD_ZVAL(timeout);
    ZVAL_STRING(timeout, "10", 0);
    tmp_pass[2] = &timeout;

    zval * ret_redis_obj = NULL;
    zval pcon_fun_name;
    ZVAL_STRING(&pcon_fun_name, "connect", 0);
    call_user_function_ex(NULL, &new_obj, &pcon_fun_name, &ret_redis_obj, 3, tmp_pass, 0, NULL TSRMLS_CC);
    efree(timeout);

    if (ret_redis_obj) {
        if (Z_BVAL_P(ret_redis_obj) == FALSE) {
            zval_ptr_dtor(&ex_arr);
            zval_ptr_dtor(&ret_redis_obj);
            CP_TEST_RETURN_FALSE(flag);
            cp_add_fail_into_mem(args, data_source);
            CP_INTERNAL_ERROR_SEND_RETURN("connect redis error!");
        } else {
            zval_ptr_dtor(&ret_redis_obj);
        }
    }
    if (EG(exception)) {
        zval_ptr_dtor(&new_obj);
        zval_ptr_dtor(&ex_arr);
        CP_TEST_RETURN_FALSE(flag);
        cp_add_fail_into_mem(args, data_source);
        CP_SEND_EXCEPTION_RETURN;
    }
    if (flag == CP_CONNECT_PING) {
        zval_ptr_dtor(&new_obj);
        zval_ptr_dtor(&ex_arr);
        return CP_TRUE;
    }

    if (zend_hash_index_find(Z_ARRVAL_P(ex_arr), 2, (void**) &db) == SUCCESS) {
        if (!cp_redis_select(new_obj, db)) {
            zval_ptr_dtor(&ex_arr);
            return CP_FALSE;
        }
    }
    zval_ptr_dtor(&ex_arr);
    //存起來
    if (zend_hash_add(&redis_object_table, Z_STRVAL_P(data_source), Z_STRLEN_P(data_source), (void*) &new_obj, sizeof (zval *), NULL) == FAILURE) {
        CP_INTERNAL_ERROR_SEND_RETURN("redis obj add table fail!");
    }
    zval **method;
    if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("method"), (void **) &method) == FAILURE) {
        CP_INTERNAL_ERROR_SEND_RETURN("redis no method!");
    }
    if (strcmp(Z_STRVAL_PP(method), "select") == 0) {
        CP_INTERNAL_NORMAL_SEND_RETURN("CON_SUCCESS!");
    } else {
        zval * ret_value = NULL;
        if (cp_call_user_function(&new_obj, *method, &ret_value, args) == SUCCESS) {
            if (!EG(exception)) {
                CP_INTERNAL_SERIALIZE_SEND_MEM(ret_value, CP_SIGEVENT_TURE);

            } else {
                CP_SEND_EXCEPTION;
            }
        } else {
            CP_INTERNAL_ERROR_SEND("call redis method error!");
        }
        if (ret_value)
            zval_ptr_dtor(&ret_value);
        return CP_TRUE; //no use
    }
}

static void redis_dispatch(zval * args)
{
    zval **data_source;
    zval **object;
    if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("data_source"), (void **) &data_source) == SUCCESS) {
        if (zend_hash_find(&redis_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source), (void **) &object) == SUCCESS) {
            zval **method;
            if (zend_hash_find(Z_ARRVAL_P(args), ZEND_STRS("method"), (void **) &method) == FAILURE) {
                zval error_str;
                ZVAL_STRING(&error_str, "redis no method error!", 0);
                CP_INTERNAL_SERIALIZE_SEND_MEM(&error_str, CP_SIGEVENT_EXCEPTION);
                return;
            } else if (strcmp(Z_STRVAL_PP(method), "select") == 0) {
                zval select_return;
                ZVAL_BOOL(&select_return, 1);
                CP_INTERNAL_SERIALIZE_SEND_MEM(&select_return, CP_SIGEVENT_TURE);
                return;
            }
            zval * ret_value = NULL;
            if (cp_call_user_function(object, *method, &ret_value, args) == FAILURE) {
                zval error_str;
                ZVAL_STRING(&error_str, "call redis method error!", 0);
                CP_INTERNAL_SERIALIZE_SEND_MEM(&error_str, CP_SIGEVENT_EXCEPTION);
            } else {
                if (EG(exception)) {
                    zval *str;
                    CP_SEND_EXCEPTION_ARGS(&str);
                    char *p = strstr(Z_STRVAL_P(str), "server went away");
                    char *p2 = strstr(Z_STRVAL_P(str), "Connection lost");
                    if (p || p2) {
                        zend_hash_del(&redis_object_table, Z_STRVAL_PP(data_source), Z_STRLEN_PP(data_source));
                    }
                    zval_ptr_dtor(&str);
                } else {
                    CP_INTERNAL_SERIALIZE_SEND_MEM(ret_value, CP_SIGEVENT_TURE);
                }
            }
            if (ret_value)
                zval_ptr_dtor(&ret_value);
        } else {
            redis_proxy_connect(*data_source, args, CP_CONNECT_NORMAL);
        }
    } else {
        CP_INTERNAL_ERROR_SEND("redis no datasource!");
    }
}

int worker_onReceive(zval * unser_value)
{
    zval **type;
    if (zend_hash_find(Z_ARRVAL_P(unser_value), ZEND_STRS("type"), (void **) &type) == SUCCESS) {
        if (strcmp(Z_STRVAL_PP(type), "pdo") == 0) {
            pdo_dispatch(unser_value);
        } else if (strcmp(Z_STRVAL_PP(type), "redis") == 0) {
            redis_dispatch(unser_value);
        }
    } else {
        cpLog("args error no type!");
    }
    zval_ptr_dtor(&unser_value);
    return CP_TRUE;
}

static void cp_add_fail_into_mem(zval *o_arg, zval * data_source)
{

    zval *args;
    MAKE_STD_ZVAL(args);
    *args = *o_arg;
    zval_copy_ctor(args);
    if (!CPGL.ping_mem_addr) {
        if ((CPGL.ping_mem_addr = shmat(CPGS->ping_workers->sm_obj.shmid, NULL, 0)) < 0) {
            cpLog("worker attach ping worker sys mem error Error: %s [%d]", strerror(errno), errno);
        }
    }
    zval *arr = CP_PING_GET_PRO(CPGL.ping_mem_addr);
    if (Z_TYPE_P(arr) == IS_NULL) {
        zval first_arr;
        array_init(&first_arr);
        add_assoc_long(args, "count", 1);
        add_assoc_zval(&first_arr, Z_STRVAL_P(data_source), args);
        cp_ser_and_setpro(&first_arr);
        zval_dtor(&first_arr);
    } else if (Z_TYPE_P(arr) != IS_BOOL) {
        zval **zval_source;
        if (zend_hash_find(Z_ARRVAL_P(arr), Z_STRVAL_P(data_source), Z_STRLEN_P(data_source) + 1, (void **) &zval_source) == SUCCESS) {//++
            zval **zval_probably_count;
            if (zend_hash_find(Z_ARRVAL_PP(zval_source), ZEND_STRS("count"), (void **) &zval_probably_count) == SUCCESS) {
                int num = (int) Z_LVAL_PP(zval_probably_count);
                add_assoc_long(args, "count", ++num);
                zend_hash_del(Z_ARRVAL_P(arr), Z_STRVAL_P(data_source), Z_STRLEN_P(data_source));
                add_assoc_zval(arr, Z_STRVAL_P(data_source), args);
                cp_ser_and_setpro(arr);
            }
        } else {//add
            add_assoc_long(args, "count", 1);
            add_assoc_zval(arr, Z_STRVAL_P(data_source), args);
            cp_ser_and_setpro(arr);
        }

    }
    zval_ptr_dtor(&arr);
}
