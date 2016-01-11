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
#include "php_streams.h"
#include "php_network.h"
#include "ext/standard/basic_functions.h"

extern zend_class_entry *pdo_connect_pool_class_entry_ptr;
extern zend_class_entry *redis_connect_pool_class_entry_ptr;
extern zend_class_entry *pdo_connect_pool_PDOStatement_class_entry_ptr;

#define CON_FORMART_KEY(str,port) sprintf((str), "connect_pool_sock%d" , (port));
#define CON_FAIL_MESSAGE                         "connect to pool_server fail"

typedef struct _cpRecvEvent
{
    zval *ret_value;
    uint8_t type;
} cpRecvEvent;

cpRecvEvent RecvData;
static int *workerid2writefd = NULL;
static int *workerid2readfd = NULL;
static void **semid2attbuf = NULL;
static HashTable ping_addr;
static HashTable *ptr_ping_addr = NULL;
static int cpPid = 0;
static int dev_random_fd = -1;
#define CP_GET_PID if(cpPid==0)cpPid=getpid()

static int php_pdo_connect_pool_close(cpClient *cli)
{
    char str[100] = {0};
    CON_FORMART_KEY(str, cli->port);
    if (zend_hash_del(&EG(persistent_list), str, strlen(str)) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "del hash error!");
        return FAILURE;
    }
    return SUCCESS;
}

static void release_worker(zval *object)
{
    zend_rsrc_list_entry *p_sock_le;
    zval **pool_port;
    if (zend_hash_find(Z_OBJPROP_P(object), ZEND_STRS("pool_port"), (void **) &pool_port) == SUCCESS)
    {
        char str[100] = {0};
        CON_FORMART_KEY(str, (int) Z_LVAL_PP(pool_port));
        if (zend_hash_find(&EG(persistent_list), str, strlen(str), (void **) &p_sock_le) == SUCCESS)
        {
            send_oob2proxy(p_sock_le);
        }
        else
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "p_sock_le can not find");
        }
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "pool_port can not find");
    }
}

static int get_writefd(int worker_id)
{
    if (workerid2writefd == NULL)
    {
        workerid2writefd = (int *) calloc(CP_GROUP_NUM*CP_GROUP_LEN, sizeof (int));
        if (workerid2writefd == NULL)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "calloc Error: %s [%d]", strerror(errno), errno);
        }
    }
    int pipe_fd_write;
    if (workerid2writefd[worker_id] == 0)
    {
        char file_c2w[CP_FIFO_NAME_LEN] = {0};
        sprintf(file_c2w, "%s_%d", CP_FIFO_NAME_PRE, worker_id);
        pipe_fd_write = cpCreateFifo(file_c2w);
        if (pipe_fd_write < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "pipe open Error: %s [%d]", strerror(errno), errno);
        }
        workerid2writefd[worker_id] = pipe_fd_write;
    }
    else
    {
        pipe_fd_write = workerid2writefd[worker_id];
    }
    return pipe_fd_write;
}

static int get_readfd(int worker_id)
{
    if (workerid2readfd == NULL)
    {
        workerid2readfd = (int *) calloc(CP_GROUP_NUM*CP_GROUP_LEN, sizeof (int));
        if (workerid2readfd == NULL)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "calloc Error: %s [%d]", strerror(errno), errno);
        }
    }
    int pipe_fd_read;
    if (workerid2readfd[worker_id] == 0)
    {
        char file_w2c[CP_FIFO_NAME_LEN] = {0};
        sprintf(file_w2c, "%s_%d_1", CP_FIFO_NAME_PRE, worker_id); //worker 2 client
        pipe_fd_read = cpCreateFifo(file_w2c);
        if (pipe_fd_read < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "pipe open Error: %s [%d]", strerror(errno), errno);
        }
        workerid2readfd[worker_id] = pipe_fd_read;
    }
    else
    {
        pipe_fd_read = workerid2readfd[worker_id];
    }
    return pipe_fd_read;
}

static void* get_attach_buf(int worker_id, int max, char *mm_name)
{
    if (semid2attbuf == NULL)
    {
        semid2attbuf = (void **) calloc(CP_GROUP_NUM*CP_GROUP_LEN, sizeof (void*));
        if (semid2attbuf == NULL)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "calloc Error: %s [%d]", strerror(errno), errno);
        }
    }
    void* buf = NULL;
    if (semid2attbuf[worker_id] == 0)
    {
        int fd = open(mm_name, O_RDWR);
        if (fd == -1)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "open error Error: %s [%d]", strerror(errno), errno);
        }
        if ((buf = mmap(NULL, max, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "attach sys mem error Error: %s [%d]", strerror(errno), errno);
        }
        semid2attbuf[worker_id] = buf;
    }
    else
    {
        buf = semid2attbuf[worker_id];
    }

    return buf;
}

CPINLINE int CP_CLIENT_SERIALIZE_SEND_MEM(zval *ret_value, int worker_id, int max, char *mm_name)
{
    int pipe_fd_write = get_writefd(worker_id);
    instead_smart dest;
    dest.len = 0;
    dest.addr = get_attach_buf(worker_id, max, mm_name);
    dest.max = max;
    dest.exceed = 0;
    php_msgpack_serialize(&dest, ret_value);
    if (dest.exceed == 1)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "data is exceed,increase max_read_len Error: %s [%d] ", strerror(errno), errno);
    }
    else
    {
        cpWorkerInfo worker_event;
        worker_event.len = dest.len;
        worker_event.pid = cpPid;
        worker_event.type = 0; //暫時沒用
        int ret = write(pipe_fd_write, &worker_event, sizeof (worker_event));
        if (ret == -1)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "write error Error: %s [%d]", strerror(errno), errno);
        }
        return SUCCESS;
    }
    return FAILURE;
}

void* connect_pool_perisent(zval* zres, int port)
{
    zend_rsrc_list_entry sock_le;
    int ret;
    cpClient* cli = (cpClient*) pecalloc(sizeof (cpClient), 1, 1);
    if (cpClient_create(cli) < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "pdo_connect_pool: create sock fail. Error: %s [%d]", strerror(errno), errno);
    }
    cli->port = port;
    ret = cpClient_connect(cli, "127.0.0.1", cli->port, (float) 100, 0); //所有的操作100s超时
    if (ret < 0)
    {
        pefree(cli, 1);
        return NULL;
    }
    sock_le.type = le_cli_connect_pool;
    sock_le.ptr = cli;
    ZEND_REGISTER_RESOURCE(zres, cli, le_cli_connect_pool);
    char str[100] = {0};
    CON_FORMART_KEY(str, cli->port);
    zend_hash_update(&EG(persistent_list), str, strlen(str), (void*) &sock_le, sizeof (zend_rsrc_list_entry), NULL);
    return cli;
}

CPINLINE int cli_real_send(cpClient **real_cli, zval *send_data, zval *this, zend_class_entry *ce)
{
    int ret = 0;
    cpClient *cli = *real_cli;
    cpMasterInfo *info = &cli->info;
    if (cli->released == CP_FD_RELEASED)
    {
        zval **data_source;
        zend_hash_find(Z_ARRVAL_P(send_data), ZEND_STRS("data_source"), (void **) &data_source);
        cpTcpEvent event;
        event.type = CP_TCPEVENT_GET;
        event.ClientPid = cpPid;
        strcpy(event.data_source, Z_STRVAL_PP(data_source));
        int ret = cpClient_send(cli->sock, (char *) &event, sizeof (event), 0);
        if (ret < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "send failed in GET. Error:%d", errno);
        }
        int n = cpClient_recv(cli, info, sizeof (cpMasterInfo), 1);
        if (info->worker_id == -1)
        {
            zend_throw_exception(NULL, CP_MULTI_PROCESS_ERR, 0 TSRMLS_CC);
            return -1;
        }
        if (info->worker_id == -2)
        {
            zend_throw_exception(NULL, "can not find datasource from pool.ini", 0 TSRMLS_CC);
            return -1;
        }
        if (n > 0)
        {
            ret = CP_CLIENT_SERIALIZE_SEND_MEM(send_data, info->worker_id, info->max, info->mmap_name);
            if (ret == SUCCESS)
            {
                cli->released = CP_FD_NRELEASED;
            }
        }
        else if (n == 0)
        {
            ret = cpClient_close(cli);
            zval *zres = NULL;
            MAKE_STD_ZVAL(zres);
            cpClient *cli_retry = NULL;
            if ((cli_retry = connect_pool_perisent(zres, cli->port)) == NULL)
            {
                efree(zres);
                zend_throw_exception(NULL, CON_FAIL_MESSAGE, 0 TSRMLS_CC);
                return -1;
            }
            else
            {
                zend_update_property(ce, this, ZEND_STRL("cli"), zres TSRMLS_CC);
                *real_cli = cli_retry;
                return cli_real_send(&cli_retry, send_data, this, ce);
            }
        }
        else
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "connect_pool: recv failed. Error: %s [%d]", strerror(errno), errno);
        }
    }
    else
    {
        ret = CP_CLIENT_SERIALIZE_SEND_MEM(send_data, info->worker_id, info->max, info->mmap_name);
    }
    return ret;
}

static int cli_real_recv(cpMasterInfo *info)
{
    int pipe_fd_read = get_readfd(info->worker_id);
    cpWorkerInfo event;
    int ret = 0;
    do
    {
        ret = cpFifoRead(pipe_fd_read, &event, sizeof (event));
        if (ret < 0)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "fifo read Error: %s [%d]", strerror(errno), errno);
        }
    } while (event.pid != cpPid); //有可能有脏数据  读出来

    zval *ret_value;
    ALLOC_INIT_ZVAL(ret_value);
    php_msgpack_unserialize(ret_value, get_attach_buf(info->worker_id, info->max, info->mmap_name), event.len);
    RecvData.type = event.type;
    RecvData.ret_value = ret_value;
    return SUCCESS;
}

static void check_need_exchange(zval * object, char *cur_type)
{//修复:用了ms  但切换的时候忘记release了会导致一个worker多个连接的问题
    char *lt = NULL;
    zval **last_type;
    // compare with last_type
    if (zend_hash_find(Z_OBJPROP_P(object), ZEND_STRS("last_type"), (void **) &last_type) == SUCCESS)
    {
        lt = Z_STRVAL_PP(last_type);
    }
    // exchange 
    if (cur_type != lt)
    {
        release_worker(object);
        zend_update_property_string(pdo_connect_pool_class_entry_ptr, object, ZEND_STRL("last_type"), cur_type TSRMLS_CC);
    }
}

static char* php_check_ms(char *cmd, zval *z_args, zval* object)
{
    zval **enable_slave, **sql;
    char *cur_type = "m";
    zend_hash_find(Z_OBJPROP_P(object), ZEND_STRS("enable_slave"), (void **) &enable_slave);
    if (!Z_BVAL_PP(enable_slave))
    {
        return cur_type;
    }

    if (strcasecmp("query", cmd) == 0 || strcasecmp("exec", cmd) == 0 || strcasecmp("prepare", cmd) == 0)
    {
        zend_hash_index_find(Z_ARRVAL_P(z_args), 0, (void**) &sql);
        convert_to_string_ex(sql);
        char pre[8] = {0};
        strncpy(pre, Z_STRVAL_PP(sql), 6);
        int i = 0;
        for (; i < 6; i++)
        {
            if (pre[i] == ' ')
            {
                pre[i] = '\0';
                break;
            }
            pre[i] = tolower(pre[i]);
        }
        if (strcmp(pre, "select") == 0 || strcmp(pre, "show") == 0)
        {
            cur_type = "s";
        }
        else
        {
            cur_type = "m";
        }
    }
    return cur_type;
}

int cp_system_random(int min, int max)
{
    char *next_random_byte;
    int bytes_to_read;
    unsigned random_value;

    assert(max > min);

    if (dev_random_fd == -1)
    {
        dev_random_fd = open("/dev/urandom", O_RDONLY);
        assert(dev_random_fd != -1);
    }

    next_random_byte = (char *) &random_value;
    bytes_to_read = sizeof (random_value);

    if (read(dev_random_fd, next_random_byte, bytes_to_read) < 0)
    {
        return -1;
    }
    return min + (random_value % (max - min + 1));
}


//create the pass args that pass to mysql

static zval* create_pass_data(char* cmd, zval* z_args, zval* object, char* cur_type, zval **ret_data_source)
{
    zval **data_source, **username, **pwd, **options, *pass_data, *zval_conf, **real_data_srouce_arr;
    zval_conf = zend_read_property(pdo_connect_pool_class_entry_ptr, object, ZEND_STRL("config"), 0 TSRMLS_DC);

    if (*cur_type == 's')
    {
        zval **slave;
        zval *start_prt, start, end, *end_prt;
        start_prt = &start;
        end_prt = &end;

        zend_hash_find(Z_ARRVAL_P(zval_conf), ZEND_STRS("slave"), (void **) &slave);
        int slave_cnt;
        slave_cnt = zend_hash_num_elements(Z_ARRVAL_P(*slave));

        if (slave_cnt > 0)
        {
            int index;
            index = cp_system_random(0, (slave_cnt - 1));

            if (zend_hash_index_find(Z_ARRVAL_PP(slave), index, (void **) &real_data_srouce_arr) != SUCCESS)
            {
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "not find slave ,check config");
            }
        }
    }
    else
    {
        if (zend_hash_find(Z_ARRVAL_P(zval_conf), ZEND_STRS("master"), (void **) &real_data_srouce_arr) != SUCCESS)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "not find master ,check config");
        }
    }
    // find args
    zend_hash_find(Z_ARRVAL_PP(real_data_srouce_arr), ZEND_STRS("data_source"), (void **) &data_source);
    zend_hash_find(Z_ARRVAL_PP(real_data_srouce_arr), ZEND_STRS("username"), (void **) &username);
    zend_hash_find(Z_ARRVAL_PP(real_data_srouce_arr), ZEND_STRS("pwd"), (void **) &pwd);

    MAKE_STD_ZVAL(pass_data);
    array_init(pass_data);
    add_assoc_string(pass_data, "type", "pdo", 1);
    add_assoc_string(pass_data, "method_type", "connect", 1);
    add_assoc_string(pass_data, "method", cmd, 1);
    add_assoc_string(pass_data, "data_source", Z_STRVAL_PP(data_source), 1);
    *ret_data_source = *data_source;
    add_assoc_string(pass_data, "username", Z_STRVAL_PP(username), 1);
    add_assoc_string(pass_data, "password", Z_STRVAL_PP(pwd), 1);
    zval_add_ref(&z_args);
    add_assoc_zval(pass_data, "args", z_args);
    if (zend_hash_find(Z_ARRVAL_PP(real_data_srouce_arr), ZEND_STRS("options"), (void **) &options) != SUCCESS)
    {
        zval *new_option = NULL;
        MAKE_STD_ZVAL(new_option);
        array_init(new_option);
        add_index_long(new_option, PDO_ATTR_ERRMODE, PDO_ERRMODE_EXCEPTION);
        add_index_string(new_option, PDO_ATTR_DRIVER_SPECIFIC + 2, "SET SESSION wait_timeout=2147483", 1);
        add_assoc_zval(pass_data, "options", new_option);
    }
    else
    {
        zval_add_ref(options);
        add_index_long(*options, PDO_ATTR_ERRMODE, PDO_ERRMODE_EXCEPTION); //set exception mode for delete pdo object from pool when gone away
        add_index_string(*options, PDO_ATTR_DRIVER_SPECIFIC + 2, "SET SESSION wait_timeout=2147483", 1);
        add_assoc_zval(pass_data, "options", *options);
    }
    return pass_data;
}

PHP_METHOD(pdo_connect_pool_PDOStatement, __call)
{
    zval *z_args;
    zval *object;
    zval *pass_data;
    zval **zres, **source_zval;

    char *cmd;
    int cmd_len;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Osa", &object, pdo_connect_pool_PDOStatement_class_entry_ptr, &cmd, &cmd_len, &z_args) == FAILURE)
    {
        RETURN_FALSE;
    }

    cpClient *cli;
    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("cli"), (void **) &zres) == SUCCESS)
    {
        ZEND_FETCH_RESOURCE(cli, cpClient*, zres, -1, CP_RES_CLIENT_NAME, le_cli_connect_pool);
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "pdo_connect_pool: object is not instanceof pdo_connect_pool. ");
        RETURN_FALSE;
    }
    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("data_source"), (void **) &source_zval) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "pdo_connect_pool: get data_source name failed!");
        RETURN_FALSE;
    }

    MAKE_STD_ZVAL(pass_data);
    array_init(pass_data);
    add_assoc_string(pass_data, "data_source", Z_STRVAL_PP(source_zval), 1);
    add_assoc_string(pass_data, "method", cmd, 1);
    zval_add_ref(&z_args);
    add_assoc_zval(pass_data, "args", z_args);
    add_assoc_string(pass_data, "method_type", "PDOStatement", 1);
    add_assoc_string(pass_data, "type", "pdo", 1);
    int ret = cli_real_send(&cli, pass_data, getThis(), pdo_connect_pool_PDOStatement_class_entry_ptr);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "cli_real_send faild error Error: %s [%d] ", strerror(errno), errno);
    }
    cli_real_recv(&cli->info);
    if (RecvData.type == CP_SIGEVENT_EXCEPTION)
    {
        zend_throw_exception(NULL, Z_STRVAL_P(RecvData.ret_value), 0 TSRMLS_CC);
        RETVAL_BOOL(0);
    }
    else
    {
        RETVAL_ZVAL(RecvData.ret_value, 0, 1);
    }
    zval_ptr_dtor(&pass_data);
}

PHP_METHOD(pdo_connect_pool, __call)
{
    zval *z_args, *pass_data, *object, **zres, *source_zval, **use_ms;
    char *cmd, *cur_type;
    int cmd_len;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Osa", &object, pdo_connect_pool_class_entry_ptr, &cmd, &cmd_len, &z_args) == FAILURE)
    {
        RETURN_FALSE;
    }

    cpClient *cli;
    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("cli"), (void **) &zres) == SUCCESS)
    {
        ZEND_FETCH_RESOURCE(cli, cpClient*, zres, -1, CP_RES_CLIENT_NAME, le_cli_connect_pool);
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "pdo_connect_pool: object is not instanceof pdo_connect_pool. ");
        RETURN_FALSE;
    }

    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("use_ms"), (void **) &use_ms) == SUCCESS)
    {
        cur_type = "m";
    }
    else
    {
        cur_type = php_check_ms(cmd, z_args, object);
        check_need_exchange(getThis(), cur_type);
    }
    pass_data = create_pass_data(cmd, z_args, object, cur_type, &source_zval);
    int ret = cli_real_send(&cli, pass_data, getThis(), pdo_connect_pool_class_entry_ptr);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "cli_real_send faild error Error: %s [%d] ", strerror(errno), errno);
    }

    cli_real_recv(&cli->info);
    if (RecvData.type == CP_SIGEVENT_PDO)
    {//返回一个模拟pdo类
        object_init_ex(return_value, pdo_connect_pool_PDOStatement_class_entry_ptr);
        zend_update_property(pdo_connect_pool_PDOStatement_class_entry_ptr, return_value, ZEND_STRL("cli"), *zres TSRMLS_CC);
        zend_update_property(pdo_connect_pool_PDOStatement_class_entry_ptr, return_value, ZEND_STRL("data_source"), source_zval TSRMLS_CC); //标示这个连接的真实目标
        zval_ptr_dtor(&RecvData.ret_value);
    }
    else if (RecvData.type == CP_SIGEVENT_EXCEPTION)
    {
        zend_throw_exception(NULL, Z_STRVAL_P(RecvData.ret_value), 0 TSRMLS_CC);
        RETVAL_BOOL(0);
    }
    else
    {
        RETVAL_ZVAL(RecvData.ret_value, 0, 1);
    }
    zval_ptr_dtor(&pass_data);
}

PHP_METHOD(pdo_connect_pool, __destruct)
{
}

PHP_METHOD(pdo_connect_pool, __construct)
{
    //     cpLog_init("/tmp/fpmlog");
    zval *zres, *zval_conf, *data_source, *options = NULL, *master = NULL;
    zval *object = getThis();
    char *username = NULL, *password = NULL;
    int usernamelen, passwordlen;
    int port = CP_PORT_PDO;

    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|s!s!a!l!", &data_source,
            &username, &usernamelen, &password, &passwordlen, &options, &port))
    {
        ZVAL_NULL(object);
        return;
    }
    CP_GET_PID;
    MAKE_STD_ZVAL(zres);
    cpClient *cli;
    zend_rsrc_list_entry *p_sock_le;
    char str[100] = {0};
    CON_FORMART_KEY(str, port);

    if (zend_hash_find(&EG(persistent_list), str, strlen(str), (void **) &p_sock_le) == SUCCESS)
    {
        cli = (cpClient*) p_sock_le->ptr;
        ZEND_REGISTER_RESOURCE(zres, cli, le_cli_connect_pool);
    }
    else
    {//create long connect to pool_server
        if ((cli = connect_pool_perisent(zres, port)) == NULL)
        {// error
            efree(zres);
            zend_throw_exception(NULL, CON_FAIL_MESSAGE, 0 TSRMLS_CC);
            return;
        }
    }

    switch (Z_TYPE_P(data_source))
    {
        case IS_STRING:
            MAKE_STD_ZVAL(zval_conf);
            MAKE_STD_ZVAL(master);
            array_init(zval_conf);
            array_init(master);

            add_assoc_string(master, "data_source", Z_STRVAL_P(data_source), 1);
            add_assoc_string(master, "username", username, 1);
            add_assoc_string(master, "pwd", password, 1);
            if (options != NULL)
            {
                zval_add_ref(&options);
                add_assoc_zval(master, "options", options);
            }
            add_assoc_zval(zval_conf, "master", master);
            zend_update_property_bool(pdo_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("use_ms"), 0 TSRMLS_CC);
            zend_update_property(pdo_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("config"), zval_conf TSRMLS_CC);
            break;
        case IS_ARRAY:
            zval_add_ref(&data_source);
            zend_update_property(pdo_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("config"), data_source TSRMLS_CC);
            break;
    }
    zend_update_property(pdo_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("cli"), zres TSRMLS_CC);
    zend_update_property_long(pdo_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("pool_port"), port TSRMLS_CC);
    zend_update_property_bool(pdo_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("enable_slave"), 1 TSRMLS_CC);
    zval_ptr_dtor(&zres);
}

PHP_FUNCTION(client_close)
{//close 关闭和中间件的连接
    zval **zres;
    cpClient *cli;
    int ret;

    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("cli"), (void **) &zres) == SUCCESS)
    {
        ZEND_FETCH_RESOURCE(cli, cpClient*, zres, -1, CP_RES_CLIENT_NAME, le_cli_connect_pool);
    }
    else
    {
        RETURN_FALSE;
    }
    ret = php_pdo_connect_pool_close(cli);
    CP_CHECK_RETURN(ret);
}

PHP_METHOD(pdo_connect_pool, release)
{
    release_worker(getThis());
    CP_CHECK_RETURN(1);
}

PHP_METHOD(redis_connect_pool, release)
{
    release_worker(getThis());
    CP_CHECK_RETURN(1);
}

PHP_METHOD(redis_connect_pool, __destruct)
{

}

PHP_METHOD(redis_connect_pool, __construct)
{
    zval *zres, *pool_port;
    MAKE_STD_ZVAL(zres);
    cpClient *cli;
    zend_rsrc_list_entry *p_sock_le;
    int port = CP_PORT_REDIS;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &port))
    {
        return;
    }
    char str[100] = {0};
    CON_FORMART_KEY(str, port);

    if (zend_hash_find(&EG(persistent_list), str, strlen(str), (void **) &p_sock_le) == SUCCESS)
    {
        cli = (cpClient*) p_sock_le->ptr;
        ZEND_REGISTER_RESOURCE(zres, cli, le_cli_connect_pool);
    }
    else
    {//这个fpm进程第一次创建连接
        if ((cli = connect_pool_perisent(zres, port)) == NULL)
        {//没连上
            efree(zres);
            zend_throw_exception(NULL, CON_FAIL_MESSAGE, 0 TSRMLS_CC);
            return;
        }
    }
    //    cpQueueSignalSet(CP_SIG_EVENT, HandleRecv);
    CP_GET_PID;
    MAKE_STD_ZVAL(pool_port);
    ZVAL_LONG(pool_port, port);
    zend_update_property(redis_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("cli"), zres TSRMLS_CC);
    zend_update_property(redis_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("pool_port"), pool_port TSRMLS_CC);
    zval_ptr_dtor(&zres);
    zval_ptr_dtor(&pool_port);
}

PHP_METHOD(redis_connect_pool, connect)
{
    char *ip;
    int ip_len;
    char *port;
    int port_len = 0;
    char *time;
    int time_len = 0;
    zval *zval_ip;
    zval *zval_port;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s!|s!s!", &ip, &ip_len, &port, &port_len, &time, &time_len) == FAILURE)
    {
        RETURN_FALSE;
    }
    //    convert_to_string(*port);
    MAKE_STD_ZVAL(zval_ip);
    ZVAL_STRING(zval_ip, ip, 1);

    MAKE_STD_ZVAL(zval_port);
    if (port_len > 0)
    {
        ZVAL_STRING(zval_port, port, 1);
    }
    else
    {
        ZVAL_STRING(zval_port, "6379", 1);
    }
    //临时标示这个连接的真实目标,根据下一步是select还是get来确定db号,可以減少一次select操作
    zend_update_property(redis_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("ip"), zval_ip TSRMLS_CC);
    zend_update_property(redis_connect_pool_class_entry_ptr, getThis(), ZEND_STRL("port"), zval_port TSRMLS_CC);

    zval_ptr_dtor(&zval_port);
    zval_ptr_dtor(&zval_ip);

    RETURN_TRUE;
}

PHP_METHOD(redis_connect_pool, select)
{
    zval *pass_data;
    zval *object;
    zval **zres, *source_zval, **ip, **port, *zval_db, *z_args;
    char source_char[100] = {0};
    char *db;
    int db_len;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os!", &object, redis_connect_pool_class_entry_ptr, &db, &db_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (zend_hash_find(Z_OBJPROP_P(object), ZEND_STRS("ip"), (void **) &ip) == SUCCESS)
    {
        strcat(source_char, Z_STRVAL_PP(ip));
        strcat(source_char, ":");
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "redis_connect_pool: IP is empty ");
        RETURN_FALSE;
    }

    if (zend_hash_find(Z_OBJPROP_P(object), ZEND_STRS("port"), (void **) &port) == SUCCESS)
    {
        strcat(source_char, Z_STRVAL_PP(port));
        strcat(source_char, ":");
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "redis_connect_pool: PORT is empty");
        RETURN_FALSE;
    }

    MAKE_STD_ZVAL(zval_db);
    ZVAL_STRING(zval_db, db, 1);
    zend_update_property(redis_connect_pool_class_entry_ptr, object, ZEND_STRL("db"), zval_db TSRMLS_CC);
    strcat(source_char, db);
    MAKE_STD_ZVAL(source_zval);
    ZVAL_STRING(source_zval, source_char, 1);
    zend_update_property(redis_connect_pool_class_entry_ptr, object, ZEND_STRL("data_source"), source_zval TSRMLS_CC); //确定数据源
    zval_ptr_dtor(&zval_db);
    zval_ptr_dtor(&source_zval);

    cpClient *cli;
    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("cli"), (void **) &zres) == SUCCESS)
    {
        ZEND_FETCH_RESOURCE(cli, cpClient*, zres, -1, CP_RES_CLIENT_NAME, le_cli_connect_pool);
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "redis_connect_pool: object is not instanceof redis_connect_pool. ");
        RETURN_FALSE;
    }

    MAKE_STD_ZVAL(pass_data);
    array_init(pass_data);
    add_assoc_string(pass_data, "type", "redis", 1);
    add_assoc_string(pass_data, "method", "select", 1);
    add_assoc_string(pass_data, "data_source", source_char, 1);

    MAKE_STD_ZVAL(z_args);
    array_init(z_args);
    add_assoc_string(z_args, "db", db, 1);
    add_assoc_zval(pass_data, "args", z_args);

    int ret = cli_real_send(&cli, pass_data, getThis(), redis_connect_pool_class_entry_ptr);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "cli_real_send faild error Error: %s [%d] ", strerror(errno), errno);
    }

    cli_real_recv(&cli->info);
    if (RecvData.type == CP_SIGEVENT_EXCEPTION)
    {
        zend_throw_exception(NULL, Z_STRVAL_P(RecvData.ret_value), 0 TSRMLS_CC);
        RETVAL_BOOL(0);
    }
    else
    {
        RETVAL_ZVAL(RecvData.ret_value, 0, 1);
    }
    zval_ptr_dtor(&pass_data);
}

PHP_METHOD(redis_connect_pool, __call)
{
    zval *z_args;
    zval *pass_data;
    zval *object;
    zval **zres, **source_zval;
    char source_char[100] = {0};
    char *cmd;
    int cmd_len;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Osa", &object, redis_connect_pool_class_entry_ptr, &cmd, &cmd_len, &z_args) == FAILURE)
    {
        RETURN_FALSE;
    }

    cpClient *cli;
    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("cli"), (void **) &zres) == SUCCESS)
    {
        ZEND_FETCH_RESOURCE(cli, cpClient*, zres, -1, CP_RES_CLIENT_NAME, le_cli_connect_pool);
    }
    else
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "redis_connect_pool: object is not instanceof redis_connect_pool. ");
        RETURN_FALSE;
    }

    zval_add_ref(&z_args);
    MAKE_STD_ZVAL(pass_data);
    array_init(pass_data);
    add_assoc_string(pass_data, "method", cmd, 1);
    add_assoc_string(pass_data, "type", "redis", 1);
    add_assoc_zval(pass_data, "args", z_args);
    if (zend_hash_find(Z_OBJPROP_P(getThis()), ZEND_STRS("data_source"), (void **) &source_zval) == SUCCESS)
    {
        add_assoc_string(pass_data, "data_source", Z_STRVAL_PP(source_zval), 1);
    }
    else
    {//沒select 走db0
        zval **ip;
        if (zend_hash_find(Z_OBJPROP_P(object), ZEND_STRS("ip"), (void **) &ip) == SUCCESS)
        {
            strcat(source_char, Z_STRVAL_PP(ip));
            strcat(source_char, ":");
        }
        else
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "redis_connect_pool: IP is empty ");
            RETURN_FALSE;
        }
        zval **port;
        if (zend_hash_find(Z_OBJPROP_P(object), ZEND_STRS("port"), (void **) &port) == SUCCESS)
        {
            strcat(source_char, Z_STRVAL_PP(port));
            strcat(source_char, ":");
        }
        else
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "redis_connect_pool: PORT is empty");
            RETURN_FALSE;
        }
        strcat(source_char, "0");
        zval *definitely_source;
        MAKE_STD_ZVAL(definitely_source);
        ZVAL_STRING(definitely_source, source_char, 1);
        zend_update_property(redis_connect_pool_class_entry_ptr, object, ZEND_STRL("data_source"), definitely_source TSRMLS_CC); //确定数据源
        zval_ptr_dtor(&definitely_source);
        add_assoc_string(pass_data, "data_source", source_char, 1);
    }

    int ret = cli_real_send(&cli, pass_data, getThis(), redis_connect_pool_class_entry_ptr);
    if (ret < 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "cli_real_send faild error Error: %s [%d] ", strerror(errno), errno);
    }

    cli_real_recv(&cli->info);
    if (RecvData.type == CP_SIGEVENT_EXCEPTION)
    {
        zend_throw_exception(NULL, Z_STRVAL_P(RecvData.ret_value), 0 TSRMLS_CC);
        RETVAL_BOOL(0);
    }
    else
    {
        RETVAL_ZVAL(RecvData.ret_value, 0, 1); //no copy  destroy
    }
    zval_ptr_dtor(&pass_data);
}

PHP_FUNCTION(get_disable_list)
{
    zval *conf = NULL;
    long port;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a!l", &conf, &port) == FAILURE)
    {
        return;
    }
    if (!ptr_ping_addr)
    {
        ptr_ping_addr = &ping_addr;
        zend_hash_init(ptr_ping_addr, 10, NULL, ZVAL_PTR_DTOR, 1);
    }
    void *addr = NULL;
    if (FAILURE == zend_hash_index_find(ptr_ping_addr, port, &addr))
    {

        char ping_mm_name[CP_PING_MD5_LEN] = {0};
        sprintf(ping_mm_name, "%s_%d", CP_MMAP_NAME_PRE, 0x2526 + (int) port);
        int fd = open(ping_mm_name, O_RDWR | O_CREAT, S_IROTH | S_IWOTH);
        if (fd == -1)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "open error Error: %s [%d]", strerror(errno), errno);
        }
        ftruncate(fd, CP_PING_MD5_LEN); //extend 黑洞
        addr = mmap(NULL, CP_PING_MD5_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
#ifdef MAP_FAILED
        if (addr == MAP_FAILED)
#else
        if (!mem)
#endif
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "mmap failed: %s [%d]", strerror(errno), errno);
            RETURN_FALSE
        }
        zend_hash_index_update(ptr_ping_addr, port, addr, sizeof (void *), NULL);
    }

    zval *new_md5 = cpMD5(conf);
    if (memcmp(addr, Z_STRVAL_P(new_md5), CP_PING_MD5_LEN) == 0)
    {
        zval_ptr_dtor(&new_md5);
        zval *arr = CP_PING_GET_DIS(addr);
        if (Z_TYPE_P(arr) == IS_BOOL || Z_TYPE_P(arr) == IS_NULL)
        {
            //todo again
            array_init(return_value);
        }
        else
        {
            RETURN_ZVAL(arr, 0, 1);
        }
        zval_ptr_dtor(&arr);
    }
    else
    {
        memcpy(addr, Z_STRVAL_P(new_md5), CP_PING_MD5_LEN);
        zval_ptr_dtor(&new_md5);
        int *pid = addr + CP_PING_MD5_LEN;
        if (*pid > 0)
        {
            kill(*pid, SIGUSR1); //清空disable和probably
        }
        array_init(return_value);
    }
}


//PHP_METHOD(pdo_connect_pool, quote)
//{//todo
//	char *str;
//	int str_len;
//	long paramtype = PDO_PARAM_STR;
//	char *qstr;
//	int qlen;
//
//	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &str, &str_len, &paramtype)) {
//		RETURN_FALSE;
//	}
//	
//	RETURN_FALSE;
//}
