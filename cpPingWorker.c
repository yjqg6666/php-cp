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

static void cpPing_add_dislist(zval *dis_arr, zval **args, char *data_source)
{

    zval *copy;
    MAKE_STD_ZVAL(copy);
    *copy = **args;
    zval_copy_ctor(copy);

    if (Z_TYPE_P(dis_arr) == IS_NULL) {
        zval first_arr;
        array_init(&first_arr);
        add_assoc_zval(&first_arr, data_source, copy);
        cp_ser_and_setdis(&first_arr);
        zval_dtor(&first_arr);
        cpLog("'%s' insert into disable list", data_source);
    } else if (Z_TYPE_P(dis_arr) != IS_BOOL) {
        zval **zval_source;
        if (zend_hash_find(Z_ARRVAL_P(dis_arr), data_source, strlen(data_source) + 1, (void **) &zval_source) == FAILURE)//SUCCESS的跳过,证明dis后继续调用这个节点了,防止重复添加
        {
            if (zend_hash_num_elements(Z_ARRVAL_P(dis_arr)) >= CPGC.max_fail_num) {
                zval_ptr_dtor(&copy);
                cpLog("the disable count exceed");
            } else {
                add_assoc_zval(dis_arr, data_source, copy);
                cp_ser_and_setdis(dis_arr);
                cpLog("'%s' insert into disable list", data_source);
            }
        } else {
            zval_ptr_dtor(&copy);
        }
    }

}

static void cpPing_del_prolist(zval *pro_arr, char *data_source)
{
    zval copy;
    copy = *pro_arr;
    zval_copy_ctor(&copy);
    zend_hash_del(Z_ARRVAL(copy), data_source, strlen(data_source) + 1);
    cp_ser_and_setpro(&copy);
    zval_dtor(&copy);
}

static void cpPingClear(int sig)
{
    bzero(CPGL.ping_mem_addr + CP_PING_MD5_LEN + CP_PING_PID_LEN, CP_PING_DIS_LEN);
}

static int cpPing_worker_loop()
{
    cpSignalSet(SIGUSR1, cpPingClear, 1, 0);
    if ((CPGL.ping_mem_addr = shmat(CPGS->ping_workers->sm_obj.shmid, NULL, 0)) < 0) {
        zend_error(E_ERROR, "attach sys mem error Error: %s [%d]", strerror(errno), errno);
    }
    bzero(CPGL.ping_mem_addr, CP_PING_MEM_LEN);
    memcpy(CPGL.ping_mem_addr + CP_PING_MD5_LEN, &CPGS->ping_workers->pid, CP_PING_PID_LEN);

    while (1) {
        sleep(1);
        zval *pro_arr = CP_PING_GET_PRO(CPGL.ping_mem_addr);
        zval *dis_arr = CP_PING_GET_DIS(CPGL.ping_mem_addr);
        if (Z_TYPE_P(pro_arr) != IS_BOOL && Z_TYPE_P(pro_arr) != IS_NULL) {
            //检查probably里面是否有可以放入disable的
            for (zend_hash_internal_pointer_reset(Z_ARRVAL_P(pro_arr)); zend_hash_has_more_elements(Z_ARRVAL_P(pro_arr)) == SUCCESS; zend_hash_move_forward(Z_ARRVAL_P(pro_arr))) {
                zval **args, **zval_count;
                zend_hash_get_current_data(Z_ARRVAL_P(pro_arr), (void**) &args);
                char *data_source;
                int keylen;
                zend_hash_get_current_key_ex(Z_ARRVAL_P(pro_arr), &data_source, &keylen, NULL, 0, NULL);
                if (zend_hash_find(Z_ARRVAL_PP(args), ZEND_STRS("count"), (void **) &zval_count) == SUCCESS) {
                    if (Z_LVAL_PP(zval_count) >= CPGC.ser_fail_hits) {//连续错n次 放入dis列表
                        cpPing_add_dislist(dis_arr, args, data_source);
                        cpPing_del_prolist(pro_arr, data_source);
                    }
                }
            }
        }
        zval_ptr_dtor(&dis_arr);

        dis_arr = CP_PING_GET_DIS(CPGL.ping_mem_addr);
        zval copy;
        copy = *dis_arr;
        zval_copy_ctor(&copy);
        if (Z_TYPE_P(dis_arr) != IS_BOOL && Z_TYPE_P(dis_arr) != IS_NULL) {
            //开始检测disable中是否有恢复的
            for (zend_hash_internal_pointer_reset(Z_ARRVAL_P(dis_arr)); zend_hash_has_more_elements(Z_ARRVAL_P(dis_arr)) == SUCCESS; zend_hash_move_forward(Z_ARRVAL_P(dis_arr))) {
                zval **args;
                zend_hash_get_current_data(Z_ARRVAL_P(dis_arr), (void**) &args);
                char *data_source;
                int keylen;
                zend_hash_get_current_key_ex(Z_ARRVAL_P(dis_arr), &data_source, &keylen, NULL, 0, NULL);
                if (strstr(data_source, "host")) {//mysql
                    if (pdo_proxy_connect(*args, CP_CONNECT_PING)) {
                        zend_hash_del(Z_ARRVAL(copy), data_source, strlen(data_source) + 1);
                        cp_ser_and_setdis(&copy);
                        cpLog("'%s' remove from disable list", data_source);
                    }
                } else {//redis
                    zval z_data_source;
                    ZVAL_STRINGL(&z_data_source, data_source, keylen, 0);
                    if (redis_proxy_connect(&z_data_source, *args, CP_CONNECT_PING)) {
                        zend_hash_del(Z_ARRVAL(copy), data_source, strlen(data_source) + 1);
                        cp_ser_and_setdis(&copy);
                        cpLog("'%s' remove from disable list", data_source);
                    }
                }
            }
        }
        zval_dtor(&copy);
        zval_ptr_dtor(&dis_arr);
        zval_ptr_dtor(&pro_arr);
    }


}

int cpFork_ping_worker()
{
    int pid, ret;
    pid = fork();
    if (pid < 0) {
        cpLog("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return FAILURE;
    } else if (pid == 0) {
        //标识为worker进程
        CPGL.process_type = CP_PROCESS_PING;
        char name[MAX_TITLE_LENGTH] = {0};
        strcat(name, "ping_");
        strcat(name, CPGC.title);
        cpSettitle(name);
        ret = cpPing_worker_loop();
        exit(ret);
    } else {
        return pid;
    }
}

CPINLINE int cpCreate_ping_worker_mem()
{
    cpShareMemory *sm_obj = &(CPGS->ping_workers->sm_obj);
    if (!cpShareMemory_sysv_create(sm_obj, CP_PING_MEM_LEN, 0x2526 + CPGC.port)) {
        cpLog("create sys v shm. Error: %s [%d]", strerror(errno), errno);
        return FAILURE;
    }
    return SUCCESS;
}