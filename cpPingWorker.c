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

static int cpPing_worker_loop() {
    char *buf = NULL;
    if ((buf = shmat(CPGS->ping_workers->sm_obj.shmid, NULL, 0)) < 0)
    {
        zend_error(E_ERROR, "attach sys mem error Error: %s [%d]", strerror(errno), errno);
    }
    while (1)
    {
        zval *arr = cp_unserialize(buf + CP_PING_DIS_LEN + CP_PING_MD5_LEN, CP_PING_PRO_LEN);
        if (Z_TYPE_P(arr) == IS_BOOL)
        {
            continue;
        }
        else
        {//检查probably里面是否有可以放入disable的
            for (zend_hash_internal_pointer_reset(Z_ARRVAL_P(arr)); zend_hash_has_more_elements(Z_ARRVAL_P(arr)) == SUCCESS; zend_hash_move_forward(Z_ARRVAL_P(arr)))
            {
                zval **config;
                zend_hash_get_current_data(Z_ARRVAL_P(arr), (void**) &config);
                char *name;
                int keylen;
                zend_hash_get_current_key_ex(Z_ARRVAL_P(arr), &name, &keylen, NULL, 0, NULL);
            }
            //开始检测disable中是否有恢复的
            

        }
        sleep(1);
    }


}

int cpFork_ping_worker() {
    int pid, ret;
    pid = fork();
    if (pid < 0)
    {
        cpLog("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return FAILURE;
    }
    else if (pid == 0)
    {
        //标识为worker进程
        CPGL.process_type = CP_PROCESS_PING;
        char name[MAX_TITLE_LENGTH] = {0};
        strcat(name, "ping_");
        strcat(name, CPGC.title);
        cpSettitle(name);
        ret = cpPing_worker_loop();
        exit(ret);
    }
    else
    {
        return pid;
    }
}

CPINLINE int cpCreate_ping_worker_mem() {
    cpShareMemory *sm_obj = &(CPGS->ping_workers->sm_obj);
    if (!cpShareMemory_sysv_create(sm_obj, CP_PING_MEM_LEN, 0x2526 + CPGC.port))
    {
        cpLog("create sys v shm. Error: %s [%d]", strerror(errno), errno);
        return FAILURE;
    }
    return SUCCESS;
}