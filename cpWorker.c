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
#include <signal.h>
#include <sys/wait.h>

static void cpManagerSignalHanlde(int sig);

static int cpWorker_loop(int worker_id) {
    CPWG.id = worker_id;
    char fifo_name[CP_FIFO_NAME_LEN] = {0};
    sprintf(fifo_name, "%s_%d", CP_FIFO_NAME_PRE, CPGC.group_id * CP_GROUP_LEN + worker_id); //client 2 worker
    int pipe_fd_read = cpCreateFifo(fifo_name);

    sprintf(fifo_name, "%s_%d_1", CP_FIFO_NAME_PRE, CPGC.group_id * CP_GROUP_LEN + worker_id); //worker 2 client
    int pipe_fd_write = cpCreateFifo(fifo_name);
    CPGS->workers[worker_id].pipe_fd_write = pipe_fd_write;
    cpShareMemory *sm_obj = &(CPGS->workers[worker_id].sm_obj);

    cpWorkerInfo event;
    bzero(&event, sizeof (event));
    int ret, len = 0;
    int event_len = sizeof (event);
    while (CPGS->running) {
        zval *ret_value;
        ALLOC_INIT_ZVAL(ret_value);
        if (CPGS->workers[worker_id].pre_len) {
            len = CPGS->workers[worker_id].pre_len;
            CPGS->workers[worker_id].pre_len = 0;
        } else {
            ret = cpFifoRead(pipe_fd_read, &event, event_len);
            if (!CPGS->workers[worker_id].run) {
                CPGS->workers[worker_id].pre_len = event.len; //啊~~我要挂了,赶紧存起来 下次再用
                break;
            }
            len = event.len;
        }
        if (sm_obj->mem == NULL) {
            if ((sm_obj->mem = shmat(sm_obj->shmid, NULL, 0)) < 0) {
                cpLog("attach sys mem error Error: %s [%d]", strerror(errno), errno);
            }
        }
        if (ret < 0) {
            cpLog("fifo read Error: %s [%d]", strerror(errno), errno);
        }
        php_msgpack_unserialize(ret_value, sm_obj->mem, len);
        CPWG.clientPid = event.pid;
        worker_onReceive(ret_value);
    }
    return SUCCESS;
}

int cpFork_one_worker(int worker_id) {
    int pid, ret;
    pid = fork();
    if (pid < 0) {
        cpLog("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return FAILURE;
    } else if (pid == 0) {
        //标识为worker进程
        CPGL.process_type = CP_PROCESS_WORKER;
        CPGS->workers[worker_id].run = 1;
        ret = cpWorker_loop(worker_id);
        exit(ret);
    } else {
        return pid;
    }
}

static void cpManagerRecycle(int sig) {
    int i, recycle_num = 0;
    if (pthread_spin_trylock(CPGS->spin_lock) == 0) {
        //                        for (i = CPGS->worker_num - 1; i >= 0; i--) {
        //                            cpLog("index is %d,pid is %d,status is %d", i, CPGS->workers[i].pid, CPGS->workers_status[i]);
        //                        }
        for (i = CPGS->worker_num - 1; i >= CPGC.worker_min; i--) {
            if (CPGS->workers_status[i] == CP_WORKER_BUSY) {//已经busy了就退出,否则会有跳号bug
                break;
            }
            if (CPGS->workers[i].pid == 0) {//争抢的时候就++了 所以会出现0的情况
                continue;
            }
            if (CPGS->workers_status[i] == CP_WORKER_IDLE) {//当前worker数大于最小 并且空闲
                int ret = kill(CPGS->workers[i].pid, SIGTERM);
                if (ret == -1) {
                    cpLog("[Manager]kill failed, id=%d. Error: %s [%d]", i, strerror(errno), errno);
                } else {
                    CPGS->worker_num--;
                    CPGS->workers_status[i] = CP_WORKER_DEL;
                    CPGS->workers[i].pid = 0;
                    cpShareMemory *sm_obj = &(CPGS->workers[i].sm_obj);
                    sm_obj->mem = NULL;
                    if (++recycle_num >= CPGC.recycle_num) {
                        break; //一个一个回收
                    }
                }
            }
        }
        if (pthread_spin_unlock(CPGS->spin_lock) != 0) {
            cpLog("pthread_spin_unlock. Error: %s [%d]", strerror(errno), errno);
        }
    }
    alarm(CPGC.idel_time);
}

static void cpManagerAdd(int sig) {
    int i;
    for (i = CPGS->worker_num - 1; i >= CPGC.worker_min; i--) {
        if (CPGS->workers[i].pid == 0) {//只创建刚分配并且pid为0的
            int new_pid = cpFork_one_worker(i);
            if (new_pid < 0) {
                //                        CPGS->workers[i].pid = -1;//todo fork失敗的處理
                cpLog("Fork worker process failed. Error: %s [%d]", strerror(errno), errno);
            } else {
                CPGS->workers[i].pid = new_pid;
            }
        }
    }
}

static void cpManagerReload(int sig) {
    zval *group_conf = NULL;
    group_conf = cpGetConfig(CPGC.ini_file);
    if (!Z_BVAL_P(group_conf)) {
        cpLog("parse ini file[%s] error,%s reload error!", CPGC.ini_file, CPGC.title);
    } else {
        zval **v, **conf;
        if (zend_hash_find(Z_ARRVAL_P(group_conf), CPGC.title, strlen(CPGC.title) + 1, (void **) &conf) == SUCCESS) {
            if (zend_hash_find(Z_ARRVAL_PP(conf), ZEND_STRS("pool_max"), (void **) &v) == SUCCESS) {
                convert_to_long(*v);
                CPGS->worker_max = (int) Z_LVAL_PP(v);
            }
            if (zend_hash_find(Z_ARRVAL_PP(conf), ZEND_STRS("pool_min"), (void **) &v) == SUCCESS) {
                convert_to_long(*v);
                CPGC.worker_min = (int) Z_LVAL_PP(v);
            }
            if (zend_hash_find(Z_ARRVAL_PP(conf), ZEND_STRS("recycle_num"), (void **) &v) == SUCCESS) {
                convert_to_long(*v);
                CPGC.recycle_num = (int) Z_LVAL_PP(v);
            }
            if (zend_hash_find(Z_ARRVAL_PP(conf), ZEND_STRS("idel_time"), (void **) &v) == SUCCESS) {
                convert_to_long(*v);
                CPGC.idel_time = (int) Z_LVAL_PP(v);
            }
        } else {
            cpLog("find %s failed,The reload can only modify 'pool_min','pool_max','recycle_num' and 'idel_time',if you want modify other options please restart pool", CPGC.title);
        }
        zval_ptr_dtor(&group_conf);
    }
}

int cpWorker_manager_loop() {
    int pid, new_pid;
    int i;
    int worker_exit_code;

    //reload config
    cpSignalSet(SIGUSR1, cpManagerReload, 1, 0);
    //close worker
    cpSignalSet(SIGALRM, cpManagerRecycle, 1, 0);
    //add one worker
    cpSignalSet(SIGRTMIN, cpManagerAdd, 1, 0);

    alarm(2);
    sigset_t block_alarm;
    sigemptyset(&block_alarm);
    sigaddset(&block_alarm, SIGALRM);
    sigaddset(&block_alarm, SIGRTMIN);
    sigaddset(&block_alarm, SIGUSR1);

    while (CPGS->running == 1) {
        pid = wait(&worker_exit_code);
        sigprocmask(SIG_BLOCK, &block_alarm, NULL);
        if (CPGS->running == 1 && pid > 0) {
            for (i = CPGS->worker_num; i >= 0; i--) {
                if (pid != CPGS->workers[i].pid || CPGS->workers_status[i] == CP_WORKER_DEL) {//对比pid||回收的不拉起
                    continue;
                } else {
                    if (CPGS->workers[i].run == 0) {
                        cpLog("restart worker!worker index %d,worker id %d,exit code %d\n", i, pid, WEXITSTATUS(worker_exit_code));
                    } else {
                        cpLog("worker exit!worker index %d,worker id %d,exit code %d\n", i, pid, WEXITSTATUS(worker_exit_code));
                    }
                    cpShareMemory *sm_obj = &(CPGS->workers[i].sm_obj);
                    sm_obj->mem = NULL;
                    pid = 0;
                    new_pid = cpFork_one_worker(i);
                    if (new_pid < 0) {
                        cpLog("Fork worker process failed. Error: %s [%d]", strerror(errno), errno);
                        sigprocmask(SIG_UNBLOCK, &block_alarm, NULL);
                        return FAILURE;
                    } else {
                        CPGS->workers[i].pid = new_pid;
                    }
                }
            }
        }
        sigprocmask(SIG_UNBLOCK, &block_alarm, NULL);
    }
    return SUCCESS;
}