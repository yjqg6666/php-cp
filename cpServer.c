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

int static cpListen();
int static cpWriter_receive(int fd);
void static cpSignalHanlde(int sig);
void static cpSignalInit(void);
void static cpTryGetWorkerId(cpConnection *conn, char * data, int fd, int len);
int static cpReactor_client_close(int fd);
static int cpReactor_client_receive(int fd);
static int cpReactor_client_release(int fd);
static void insert_into_used();
CPINLINE int cpCreate_worker_mem(int worker_id);

void cpServer_init(zval *conf, char *title, char *ini_file, int group_id) {
    CPGS = (cpServerGS*) cp_mmap_calloc(sizeof (cpServerGS));
    if (CPGS == NULL) {
        printf("calloc[1] fail\n");
        return;
    }
    bzero(&CPGL, sizeof (cpServerG));
    CPGC.backlog = CP_BACKLOG;
    CPGC.reactor_num = CP_CPU_NUM;
    CPGC.timeout_sec = CP_REACTOR_TIMEO_SEC;
    CPGC.timeout_usec = CP_REACTOR_TIMEO_USEC;
    CPGC.max_conn = CP_MAX_FDS;
    CPGC.max_request = CP_MAX_REQUEST;
    CPGC.idel_time = CP_IDEL_TIME;
    CPGC.recycle_num = CP_RECYCLE_NUM;
    CPGC.max_read_len = CP_DEF_MAX_READ_LEN;
    CPGC.group_id = group_id;

    CPGS->worker_max = CP_MAX_WORKER;
    CPGC.worker_min = CP_MIN_WORKER;

    strcpy(CPGC.title, title);
    strcpy(CPGC.ini_file, ini_file);
    cpSettitle(title);

    zval **v;
    //daemonize，守护进程化
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("daemonize"), (void **) &v) == SUCCESS) {
        convert_to_long(*v);
        CPGC.daemonize = (int) Z_LVAL_PP(v);
    }
    //pool_max
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("pool_max"), (void **) &v) == SUCCESS) {
        convert_to_long(*v);
        CPGS->worker_max = (int) Z_LVAL_PP(v);
    }
    //pool_min
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("pool_min"), (void **) &v) == SUCCESS) {
        convert_to_long(*v);
        CPGC.worker_min = (int) Z_LVAL_PP(v);
    }

    //pool_min
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("recycle_num"), (void **) &v) == SUCCESS) {
        convert_to_long(*v);
        CPGC.recycle_num = (int) Z_LVAL_PP(v);
    }
    //error_file
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("log_file"), (void **) &v) == SUCCESS) {
        memcpy(CPGC.log_file, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
    }
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("max_read_len"), (void **) &v) == SUCCESS) {
        convert_to_long(*v);
        CPGC.max_read_len = (int) Z_LVAL_PP(v);
    }
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("port"), (void **) &v) == SUCCESS) {//todo check null
        convert_to_long(*v);
        CPGC.port = (int) Z_LVAL_PP(v);
    }

    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("idel_time"), (void **) &v) == SUCCESS) {
        convert_to_long(*v);
        CPGC.idel_time = (int) Z_LVAL_PP(v);
    }

    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("use_wait_queue"), (void **) &v) == SUCCESS) {
        convert_to_long(*v);
        CPGC.use_wait_queue = (int) Z_LVAL_PP(v);
    }
}

int cpServer_create() {
    if (CPGC.worker_min < 1 || CPGC.reactor_num < 1 || CPGC.max_read_len >= CP_MAX_READ_LEN) {
        printf("Fatal Error: worker_min < 1 or reactor_num < 1 or max_read_len >%d\n", CP_MAX_READ_LEN);
        return FAILURE;
    }

    CPGS->reactor_threads = (cpThread*) cp_mmap_calloc(CPGC.reactor_num * sizeof (cpThread));
    if (CPGS->reactor_threads == NULL) {
        cpLog("calloc[1] fail");
        return FAILURE;
    }

    CPGS->conlist = (cpConnection*) cp_mmap_calloc(CPGC.max_conn * sizeof (cpConnection));
    if (CPGS->conlist == NULL) {
        cpLog("calloc[1] fail");
        return FAILURE;
    }

    CPGS->workerfd2clientfd_list = (uint32_t*) cp_mmap_calloc(CPGC.max_conn * sizeof (uint32_t));
    if (CPGS->workerfd2clientfd_list == NULL) {
        cpLog("calloc[1] fail");
        return FAILURE;
    }

    CPGS->workers_status = (volatile_int8*) cp_mmap_calloc(sizeof (volatile_int8) * CP_GROUP_LEN);
    if (CPGS->workers_status == NULL) {
        cpLog("alloc for worker_status fail");
        return FAILURE;
    }

    CPGS->workers = (cpWorker*) cp_mmap_calloc(CP_GROUP_LEN * sizeof (cpWorker));
    if (CPGS->workers == NULL) {
        cpLog("[Main] calloc[workers] fail");
        return FAILURE;
    }

    CPGS->spin_lock = (pthread_spinlock_t*) cp_mmap_calloc(sizeof (pthread_spinlock_t));
    //worker闲忙的锁,未做兼容,只在linux用
    if (pthread_spin_init(CPGS->spin_lock, 1) < 0) {
        cpLog("pthread_spin_init error!. Error: %s [%d]", strerror(errno), errno);
        return FAILURE;
    }

    cpLog_init(CPGC.log_file);
    CPGS->running = 1;

    return SUCCESS;
}

int static cpList_create() {
    int i;
    CPGS->WaitList = CPGS->WaitTail = NULL;
    return SUCCESS;
}

int cpServer_start() {
    int i, pid, ret;
    //run as daemon
    if (CPGC.daemonize > 0) {
        if (daemon(0, 0) < 0) {
            return FAILURE;
        }
    }
    CPGS->master_pid = getpid();
    CPGL.process_type = CP_PROCESS_MASTER;
    cpList_create();

    pid = fork();
    switch (pid) {
            //创建manager进程
        case 0:
            //********************数据库坏连接检测恢复进程******************************
            //            pid = fork();
            //            if (pid < 0) {
            //                cpLog("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
            //            } else if (pid == 0) {
            ////                cpSignalSet(SIGALRM, cpManagerSignalHanlde, 1, 0);
            //            }
            //********************数据库坏连接检测恢复进程******************************
            for (i = 0; i < CPGC.worker_min; i++) {//alloc了max个 但是只启动min个
                pid = cpFork_one_worker(i);
                cpCreate_worker_mem(i);
                if (pid < 0) {
                    cpLog("Fork worker process fail");
                    return FAILURE;
                } else {
                    CPGS->workers[i].pid = pid;
                    CPGS->workers_status[i] = CP_WORKER_IDLE;
                }
            }
            //标识为管理进程
            CPGL.process_type = CP_PROCESS_MANAGER;
            CPGS->worker_num = CPGC.worker_min; //初始为min个worker
            ret = cpWorker_manager_loop();
            exit(ret);
            break;
            //主进程
        default:
            CPGS->manager_pid = pid;
            break;
        case -1:
        {
            cpLog("fork manager process fail");
            return FAILURE;
        }
    }

    cpSignalInit();
    if (cpReactor_start() < 0) {
        cpLog("Reactor_start[1] fail");
        return FAILURE;
    }
    return SUCCESS;
}

static int cpServer_master_onAccept(int fd) {
    struct sockaddr_in client_addr;
    uint32_t client_addrlen = sizeof (client_addr);
    int conn_fd, c_pti = 0, i;

    for (i = 0; i < CP_ACCEPT_MAX_COUNT; i++) {
        //accept得到连接套接字
        conn_fd = accept(fd, (struct sockaddr *) &client_addr, &client_addrlen);
        if (conn_fd < 0) {
            switch (errno) {
                case EAGAIN:
                    return SUCCESS;
                case EINTR:
                    continue;
                default:
                    cpLog("accept fail. Error: %s[%d]", strerror(errno), errno);
                    return SUCCESS;
            }
        }
        //连接过多
        if (CPGS->connect_count >= CPGC.max_conn) {
            cpLog("too many connection");
            close(conn_fd);
            return SUCCESS;
        }
        //        swSetNonBlock(conn_fd);

        int flag = 1;
        setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof (flag));
#if (defined SO_KEEPALIVE) && (defined TCP_KEEPIDLE)  
        int keepalive = 1;
        int keep_idle = CP_TCP_KEEPCOUNT;
        int keep_interval = CP_TCP_KEEPIDLE;
        int keep_count = CP_TCP_KEEPINTERVAL;

        setsockopt(conn_fd, SOL_SOCKET, SO_KEEPALIVE, (void *) &keepalive, sizeof (keepalive));
        setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPIDLE, (void*) &keep_idle, sizeof (keep_idle));
        setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *) &keep_interval, sizeof (keep_interval));
        setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPCNT, (void *) &keep_count, sizeof (keep_count));
#endif

        if (CPGC.reactor_num > 1) {
            int i, event_num = CPGS->reactor_threads[0].event_num;
            CPGS->reactor_next_i = 0;
            for (i = 1; i < CPGC.reactor_num; i++) {
                if (CPGS->reactor_threads[i].event_num < event_num) {
                    CPGS->reactor_next_i = i;
                    event_num = CPGS->reactor_threads[i].event_num;
                }
            }
            c_pti = CPGS->reactor_next_i;
        }


        cpConnection *conn = &(CPGS->conlist[conn_fd]);
        if (conn) {//不能在add后做,线程安全,防止添加到reactor后马上就读到数据,这时候下面new_connect还没执行。
            conn->release = CP_FD_RELEASED;
        }
        if (cpEpoll_add(CPGS->reactor_threads[c_pti].epfd, conn_fd, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLPRI) < 0) {
            cpLog("[Master]add event fail Errno=%d|FD=%d", errno, conn_fd);
            close(conn_fd);
            return SUCCESS;
        } else {
            CPGS->reactor_threads[c_pti].event_num++;
            conn->fd = conn_fd;
            conn->pth_id = c_pti;
            CPGS->connect_count++;
        };

        continue;
    }
    return SUCCESS;
}

CPINLINE static int MasterSend2Client(int fd, int worker_id, int CPid) {
    CPGS->workers[worker_id].fd = fd;
    cpMasterInfo info;
    int sizeinfo = sizeof (info);
    info.worker_id = CPGC.group_id * CP_GROUP_LEN + worker_id;
    info.semid = CPGS->workers[worker_id].sm_obj.shmid;
    info.max = CPGC.max_read_len;
    CPGS->workers[worker_id].CPid = CPid;
    return cpWrite(fd, &info, sizeinfo);
}

CPINLINE int cpCreate_worker_mem(int worker_id) {
    cpShareMemory *sm_obj = &(CPGS->workers[worker_id].sm_obj);
    if (!cpShareMemory_sysv_create(sm_obj, CPGC.max_read_len, 0x3526 + CPGC.port * CP_GROUP_LEN + worker_id)) {//todo check <1000
        cpLog("create sys v shm. Error: %s [%d]", strerror(errno), errno);
        return FAILURE;
    }
    return SUCCESS;
}

static void cpTryGetWorkerId(cpConnection *conn, char * data, int fd, int len) {
    if (pthread_spin_lock(CPGS->spin_lock) == 0) {
        int i;
        for (i = 0; i < CPGS->worker_num; i++) {
            if (CPGS->workers_status[i] == CP_WORKER_IDLE && i < CPGS->worker_max) {
                CPGS->workers_status[i] = CP_WORKER_BUSY;
                conn->worker_id = i;
                conn->release = CP_FD_NRELEASED;
                if (pthread_spin_unlock(CPGS->spin_lock) != 0) {
                    cpLog("pthread_spin_unlock. Error: %s [%d]", strerror(errno), errno);
                }
                return;
            }
        }
        if (CPGS->worker_num < CPGS->worker_max) {//争抢失败增加一个worker
            conn->release = CP_FD_NRELEASED;
            conn->worker_id = CPGS->worker_num;
            cpCreate_worker_mem(CPGS->worker_num);
            CPGS->workers_status[CPGS->worker_num] = CP_WORKER_BUSY; //创建后立马分配,防止第一次too many connections
            CPGS->worker_num++; //先加 线程安全
            int ret = kill(CPGS->manager_pid, SIGRTMIN);
            if (ret < 0) {
                CPGS->worker_num--; //todo 
                cpLog("send sig error. Error: %s [%d]", strerror(errno), errno);
            }
        } else if (CPGC.use_wait_queue) {
            cpWaitList *node = (cpWaitList*) emalloc(sizeof (cpWaitList) + len);
            node->fd = fd;
            node->len = len;
            node->next = NULL;
            if (CPGS->WaitList) {
                CPGS->WaitTail->next = node;
                node->pre = CPGS->WaitTail;
                CPGS->WaitTail = node;
            } else {
                node->pre = NULL;
                CPGS->WaitList = CPGS->WaitTail = node;
            }
            memcpy(node->data, data, len);
            conn->release = CP_FD_WAITING;
        }
        if (pthread_spin_unlock(CPGS->spin_lock) != 0) {
            cpLog("pthread_spin_unlock. Error: %s [%d]", strerror(errno), errno);
        }
    } else {
        cpLog("pthread_spin_lock. Error: %s [%d]", strerror(errno), errno);
    }
}

static int cpReactor_client_release(int fd) {
    cpConnection *conn = &(CPGS->conlist[fd]);
    if (conn->release == CP_FD_NRELEASED) {//防止too many cons&&重复release
        CPGS->workers[conn->worker_id].request++;
        if (pthread_spin_lock(CPGS->spin_lock) == 0) {
            if (CPGS->workers[conn->worker_id].request >= CP_MAX_REQUEST) {
                CPGS->workers[conn->worker_id].request = 0;
                CPGS->workers[conn->worker_id].run = 0;
                //                cpLog("%p ,worker %d,max %d,num %d",CPGS->WaitList,conn->worker_id,CPGS->worker_max,CPGS->worker_num);
            }
            if (CPGS->WaitList && CPGC.use_wait_queue && conn->worker_id <= CPGS->worker_max) {//wait is not null&&use queue&&use reload to reduce max maybe trigger this
                cpConnection *wait_conn = &(CPGS->conlist[CPGS->WaitList->fd]); //等待队列的连接
                wait_conn->worker_id = conn->worker_id;
                wait_conn->release = CP_FD_NRELEASED;
                conn->release = CP_FD_RELEASED;
                cpWaitList *tmp = CPGS->WaitList;
                if (CPGS->WaitList->next) {
                    CPGS->WaitList = CPGS->WaitList->next;
                    CPGS->WaitList->pre = NULL;
                } else {
                    CPGS->WaitList = CPGS->WaitTail = NULL;
                }
                cpTcpEvent *wait_event = (cpTcpEvent*) tmp->data;
                if (MasterSend2Client(wait_conn->fd, wait_conn->worker_id, wait_event->ClientPid) < 0) {
                    cpLog("Write in cpReactor_client_release. Error: %s [%d]", strerror(errno), errno);
                }
                efree(tmp);
            } else {
                CPGS->workers_status[conn->worker_id] = CP_WORKER_IDLE;
                conn->release = CP_FD_RELEASED;
            }
            if (pthread_spin_unlock(CPGS->spin_lock) != 0) {
                cpLog("pthread_spin_unlock. Error: %s [%d]", strerror(errno), errno);
            }
        }
    } else if (conn->release == CP_FD_WAITING) {//在队列里面,没等到分配就结束进程了,从queue里面删除
        if (pthread_spin_lock(CPGS->spin_lock) == 0) {
            cpWaitList *p = CPGS->WaitList;
            while (p) {
                if (p->fd == fd) {
                    if (p == CPGS->WaitList) {
                        if (p->next) {
                            p->next->pre = NULL;
                            CPGS->WaitList = p->next;
                        } else {//only one
                            CPGS->WaitList = CPGS->WaitTail = NULL;
                        }
                    } else if (p == CPGS->WaitTail) {
                        p->pre->next = NULL;
                        CPGS->WaitTail = p->pre;
                    } else {
                        p->pre->next = p->next;
                        p->next->pre = p->pre;
                    }
                    efree(p);
                    break;
                }
                p = p->next;
            }
            conn->release = CP_FD_RELEASED;
            if (pthread_spin_unlock(CPGS->spin_lock) != 0) {
                cpLog("pthread_spin_unlock. Error: %s [%d]", strerror(errno), errno);
            }
            cpLog("The fd %d is closed and remove from the queue but no conn dispatch , maybe have slow query", fd);
        }
    }

    return SUCCESS;

}

static int cpReactor_client_close(int fd) {//长连接 相当于mshutdown
    cpReactor_client_release(fd);
    cpConnection *conn = &(CPGS->conlist[fd]);
    //关闭连接
    cpEpoll_del(CPGS->reactor_threads[conn->pth_id].epfd, fd);
    (CPGS->reactor_threads[conn->pth_id].event_num <= 0) ? CPGS->reactor_threads[conn->pth_id].event_num = 0 : CPGS->reactor_threads[conn->pth_id].event_num--;
    CPGS->connect_count--;

    return SUCCESS;
}

static int cpReactor_client_receive(int fd) {
    int n;
    int event_size = sizeof (cpTcpEvent);
    char data[event_size];
    //非ET模式会持续通知
    n = cpNetRead(fd, data, event_size);

    cpConnection *conn = &(CPGS->conlist[fd]);
    if (n > 0) {
        cpTcpEvent *event = (cpTcpEvent*) data;
        if (event->type == CP_TCPEVENT_RELEASE) {
            return cpReactor_client_release(fd);
        }
        if (conn->release == CP_FD_RELEASED) {//之前释放了,或者刚进来的连接,需要争抢(这个状态不需要加锁,每个con的fd只分配给一个线程)
            cpTryGetWorkerId(conn, data, fd, n);
            if (conn->release == CP_FD_WAITING) {
                return 1;
            }
            if (conn->release == CP_FD_RELEASED) {//争抢失败,fork失败
                char tmp[sizeof (CP_TOO_MANY_CON_ERR) + sizeof (CP_CLIENT_EOF_STR)] = {CP_TOO_MANY_CON_ERR};
                strcat(tmp, CP_CLIENT_EOF_STR);
                return cpWrite(fd, tmp, strlen(tmp));
            }
        }
        return MasterSend2Client(fd, conn->worker_id, event->ClientPid);
    } else if (n == 0) {
close_fd:
        return cpReactor_client_close(fd);
    } else {//需要检测errno来区分是EAGAIN还是ECONNRESET
        if (errno == EAGAIN) {
            return SUCCESS;
        } else if (errno == ECONNRESET) {
            goto close_fd;
        } else {
            cpLog("Read from socket[%d] fail. Error: %s [%d]", fd, strerror(errno), errno);
            return SUCCESS;
        }
    }
    return SUCCESS;
}

int static cpReactor_thread_loop(int *id) {

    struct timeval timeo;
    timeo.tv_sec = CP_REACTOR_TIMEO_SEC;
    timeo.tv_usec = CP_REACTOR_TIMEO_USEC;

    swSingalNone();

    int epfd = epoll_create(512); //这个参数没用
    CPGS->reactor_threads[*id].epfd = epfd;

    epoll_wait_handle handles[CP_MAX_EVENT];
    handles[EPOLLIN] = cpReactor_client_receive;
    handles[EPOLLPRI] = cpReactor_client_release;
    handles[EPOLL_CLOSE] = cpReactor_client_close;

    cpEpoll_wait(handles, &timeo, epfd);

    free(id);
    pthread_exit(*id);
    return SUCCESS;
}

int cpReactor_start() {
    int sock, i;
    if ((sock = cpListen()) < 0) {
        cpLog("listen[1] fail");
        return FAILURE;
    }

    int accept_epfd = epoll_create(512); //这个参数没用
    if (cpEpoll_add(accept_epfd, sock, EPOLLIN) < 0) {
        return FAILURE;
    };

    pid_init();
    set_pid(CPGS->master_pid);

    struct timeval timeo;
    timeo.tv_sec = CP_REACTOR_TIMEO_SEC;
    timeo.tv_usec = CP_REACTOR_TIMEO_USEC;
    pthread_t pidt;
    for (i = 0; i < CPGC.reactor_num; i++) {
        int *index = (int*) malloc(sizeof (int));
        *index = i;
        if (pthread_create(&pidt, NULL, (void * (*)(void *)) cpReactor_thread_loop, (void *) index) < 0) {
            cpLog("pthread_create[tcp_reactor] fail");
        }
        pthread_detach(pidt);
        CPGS->reactor_threads[i].thread_id = pidt;
    }
    epoll_wait_handle handles[CP_MAX_EVENT];
    handles[EPOLLIN] = cpServer_master_onAccept;

    usleep(50000);
    cpLog("start %s success", CPGC.title);
    return cpEpoll_wait(handles, &timeo, accept_epfd);
}

int static cpListen() {
    int sock;
    int option;
    int ret;

    struct sockaddr_in addr_in4;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cpLog("swSocket_listen: Create socket fail.Errno=%d", errno);
        return FAILURE;
    }
    option = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof (int));

    bzero(&addr_in4, sizeof (addr_in4));
    inet_pton(AF_INET, "127.0.0.1", &(addr_in4.sin_addr));
    addr_in4.sin_port = htons(CPGC.port);
    addr_in4.sin_family = AF_INET;
    ret = bind(sock, (struct sockaddr *) &addr_in4, sizeof (addr_in4));

    if (ret < 0) {
        cpLog("Bind fail.port=%d. Error: %s [%d]", CPGC.port, strerror(errno), errno);
        return FAILURE;
    }
    //开始监听套接字
    ret = listen(sock, CPGC.backlog);
    if (ret < 0) {
        cpLog("Listen fail.port=%d. Error: %s [%d]", CPGC.port, strerror(errno), errno);
        return FAILURE;
    }
    swSetNonBlock(sock);

    if (sock < 0) {
        return FAILURE;
    }
    int bufsize = CP_UNSOCK_BUFSIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof (bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof (bufsize));
    return sock;
}

static void cpSignalHanlde(int sig) {
    switch (sig) {
        case SIGTERM:
            cpLog("stop %s", CPGC.title);
            CPGS->running = 0;
            int i = 0;
            for (; i < CPGS->worker_num; i++) {
                int ret = kill(CPGS->workers[i].pid, SIGKILL);
                if (ret == -1) {
                    cpLog("kill failed, id=%d. Error: %s [%d]", i, strerror(errno), errno);
                }
            }
            exit(1);
            break;
        case SIGUSR1:
            cpLog("reload %s", CPGC.title);
            int ret = kill(CPGS->manager_pid, SIGUSR1);
            if (ret == -1) {
                cpLog("reload failed, id=%d. Error: %s [%d]", i, strerror(errno), errno);
            }
            break;
        default:
            break;
    }
}

void static cpSignalInit(void) {
    cpSignalSet(SIGHUP, SIG_IGN, 1, 0);
    cpSignalSet(SIGPIPE, SIG_IGN, 1, 0);
    cpSignalSet(SIGUSR1, cpSignalHanlde, 1, 0);
    cpSignalSet(SIGUSR2, SIG_IGN, 1, 0);
    cpSignalSet(SIGTERM, cpSignalHanlde, 1, 0);
}
