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
void static cpSignalHanlde(int sig);
void static cpSignalInit(void);
void static cpTryGetWorkerId(cpConnection *conn, char * data, int fd, int len, int group_id);
int static cpReactor_client_close(int fd);
static int cpReactor_client_receive(int fd);
static int cpReactor_client_release(int fd);
static int cpReactor_start(int sock);

void cpServer_init_common(zval *conf)
{
    zval **v;
    //daemonize，守护进程化
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("daemonize"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        CPGC.daemonize = (int) Z_LVAL_PP(v);
    }

    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("recycle_num"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        CPGC.recycle_num = (int) Z_LVAL_PP(v);
    }
    //error_file
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("log_file"), (void **) &v) == SUCCESS)
    {
        memcpy(CPGC.log_file, Z_STRVAL_PP(v), Z_STRLEN_PP(v));
    }
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("max_read_len"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        CPGC.max_read_len = (int) Z_LVAL_PP(v);
    }
    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("port"), (void **) &v) == SUCCESS)
    {//todo check null
        convert_to_long(*v);
        CPGC.port = (int) Z_LVAL_PP(v);
    }

    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("idel_time"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        CPGC.idel_time = (int) Z_LVAL_PP(v);
    }

    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("use_wait_queue"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        CPGC.use_wait_queue = (int) Z_LVAL_PP(v);
    }

    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("ser_fail_hits"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        CPGC.ser_fail_hits = (int) Z_LVAL_PP(v);
    }

    if (zend_hash_find(Z_ARRVAL_P(conf), ZEND_STRS("max_fail_num"), (void **) &v) == SUCCESS)
    {
        convert_to_long(*v);
        CPGC.max_fail_num = (int) Z_LVAL_PP(v);
    }
}

void cpServer_init(zval *conf, char *ini_file)
{
    size_t group_num = 0;
    CPGS = (cpServerGS*) cp_mmap_calloc(sizeof (cpServerGS));
    if (CPGS == NULL)
    {
        php_printf("calloc[1] fail\n");
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
    CPGC.ser_fail_hits = 1;
    CPGC.max_fail_num = 2;

    strcpy(CPGC.ini_file, ini_file);
    MAKE_STD_ZVAL(CPGS->group);
    array_init(CPGS->group);

    for (zend_hash_internal_pointer_reset(Z_ARRVAL_P(conf)); zend_hash_has_more_elements(Z_ARRVAL_P(conf)) == SUCCESS; zend_hash_move_forward(Z_ARRVAL_P(conf)))
    {
        zval **config;
        zend_hash_get_current_data(Z_ARRVAL_P(conf), (void**) &config);
        char *name;
        uint keylen;
        zend_hash_get_current_key_ex(Z_ARRVAL_P(conf), &name, &keylen, NULL, 0, NULL);
        if (strcmp(name, "common") == 0)
        {//common config
            cpServer_init_common(*config);
        }
        else
        {
            zval **v;
            add_assoc_long(CPGS->group, name, group_num);
            strcpy(CPGS->G[group_num].name, name);
            if (zend_hash_find(Z_ARRVAL_PP(config), ZEND_STRS("pool_min"), (void **) &v) == SUCCESS)
            {
                convert_to_long(*v);
                CPGS->G[group_num].worker_num = CPGS->G[group_num].worker_min = Z_LVAL_PP(v);
            }
            if (zend_hash_find(Z_ARRVAL_PP(config), ZEND_STRS("pool_max"), (void **) &v) == SUCCESS)
            {
                convert_to_long(*v);
                CPGS->G[group_num].worker_max = Z_LVAL_PP(v);
            }

            CPGS->G[group_num].workers_status = (volatile_int8*) cp_mmap_calloc(sizeof (volatile_int8) * CP_GROUP_LEN);
            if (CPGS->G[group_num].workers_status == NULL)
            {
                cpLog("alloc for worker_status fail");
                return;
            }

            CPGS->G[group_num].workers = (cpWorker*) cp_mmap_calloc(CP_GROUP_LEN * sizeof (cpWorker));
            if (CPGS->G[group_num].workers == NULL)
            {
                cpLog("[Main] calloc[workers] fail");
                return;
            }

            pthread_mutexattr_t attr;
            pthread_mutexattr_init(&attr);
            pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
            CPGS->G[group_num].mutex_lock = (pthread_mutex_t*) cp_mmap_calloc(sizeof (pthread_mutex_t));
            if (pthread_mutex_init(CPGS->G[group_num].mutex_lock, &attr) < 0)
            {
                cpLog("pthread_mutex_init error!. Error: %s [%d]", strerror(errno), errno);
                return;
            }
            CPGS->G[group_num].WaitList = CPGS->G[group_num].WaitTail = NULL;
            CPGS->group_num++;
            group_num++;
        }
    }
}

int cpServer_create()
{
    if (CPGC.reactor_num < 1 || CPGC.max_read_len >= CP_MAX_READ_LEN)
    {
        php_printf("reactor_num < 1 or max_read_len >%d\n", CP_MAX_READ_LEN);
        return FAILURE;
    }

    if (CPGC.ser_fail_hits < 1 || CPGC.max_fail_num < 1)
    {
        php_printf("ping server conf error\n");
        return FAILURE;
    }

    cpLog_init(CPGC.log_file);
    CPGS->reactor_threads = (cpThread*) cp_mmap_calloc(CPGC.reactor_num * sizeof (cpThread));
    if (CPGS->reactor_threads == NULL)
    {
        cpLog("calloc[1] fail");
        return FAILURE;
    }

    CPGS->conlist = (cpConnection*) cp_mmap_calloc(CPGC.max_conn * sizeof (cpConnection));
    if (CPGS->conlist == NULL)
    {
        cpLog("calloc[1] fail");
        return FAILURE;
    }

    CPGS->workerfd2clientfd_list = (uint32_t*) cp_mmap_calloc(CPGC.max_conn * sizeof (uint32_t));
    if (CPGS->workerfd2clientfd_list == NULL)
    {
        cpLog("calloc[1] fail");
        return FAILURE;
    }

    CPGS->ping_workers = (cpWorker*) cp_mmap_calloc(sizeof (cpWorker));
    if (CPGS->ping_workers == NULL)
    {
        cpLog("[Main] calloc[ping_workers] fail");
        return FAILURE;
    }

    CPGS->running = 1;

    return SUCCESS;
}

int cpServer_start()
{
    int w, pid, ret, sock, g;
    if (CPGC.daemonize > 0)
    {
        if (daemon(0, 0) < 0)
        {
            return FAILURE;
        }
    }
    if ((sock = cpListen()) < 0)
    {
        cpLog("listen[1] fail");
        return FAILURE;
    }

    CPGS->master_pid = getpid();
    CPGL.process_type = CP_PROCESS_MASTER;

    pid = fork();
    switch (pid)
    {
            //创建manager进程
        case 0:
            for (g = 0; g < CPGS->group_num; g++)
            {
                for (w = 0; w < CPGS->G[g].worker_min; w++)
                {
                    //alloc了max个 但是只启动min个
                    ret = cpCreate_worker_mem(w, g);
                    pid = cpFork_one_worker(w, g);
                    if (pid < 0 || ret < 0)
                    {
                        cpLog("Fork worker process fail");
                        return FAILURE;
                    }
                    else
                    {
                        CPGS->G[g].workers[w].pid = pid;
                        CPGS->G[g].workers_status[w] = CP_WORKER_IDLE;
                    }
                }
            }

            //数据库坏连接检测恢复进程
            //            ret = cpCreate_ping_worker_mem();
            //            ping_pid = cpFork_ping_worker();
            //            if (ping_pid < 0 || ret < 0)
            //            {
            //                cpLog("Fork ping  process fail");
            //                return FAILURE;
            //            }
            //            CPGS->ping_workers->pid = ping_pid;

            //标识为管理进程
            CPGL.process_type = CP_PROCESS_MANAGER;
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
    if (cpReactor_start(sock) < 0)
    {
        cpLog("Reactor_start[1] fail");
        return FAILURE;
    }
    return SUCCESS;
}

static int cpServer_master_onAccept(int fd)
{
    struct sockaddr_in client_addr;
    uint32_t client_addrlen = sizeof (client_addr);
    int conn_fd, c_pti = 0, i;

    for (i = 0; i < CP_ACCEPT_MAX_COUNT; i++)
    {
        //accept得到连接套接字
        conn_fd = accept(fd, (struct sockaddr *) &client_addr, &client_addrlen);
        if (conn_fd < 0)
        {
            switch (errno)
            {
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
        if (CPGS->connect_count >= CPGC.max_conn)
        {
            cpLog("too many connection");
            close(conn_fd);
            return SUCCESS;
        }

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

        if (CPGC.reactor_num > 1)
        {
            int i, event_num = CPGS->reactor_threads[0].event_num;
            CPGS->reactor_next_i = 0;
            for (i = 1; i < CPGC.reactor_num; i++)
            {
                if (CPGS->reactor_threads[i].event_num < event_num)
                {
                    CPGS->reactor_next_i = i;
                    event_num = CPGS->reactor_threads[i].event_num;
                }
            }
            c_pti = CPGS->reactor_next_i;
        }


        cpConnection *conn = &(CPGS->conlist[conn_fd]);
        if (conn)
        {//不能在add后做,线程安全,防止添加到reactor后马上就读到数据,这时候下面new_connect还没执行。
            conn->release = CP_FD_RELEASED;
        }
        if (cpEpoll_add(CPGS->reactor_threads[c_pti].epfd, conn_fd, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLPRI) < 0)
        {
            cpLog("[Master]add event fail Errno=%d|FD=%d", errno, conn_fd);
            close(conn_fd);
            return SUCCESS;
        }
        else
        {
            CPGS->reactor_threads[c_pti].event_num++;
            conn->fd = conn_fd;
            conn->pth_id = c_pti;
            CPGS->connect_count++;
        };

        continue;
    }
    return SUCCESS;
}

CPINLINE static int MasterSend2Client(int fd, int worker_id, int CPid, int group_id)
{
    CPGS->G[group_id].workers[worker_id].fd = fd;
    cpMasterInfo info;
    int sizeinfo = sizeof (info);
    info.worker_id = group_id * CP_GROUP_LEN + worker_id;
    strcpy(info.mmap_name, CPGS->G[group_id].workers[worker_id].sm_obj.mmap_name);
    info.ping_pid = CPGS->ping_workers->pid;
    info.max = CPGC.max_read_len;
    CPGS->G[group_id].workers[worker_id].CPid = CPid;
    return cpWrite(fd, &info, sizeinfo);
}

static void cpTryGetWorkerId(cpConnection *conn, char * data, int fd, int len, int group_id)
{
    cpGroup *G = &CPGS->G[group_id];
    if (pthread_mutex_lock(G->mutex_lock) == 0)
    {
        int i;
        for (i = 0; i < G->worker_num; i++)
        {
            if (G->workers_status[i] == CP_WORKER_IDLE && i < G->worker_max)
            {
                G->workers_status[i] = CP_WORKER_BUSY;
                conn->worker_id = i;
                conn->group_id = group_id;
                conn->release = CP_FD_NRELEASED;
                if (pthread_mutex_unlock(G->mutex_lock) != 0)
                {
                    cpLog("pthread_mutex_unlock. Error: %s [%d]", strerror(errno), errno);
                }
                return;
            }
        }
        if (G->worker_num < G->worker_max)
        {//争抢失败增加一个worker
            conn->release = CP_FD_NRELEASED;
            conn->worker_id = G->worker_num;
            conn->group_id = group_id;
            cpCreate_worker_mem(G->worker_num, group_id);
            G->workers_status[G->worker_num] = CP_WORKER_BUSY; //创建后立马分配,防止第一次too many connections
            G->worker_num++; //先加 线程安全
            int ret = kill(CPGS->manager_pid, SIGRTMIN);
            if (ret < 0)
            {
                G->worker_num--; //todo 
                cpLog("send sig error. Error: %s [%d]", strerror(errno), errno);
            }
        }
        else if (CPGC.use_wait_queue)
        {
            cpWaitList *node = (cpWaitList*) emalloc(sizeof (cpWaitList) + len);
            node->fd = fd;
            node->len = len;
            node->next = NULL;
            if (G->WaitList)
            {
                G->WaitTail->next = node;
                node->pre = G->WaitTail;
                G->WaitTail = node;
            }
            else
            {
                node->pre = NULL;
                G->WaitList = G->WaitTail = node;
            }
            memcpy(node->data, data, len);
            conn->release = CP_FD_WAITING;
        }
        if (pthread_mutex_unlock(G->mutex_lock) != 0)
        {
            cpLog("pthread_mutex_unlock. Error: %s [%d]", strerror(errno), errno);
        }
    }
    else
    {
        cpLog("pthread_spin_lock. Error: %s [%d]", strerror(errno), errno);
    }
}

static int cpReactor_client_release(int fd)
{
    cpConnection *conn = &(CPGS->conlist[fd]);
    cpGroup *G = &CPGS->G[conn->group_id];
    if (conn->release == CP_FD_NRELEASED)
    {//防止too many cons&&重复release
        if (pthread_mutex_lock(G->mutex_lock) == 0)
        {
            if (G->WaitList && CPGC.use_wait_queue && conn->worker_id <= G->worker_max)
            {//wait is not null&&use queue&&use reload to reduce max maybe trigger this
                cpConnection *wait_conn = &(CPGS->conlist[G->WaitList->fd]); //等待队列的连接
                wait_conn->worker_id = conn->worker_id;
                wait_conn->group_id = conn->group_id;
                wait_conn->release = CP_FD_NRELEASED;
                conn->release = CP_FD_RELEASED;
                cpWaitList *tmp = G->WaitList;
                if (G->WaitList->next)
                {
                    G->WaitList = G->WaitList->next;
                    G->WaitList->pre = NULL;
                }
                else
                {
                    G->WaitList = G->WaitTail = NULL;
                }
                cpTcpEvent *wait_event = (cpTcpEvent*) tmp->data;
                if (MasterSend2Client(wait_conn->fd, wait_conn->worker_id, wait_event->ClientPid, wait_conn->group_id) < 0)
                {
                    cpLog("Write in cpReactor_client_release. Error: %s [%d]", strerror(errno), errno);
                }
                efree(tmp);
            }
            else
            {
                G->workers_status[conn->worker_id] = CP_WORKER_IDLE;
                conn->release = CP_FD_RELEASED;
            }
            if (pthread_mutex_unlock(G->mutex_lock) != 0)
            {
                cpLog("pthread_spin_unlock. Error: %s [%d]", strerror(errno), errno);
            }
        }
    }
    else if (conn->release == CP_FD_WAITING)
    {//在队列里面,没等到分配就结束进程了,从queue里面删除
        if (pthread_mutex_lock(G->mutex_lock) == 0)
        {
            cpWaitList *p = G->WaitList;
            while (p)
            {
                if (p->fd == fd)
                {
                    if (p == G->WaitList)
                    {
                        if (p->next)
                        {
                            p->next->pre = NULL;
                            G->WaitList = p->next;
                        }
                        else
                        {//only one
                            G->WaitList = G->WaitTail = NULL;
                        }
                    }
                    else if (p == G->WaitTail)
                    {
                        p->pre->next = NULL;
                        G->WaitTail = p->pre;
                    }
                    else
                    {
                        p->pre->next = p->next;
                        p->next->pre = p->pre;
                    }
                    efree(p);
                    break;
                }
                p = p->next;
            }
            conn->release = CP_FD_RELEASED;
            if (pthread_mutex_unlock(G->mutex_lock) != 0)
            {
                cpLog("pthread_spin_unlock. Error: %s [%d]", strerror(errno), errno);
            }
            cpLog("The fd %d is closed and remove from the queue but no conn dispatch , maybe have slow query", fd);
        }
    }

    return SUCCESS;

}

static int cpReactor_client_close(int fd)
{//长连接 相当于mshutdown
    cpReactor_client_release(fd);
    cpConnection *conn = &(CPGS->conlist[fd]);
    //关闭连接
    cpEpoll_del(CPGS->reactor_threads[conn->pth_id].epfd, fd);
    (CPGS->reactor_threads[conn->pth_id].event_num <= 0) ? CPGS->reactor_threads[conn->pth_id].event_num = 0 : CPGS->reactor_threads[conn->pth_id].event_num--;
    CPGS->connect_count--;

    return SUCCESS;
}

static int cpReactor_client_receive(int fd)
{
    int event_size = sizeof (cpTcpEvent), n, gid;
    char data[event_size];
    zval **gid_ptr;
    //非ET模式会持续通知
    n = cpNetRead(fd, data, event_size);

    cpConnection *conn = &(CPGS->conlist[fd]);
    if (n > 0)
    {
        cpTcpEvent *event = (cpTcpEvent*) data;
        if (event->type == CP_TCPEVENT_GET && conn->release == CP_FD_NRELEASED)
        {
            //动作是获得连接但是状态是未释放，父进程连的然后在子进程和父进程中都用这个连接，会出现这种情况
            cpMasterInfo info;
            int sizeinfo = sizeof (info);
            info.worker_id = -1; //todo define it
            return cpWrite(fd, &info, sizeinfo);
        }
        if (event->type == CP_TCPEVENT_RELEASE)
        {
            return cpReactor_client_release(fd);
        }
        if (conn->release == CP_FD_RELEASED)
        {//之前释放了,或者刚进来的连接,需要争抢(这个状态不需要加锁,每个con的fd只分配给一个线程)
            if (zend_hash_find(Z_ARRVAL_P(CPGS->group), event->data_source, strlen(event->data_source) + 1, (void **) &gid_ptr) == SUCCESS)
            {
                gid = Z_LVAL_PP(gid_ptr);
            }
            else
            {
                cpLog("can not find the datasource %s from the ini", event->data_source);
                return FAILURE;
            }
            cpTryGetWorkerId(conn, data, fd, n, gid);
            if (conn->release == CP_FD_WAITING)
            {
                return SUCCESS;
            }
            if (conn->release == CP_FD_RELEASED)
            {//争抢失败,fork失败
                char tmp[sizeof (CP_TOO_MANY_CON_ERR) + sizeof (CP_CLIENT_EOF_STR)] = {CP_TOO_MANY_CON_ERR};
                strcat(tmp, CP_CLIENT_EOF_STR);
                return cpWrite(fd, tmp, strlen(tmp));
            }
            return MasterSend2Client(fd, conn->worker_id, event->ClientPid, gid);
        }
    }
    else if (n == 0)
    {
close_fd:
        return cpReactor_client_close(fd);
    }
    else
    {//需要检测errno来区分是EAGAIN还是ECONNRESET
        if (errno == EAGAIN)
        {
            return SUCCESS;
        }
        else if (errno == ECONNRESET)
        {
            goto close_fd;
        }
        else
        {
            cpLog("Read from socket[%d] fail. Error: %s [%d]", fd, strerror(errno), errno);
            return SUCCESS;
        }
    }
    return SUCCESS;
}

int static cpReactor_thread_loop(int *id)
{

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
    pthread_exit(0);
    return SUCCESS;
}

int static cpReactor_start(int sock)
{
    int i;
    int accept_epfd = epoll_create(512); //这个参数没用
    if (cpEpoll_add(accept_epfd, sock, EPOLLIN) < 0)
    {
        return FAILURE;
    };

    pid_init();
    set_pid(CPGS->master_pid);

    struct timeval timeo;
    timeo.tv_sec = CP_REACTOR_TIMEO_SEC;
    timeo.tv_usec = CP_REACTOR_TIMEO_USEC;
    pthread_t pidt;
    for (i = 0; i < CPGC.reactor_num; i++)
    {
        int *index = (int*) malloc(sizeof (int));
        *index = i;
        if (pthread_create(&pidt, NULL, (void * (*)(void *)) cpReactor_thread_loop, (void *) index) < 0)
        {
            cpLog("pthread_create[tcp_reactor] fail");
        }
        pthread_detach(pidt);
        CPGS->reactor_threads[i].thread_id = pidt;
    }
    epoll_wait_handle handles[CP_MAX_EVENT];
    handles[EPOLLIN] = cpServer_master_onAccept;

    usleep(50000);
    cpLog("start  success");
    return cpEpoll_wait(handles, &timeo, accept_epfd);
}

int static cpListen()
{
    int sock;
    int option;
    int ret;

    struct sockaddr_in addr_in4;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
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

    if (ret < 0)
    {
        cpLog("Bind fail.port=%d. Error: %s [%d]", CPGC.port, strerror(errno), errno);
        return FAILURE;
    }
    //开始监听套接字
    ret = listen(sock, CPGC.backlog);
    if (ret < 0)
    {
        cpLog("Listen fail.port=%d. Error: %s [%d]", CPGC.port, strerror(errno), errno);
        return FAILURE;
    }
    swSetNonBlock(sock);

    if (sock < 0)
    {
        return FAILURE;
    }
    int bufsize = CP_UNSOCK_BUFSIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof (bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof (bufsize));
    return sock;
}

static void cpSignalHanlde(int sig)
{
    switch (sig)
    {
        case SIGTERM:
            cpLog("stop pool server");
            CPGS->running = 0;
            int i = 0, j = 0, ret;
            for (; j < CPGS->group_num; j++)
            {
                cpGroup *G = &CPGS->G[j];
                for (; i < G->worker_num; i++)
                {
                    ret = kill(G->workers[i].pid, SIGKILL);
                    if (ret == -1)
                    {
                        cpLog("kill failed, id=%d. Error: %s [%d]", i, strerror(errno), errno);
                    }
                }
            }
            ret = kill(CPGS->ping_workers->pid, SIGKILL);
            if (ret == -1)
            {
                cpLog("kill ping worker failed, id=%d. Error: %s [%d]", i, strerror(errno), errno);
            }
            exit(1);
            break;
        case SIGUSR1:
            cpLog("reload pool server");
            ret = kill(CPGS->manager_pid, SIGUSR1);
            if (ret == -1)
            {
                cpLog("reload failed, Error: %s [%d]", strerror(errno), errno);
            }
            break;
        default:
            break;
    }
}

void static cpSignalInit(void)
{
    cpSignalSet(SIGHUP, SIG_IGN, 1, 0);
    cpSignalSet(SIGPIPE, SIG_IGN, 1, 0);
    cpSignalSet(SIGUSR1, cpSignalHanlde, 1, 0);
    cpSignalSet(SIGUSR2, SIG_IGN, 1, 0);
    cpSignalSet(SIGTERM, cpSignalHanlde, 1, 0);
}
