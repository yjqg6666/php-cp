
#include "php_connect_pool.h"

typedef struct _cpFd {
    uint32_t fd;
    uint32_t fdtype;
} cpFd;

#ifdef HAVE_KQUEUE
/**
 * 转换成kqueue 对应的事件类型1
 */
static int cpReactorKqueueGetType(int fdtype) {
    uint32_t flag = 0;

    if (isReactor_event_read(fdtype))
    {
        flag |= EVFILT_READ;
    }
    if (isReactor_event_write(fdtype))
    {
        flag |= EVFILT_WRITE;
    }
    /*
    if (isReactor_event_error(fdtype))
    {
        flag |= (EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    }
    */
    return flag;
}
/**
 * epfd kqueue()  epoll_create 产生的 服务器的fd
 * fd   listen() bind()的
 * fdtype 事件类型
 */
int cpKqueue_add(int epfd, int fd, int fdtype) {

    struct kevent e; // event
    int ret;  // 返回值
    int fflags = 0;
    bzero(&e, sizeof (e));
    cpFd fd_;

    fd_.fd = fd;
    fd_.fdtype = fdtype; // wait 中有用到

    //包含读事件
    if (isReactor_event_read(fdtype)) {
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(cpFd));
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0) {
            cpLog(" add event [epfd=%d, fd=%d, type=%d, events=read, ret=%d] failed.\n", epfd, fd, fdtype, ret);
            return FAILURE;
        }
        cpLog("add events=read success\n" , epfd, fd, fd_.fdtype);
    }

    //包含写事件
    if (isReactor_event_write(fdtype)) {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, fflags, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(cpFd));
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);

        //EV_SET(&event_change, client_socket_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        //kevent(kq, &event_change, 1, NULL, 0, NULL);

        if (ret < 0) {
    //        cpLog(" add event [epfd=%d, fd=%d, type=%d, events=write] failed.\n", epfd, fd, fdtype);
            return FAILURE;
        }
        cpLog("epfd [%d] fd [%d] fdtype [%d] add events=write success\n" , epfd, fd, fd_.fdtype);
    }

    cpLog("epfd [%d] fd [%d] fdtype [%d] \n" , epfd, fd, fd_.fdtype);
    // 这步的意义何在???
    memcpy(&e.udata, &fd_, sizeof(cpFd));
    return SUCCESS;
}

int cpKqueue_del(int epfd, int fd) {
    struct kevent e;
    int ret;
    int fflags = 0;

        // 设置e 结构体 指定为EVFILT_READ读的过滤器, 并把本事件加入该过滤器EV_DELETE
        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, fflags, 0, NULL);
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);

        if (ret < 0) {
            cpLog(" delete event [epfd=%d, fd=%d, events=read] failed.\n", epfd, fd);
            return FAILURE;
        }

        /*
        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, fflags, 0, NULL);
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0) {
            cpLog(" delete event [epfd=%d, fd=%d, events=write] failed.\n", epfd, fd);
            return FAILURE;
        }
        */
    //close时会自动从kqueue事件中移除
    ret = close(fd);
    return SUCCESS;
}

int cpKqueue_set(int fd, int fdtype) {
    return SUCCESS;
}

void cpKqueue_free() {
    return ;
}

int cpKqueue_wait(epoll_wait_handle* handles, struct timeval *timeo, int epfd) {
    int i, n, ret;
    //, usec;
    cpFd fd_;
    struct timespec t;
    struct timespec *t_ptr;

    if (timeo == NULL)
    {
        t_ptr = NULL;
        //usec = CP_MAX_UINT;
    }
    else
    {
        t.tv_sec = timeo->tv_sec;
        t.tv_nsec = timeo->tv_usec;
        t_ptr = &t;
    }

    struct kevent events[CP_REACTOR_MAXEVENTS];
    while(CPGS->running)
    {
        n = kevent(epfd, NULL, 0, events, CP_REACTOR_MAXEVENTS, t_ptr);

        if (n < 0) {
            cpLog("kqueue [#%d] Error: %s[%d]", fd_.fd, strerror(errno), errno);
            return FAILURE;
        } else if(n == 0){
            //cpLog("kenvent timeout 没有事件而已 不算超时吧!\n");
            continue;
        }else{
            for (i = 0; i < n; i++) {
                if (events[i].udata) {
                    memcpy(&fd_, &(events[i].udata), sizeof(fd_));
                }

                // 包含读事件
                //if (events[i].filter == EVFILT_READ) {
                if (fd_.fdtype & CP_EVENT_READ) {
                    cpLog("before read function \n");
                    ret = handles[CP_EVENT_READ](fd_.fd);
                    cpLog("Read fd [%d] ftype [%d] current event filter is [%d] CP_EVENT_READ [%d]  CP_EVENT_WRITE [%d]  i [%d] ret [%d]  \n", fd_.fd, fd_.fdtype, events[i].filter, CP_EVENT_READ, CP_EVENT_WRITE, i, ret);
                    //ret = handles[CP_EVENT_READ](epfd);
                    if (ret < 0)
                    {
                        cpLog("kqueue [EVFILT_READ] handle failed. fd=%d. Error: %s[%d]", fd_.fd, strerror(errno), errno);
                    }
                }
                else if (fd_.fdtype & CP_EVENT_WRITE)
                {
                    cpLog("Write fd [%d] ftype [%d] current event filter is [%d] CP_EVENT_READ [%d]  CP_EVENT_WRITE [%d]  i [%d] ret [%d]  \n", fd_.fd, fd_.fdtype, events[i].filter, CP_EVENT_READ, CP_EVENT_WRITE, i, ret);
                    //ret = handles[CP_EVENT_WRITE](fd_.fd);
                    ret = handles[CP_EVENT_READ](fd_.fd);
                    //ret = handles[CP_EVENT_READ](epfd);
                    if (ret < 0)
                    {
                        cpLog("kqueue [EPOLLOUT] handle failed. fd=%d. Error: %s[%d]", fd_.fd, strerror(errno), errno);
                    }
                } else {
                    cpLog("kqueue [ERROR] handle failed. fd=%d. Error: %s[%d]", fd_.fd, strerror(errno), errno);
                }

            }
        }

    }

    return 0;
}
#endif

