
#include "php_connect_pool.h"

typedef struct _cpFd {
    uint32_t fd;
    uint32_t fdtype;
} cpFd;

#ifdef HAVE_KQUEUE
/**
 * 转换成kqueue 对应的事件类型
 */
static inline int cpReactorKqueueGetType(int fdtype) {
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
 * epfd kqueue()  epoll_create 产生的 
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
    fd_.fdtype = fdtype;

    /*
    // 这个地方 为毛要传这个啊
    e.udata.fd = fd;
    e.udata.fdtype = fdtype;
    */

    //包含读事件
    if (isReactor_event_read(fdtype)) {
        EV_SET(&e, fd, EVFILT_READ, EV_ADD, fflags, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(cpFd));
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0) {
            cpLog(" add event [epfd=%d, fd=%d, type=%d, events=read, ret=%d] failed.\n", epfd, fd, fdtype, ret);
            return FAILURE;
        }
    }

    //包含写事件
    if (isReactor_event_write(fdtype)) {
        EV_SET(&e, fd, EVFILT_WRITE, EV_ADD, fflags, 0, NULL);
        memcpy(&e.udata, &fd_, sizeof(cpFd));
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0) {
    //        cpLog(" add event [epfd=%d, fd=%d, type=%d, events=write] failed.\n", epfd, fd, fdtype);
            return FAILURE;
        }
    }

    // 这步的意义何在???
    memcpy(&e.udata, &fd_, sizeof(cpFd));
    return SUCCESS;
}

int cpKqueue_del(int epfd, int fd) {
    struct kevent e;
    int ret;
    int fflags = 0;

        EV_SET(&e, fd, EVFILT_READ, EV_DELETE, fflags, 0, NULL);
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);

        if (ret < 0) {
            cpLog(" delete event [epfd=%d, fd=%d, events=read] failed.\n", epfd, fd);
            return FAILURE;
        }

        EV_SET(&e, fd, EVFILT_WRITE, EV_DELETE, fflags, 0, NULL);
        ret = kevent(epfd, &e, 1, NULL, 0, NULL);
        if (ret < 0) {
            cpLog(" delete event [epfd=%d, fd=%d, events=write] failed.\n", epfd, fd);
            return FAILURE;
        }
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
            for (i =0; i < n; i++) {
                if (events[i].udata) {
                    memcpy(&fd_, &(events[i].udata), sizeof(fd_));
                }

                // 包含读事件
                if (events[i].filter == EVFILT_READ) {
                    ret = handles[CP_EVENT_READ](fd_.fd);
                    if (ret < 0)
                    {
                        cpLog("kqueue [EVFILT_READ] handle failed. fd=%d. Error: %s[%d]", fd_.fd, strerror(errno), errno);
                    }
                }
                else if (events[i].filter == EVFILT_WRITE)
                {
                    //ret = handles[CP_EVENT_WRITE](fd_.fd);
                    ret = handles[CP_EVENT_READ](fd_.fd);
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

