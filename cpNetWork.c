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
  | Author: Xinhua Guo  <woshiguo35@sina.com>                         |
  +----------------------------------------------------------------------+
 */
#include "php_connect_pool.h"

#ifdef HAVE_EPOLL

/**
 * 转换成epoll 对应的事件类型
 */
static inline int cpReactorEpollGetType(int fdtype) {
    uint32_t flag = 0;

    if (isReactor_event_read(fdtype))
    {
        flag |= EPOLLIN;
    }
    if (isReactor_event_write(fdtype))
    {
        flag |= EPOLLOUT;
    }
    if (isReactor_event_error(fdtype))
    {
        flag |= (EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    }
    return flag;
}

int cpEpoll_add(int epfd, int fd, int fdtype) {
    struct epoll_event e;
    int ret;
    bzero(&e, sizeof (struct epoll_event));

    e.data.fd = fd;
    e.events = fdtype;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &e);
    if (ret < 0)
    {
        cpLog("add event fail. Error: %s[%d]", strerror(errno), errno);
        return FAILURE;
    }
    return SUCCESS;
}

int cpEpoll_del(int epfd, int fd) {
    struct epoll_event e;
    int ret;
    e.data.fd = fd;

    if (fd <= 0)
    {
        return FAILURE;
    }
    //	e.events = EPOLLIN | EPOLLET | EPOLLOUT;
    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &e);
    if (ret < 0)
    {
        cpLog("epoll remove fd[=%d] fail. Error: %s[%d]", fd, strerror(errno), errno);
        return SUCCESS;
    }
    //close时会自动从epoll事件中移除
    ret = close(fd);
    return SUCCESS;
}

CPINLINE int cpReactor_error() {
    switch (errno)
    {
        case EINTR:
            return SUCCESS;
    }
    return FAILURE;
}

int cpEpoll_wait(epoll_wait_handle *handles, struct timeval *timeo, int epfd) {
    int i, n, ret, usec;
    //    int pack_size = sizeof (uint32_t)*8;

    if (timeo == NULL)
    {
        usec = CP_MAX_UINT;
    }
    else
    {
        usec = timeo->tv_sec * 1000 + timeo->tv_usec / 1000;
    }

    struct epoll_event events[CP_REACTOR_MAXEVENTS];

    while (CPGS->running)
    {
        n = epoll_wait(epfd, events, CP_REACTOR_MAXEVENTS, usec);
        for (i = 0; i < n; i++)
        {
            //取出事件
            if (events[i].events & EPOLLIN)
            {
                ret = handles[EPOLLIN](events[i].data.fd);
                if (ret < 0)
                {
                    cpLog("epoll [EPOLLIN] handle failed. fd=%d. Error: %s[%d]", events[i].data.fd,
                            strerror(errno), errno);
                }
            }
            else if (events[i].events & EPOLLOUT)
            {
                ret = handles[EPOLLIN](events[i].data.fd);
                if (ret < 0)
                {
                    cpLog("epoll [EPOLLOUT] handle failed. fd=%d. Error: %s[%d]", events[i].data.fd,
                            strerror(errno), errno);
                }
            }
#ifndef NO_EPOLLRDHUP
            else if ((events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)))
#else
            else if ((events[i].events & (EPOLLERR | EPOLLHUP)))
#endif
            {
                if (events[i].data.fd > 0)
                {
                    ret = handles[EPOLL_CLOSE](events[i].data.fd);
                    if (ret < 0)
                    {
                        cpLog("epoll [EPOLLRDHUP] handle failed. fd=%d. Error: %s[%d]", events[i].data.fd, strerror(errno), errno);
                    }
                }
            }
        }
        if (n < 0)
        {
            if (cpReactor_error() < 0)
            {
                cpLog("Epoll[#%d] Error: %s[%d]", events[i].data.fd, strerror(errno), errno);
                return FAILURE;
            }
        }
    }
    return 0;
}
#endif

