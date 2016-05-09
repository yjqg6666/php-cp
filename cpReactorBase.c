#include "php_connect_pool.h"

/**
 *  创建fd
 */
int cpReactor_create() {
#ifdef HAVE_EPOLL
    return epoll_create(512);
#else
#ifdef HAVE_KQUEUE
    return kqueue();
#endif
#endif
}

/**
 * epfd kqueue()  epoll_create 产生的
 * fd   listen() bind()的
 * fdtype 事件类型
 */
int cpReactor_add(int epfd, int fd, int fdtype) {
#ifdef HAVE_EPOLL
        return cpEpoll_add(epfd, fd, fdtype);
#else
#ifdef HAVE_KQUEUE
        return cpKqueue_add(epfd, fd, fdtype);
#endif
#endif
}

int cpReactor_del(int epfd, int fd) {
#ifdef HAVE_EPOLL
        return cpEpoll_del(epfd, fd);
#else
#ifdef HAVE_KQUEUE
        return cpKqueue_del(epfd, fd);
#endif
#endif
}

int cpReactor_set(int fd, int fdtype) {
    return SUCCESS;
}

void cpReactor_free() {
    return ;
}

int cpReactor_wait(epoll_wait_handle* handles, struct timeval *timeo, int epfd) {

#ifdef HAVE_EPOLL
        return cpEpoll_wait(handles, timeo, epfd);
#else
#ifdef HAVE_KQUEUE
        return cpKqueue_wait(handles, timeo,  epfd);
#endif
#endif
}

