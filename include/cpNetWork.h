/* 
 * File:   NetWork.h
 * Author: guoxinhua
 *
 * Created on 2014年9月24日, 下午5:14
 */

#ifndef CP_NETWORK_H
#define	CP_NETWORK_H

#ifdef	__cplusplus
extern "C" {
#endif


    typedef int (*epoll_wait_handle)(int fd);

    int cpEpoll_add(int epfd, int fd, int fdtype);
    int cpEpoll_set(int fd, int fdtype);
    int cpEpoll_del(int epfd, int fd);
    int cpEpoll_wait(epoll_wait_handle*, struct timeval *timeo, int epfd);
    void cpEpoll_free();
    CPINLINE int cpEpoll_event_set(int fdtype);


#ifdef	__cplusplus
}
#endif

#endif	/* NETWORK_H */

