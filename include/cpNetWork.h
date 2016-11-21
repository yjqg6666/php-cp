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
#define CP_REACTOR_MAXEVENTS       4096
#define CP_MAX_EVENT               1024
#define CP_BUFFER_SIZE         (1024*1024)
#define CP_MAX_UINT            4294967295

#define EPOLL_CLOSE            10

#define CP_CLIENT_EOF_STR          "\r\n^CON^eof\r\n"
#define CP_TOO_MANY_CON            "not enough con"
#define CP_TOO_MANY_CON_ERR        "ERROR!not enough con"
#define CP_MULTI_PROCESS_ERR        "ERROR!the connection object create in parent process and use in multi process,please create in every process"
#define CP_CLIENT_EOF_LEN          strlen(CP_CLIENT_EOF_STR)
#define CP_HEADER_CON_SUCCESS      "CON_SUCCESS!"
#define CP_HEADER_ERROR            "ERROR!"
#define CP_PDO_HEADER_STATE        "PDOStatement!"
#define CP_RELEASE_HEADER          "r"
#define CP_RELEASE_HEADER_LEN      1


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

