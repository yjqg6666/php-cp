/* 
 * File:   ClientNet.h
 * Author: guoxinhua
 *
 * Created on 2014年9月30日, 上午10:52
 */

#ifndef CP_CLIENTNET_H
#define	CP_CLIENTNET_H
#define MAX_HOLD_START_STR "\n-------------------max hold time start-------------------------"
#define MAX_HOLD_END_STR   "\n-------------------max hold time end-------------------------"
#define MAX_DATA_START_STR "\n-------------------big data size start-------------------------"
#define MAX_DATA_END_STR   "\n-------------------big data size end-------------------------"

#ifdef	__cplusplus
extern "C" {
#endif
    typedef struct _cpClient {
        int sock;
        double timeout;

        struct sockaddr_in serv_addr;
        struct sockaddr_in remote_addr;

        cpMasterInfo info;
        int server_fd;
        uint8_t async; //是否是异步类的连接

        int (*lock)(struct _cpGroup *);
        int (*unLock)(struct _cpGroup *);

        uint16_t dummy_source_index;
        uint8_t querying; //async querying

        smart_str slow_log_tmp;
        smart_str big_data_tmp;
        int current_len; //for big data log
        struct timeval log_start;
    } cpClient;

    int cpClient_close(cpClient *cli);
    int cpClient_send(int sock, char *data, int length, int flag);
    int cpClient_create(cpClient *cli);
    int cpClient_recv(int sock, void *data, int len, int waitall);
    int cpClient_connect(cpClient *cli, char *host, int port, double timeout);

    void log_start(cpClient* cli);
    void log_end(cpClient* cli);
    void log_write(zval *data, cpClient* cli);
    void log_increase_size(int size, cpClient* cli);

#define CONN(cli)                                 (&CPGS->conlist[cli->server_fd])
#define CON_FORMART_KEY(str,port) sprintf((str), "connect_pool_sock%s" , (port));
#define CON_FAIL_MESSAGE                         "connect to pool_server fail"

#ifdef	__cplusplus
}
#endif

#endif	/* CLIENTNET_H */

