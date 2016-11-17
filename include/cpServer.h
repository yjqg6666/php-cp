/* 
 * File:   Server.h
 * Author: guoxinhua
 *
 * Created on 2014年9月22日, 下午3:52
 */

#ifndef CP_SERVER_H
#define	CP_SERVER_H

#ifdef	__cplusplus
extern "C" {
#endif


    typedef volatile int8_t volatile_int8;

    //    typedef struct _cpWaitList {
    //        int CPid; // fpm's pid
    //        struct _cpConnection *conn;
    //        struct _cpWaitList *next;
    //        int next_id;
    //        struct _cpWaitList *pre;
    //    } cpWaitList;

    typedef struct _cpConnection {
        int fd;

        uint16_t group_id; //0 1 2 3 
        uint16_t worker_id; //1001 1002 2001
        uint16_t worker_index; // 0 1 2 3

        uint8_t release;
        uint16_t pth_id;

        int wait_fpm_pid; //等待的fpm pid
        int next_wait_id; //sever fd
        int fpm_pid; //连接对应的fpm
        //        struct _cpWaitList WaitList;
    } cpConnection;

    typedef struct _cpIdelList {
        struct _cpIdelList *next;
        int worker_id;
    } cpIdelList;

    typedef struct _cpConfig {
        uint16_t backlog;
        uint16_t reactor_num;
        uint16_t recycle_num;
        uint16_t port;

        //连续失败多少次算失效
        uint16_t ser_fail_hits;

        //最多可以剔除多少个结点,防止网络抖动等,导致的全部踢掉
        uint16_t max_fail_num;

        uint8_t idel_time;
        uint8_t use_wait_queue;
        uint8_t daemonize;


        uint64_t max_read_len;

        int max_conn;
        int timeout_sec;
        int timeout_usec;
        int max_request;

        int max_hold_time_to_log;
        int max_data_size_to_log;

        char ini_file[MAX_INI_LENGTH];
        char log_file[128]; //日志文件

    } cpConfig;

    typedef struct _cpThread {
        int id; //0.1.2.3
        int epfd;
        pthread_t thread_id;
        uint16_t event_num;
    } cpThread;

    typedef struct _cpServerG {
        uint8_t running;
        uint8_t process_type;

        uint64_t wait_in_num;
        uint64_t wait_out_num;

        cpConfig conf;
        int epfd;
        void *ping_mem_addr;
    } cpServerG;

    typedef struct _cpGroup {
        int id; //Current worker group  id 0,1,2,3...n
        uint32_t worker_num;
        uint32_t worker_min;
        uint32_t worker_max;
        cpWorker workers[CP_GROUP_LEN];
        volatile_int8 workers_status[CP_GROUP_LEN];
        pthread_mutex_t mutex_lock;
        int first_wait_id; //server fd
        int last_wait_id; //server fd
        //        cpWaitList *WaitList; //获得失败的wait队列
        //        cpWaitList *WaitTail; //获得失败的wait队列队尾
        char name[100]; //group name

        int (*lock)(struct _cpGroup *);
        int (*unLock)(struct _cpGroup *);
        int (*tryLock)(struct _cpGroup *);
    } cpGroup;

    typedef struct _cpServerGS {
        pid_t master_pid;
        pid_t manager_pid;


        uint32_t connect_count;
        uint16_t reactor_next_i;
        //        uint16_t reactor_round_i;

        cpConnection conlist[CP_MAX_FDS];

        cpWorker *ping_workers;

        cpThread *reactor_threads;

        int running;
        cpGroup G[CP_GROUP_NUM]; //group TODO extend
        zval* group;
        int group_num;
        int max_buffer_len;
        int max_hold_time_to_log;
        int max_data_size_to_log;

        pthread_mutex_t mutex_lock;
        //        int (*global_lock)(struct _cpGroup *);
        //        int (*global_unLock)(struct _cpGroup *);

        int default_min;
        int default_max;

        char log_file[128]; //日志文件
    } cpServerGS;

    typedef struct _cpWorkerG {
        int id; //Current Proccess Worker's id 0,1,2,3...n
        int gid; //current worker's group id
        int pid;
        int working;
        uint64_t max_read_len;
        int pipe_fd_read;
        int pipe_fd_write;
        cpWorkerInfo event;
    } cpWorkerG;

    int cpServer_init(zval *conf, char *ini_file);
    int cpServer_create();
    int cpServer_start();
    int cpMutexLock(cpGroup *);
    int cpMutexUnLock(cpGroup *);
    int cpMutexTryLock(cpGroup *);
    void cpServer_try_get_worker(cpConnection *conn, int group_id);
    int cpPopWaitQueue(cpGroup *G, cpConnection *conn);


#ifdef	__cplusplus
}
#endif

#endif	/* SERVER_H */

