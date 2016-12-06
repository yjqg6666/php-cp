/* 
 * File:   Worker.h
 * Author: guoxinhua
 *
 * Created on 2014年9月23日, 上午10:59
 */

#ifndef CP_WORKER_H
#define	CP_WORKER_H

#ifdef	__cplusplus
extern "C" {
#endif
#define CP_WORKER_SENDTO_YIELD     10   //yield after sendto
    
    typedef struct _cpWorker {
        int request; //worker request NUM
        pid_t pid;
        int pipe_fd_write;
        int CPid;//当前worker服务于哪个pid
        cpShareMemory sm_obj;
    } cpWorker;

    int cpFork_one_worker(int id,int gid);
    int cpWorker_manager_loop();
    void cpWorker_do_ping();
    int cpCreate_worker_mem(int worker_id,int group_id);
    int cpWorker_attach_mem(int worker_id,int group_id);
    

#ifdef	__cplusplus
}
#endif

#endif	/* WORKER_H */

