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
        int last_from_id;
        pid_t pid;
        int pipe_fd_write;
        int pre_len;
        pid_t pre_pid;
        
        int fd;//当前worker服务于哪个fd
        int CPid;//当前worker服务于哪个pid
        
        uint8_t  run;
        cpShareMemory sm_obj;
    } cpWorker;

    int cpFork_one_worker(int id);
    int cpWorker_manager_loop();

#ifdef	__cplusplus
}
#endif

#endif	/* WORKER_H */

