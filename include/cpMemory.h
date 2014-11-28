/* 
 * File:   memory.h
 * Author: guoxinhua
 *
 * Created on 2014年9月23日, 下午3:32
 */

#ifndef CP_MEMORY_H
#define	CP_MEMORY_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <sys/mman.h>
#include <sys/shm.h>
#include <cpFunction.h>

    typedef struct _cpShareMemory {
        int size;
        int key;
        int shmid;
        void *mem;
    } cpShareMemory;

    typedef struct _cpSendMem {
        int semid;
        int len;
        int type; //0正常，-1 抛异常
    } cpSendMem;

    typedef struct _cpMasterInfo {//获取连接,master进程返回的信息
        int semid;
        int worker_id;
        int max;//数据包max
    } cpMasterInfo;

    typedef struct _cpWorkerInfo {
        int len;
        int pid;
        int type;
    } cpWorkerInfo;

    typedef struct _cpTcpEvent {
        int type;
    } cpTcpEvent;


    int cpShareMemory_sysv_create(cpShareMemory *object, int size, int key);
    int cpShareMemory_sysv_free(cpShareMemory *object, int rm);
    void *cp_mmap_calloc(int size);


#ifdef	__cplusplus
}
#endif

#endif	/* MEMORY_H */

