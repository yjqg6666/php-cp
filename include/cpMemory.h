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

    typedef struct _cpShareMemory {
        int size;
        char mmap_name[100];
        void *mem;
    } cpShareMemory;

    typedef struct _cpMasterInfo {
        int server_fd;//fpm in server's fd
    } cpMasterInfo;

    typedef struct _cpWorkerInfo {
        int len;//share mm len
        int pid;
        uint16_t type;
        char method[CP_METHOD_LEN];
        char data_source[CP_SOURCE_MAX];
    } cpWorkerInfo;

    typedef struct _cpTcpEvent {
        int type;
        int data;
    } cpTcpEvent;


    void *cp_mmap_calloc(int size);
    void* cp_mmap_calloc_with_file(cpShareMemory *object);
    int cp_create_mmap_file(cpShareMemory *object);
    int cp_create_mmap_dir();


#ifdef	__cplusplus
}
#endif

#endif	/* MEMORY_H */

