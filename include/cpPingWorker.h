/* 
 * File:   cpPingWorker.h
 * Author: guoxinhua
 *
 * Created on 2014年12月29日, 下午3:06
 */

#ifndef CPPINGWORKER_H
#define	CPPINGWORKER_H

#ifdef	__cplusplus
extern "C" {
#endif

    int cpFork_ping_worker();
    int cpCreate_ping_worker_mem();

#ifdef	__cplusplus
}
#endif

#endif	/* CPPINGWORKER_H */

