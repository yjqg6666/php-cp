/* 
 * File:   cpFunction.h
 * Author: gxhua
 *
 * Created on 2014年10月6日, 下午9:22
 */

#ifndef CONPFUNCTION_H
#define	CONPFUNCTION_H

#ifdef	__cplusplus
extern "C" {
#endif
#if __STDC_VERSION__ >= 199901L || defined(__cplusplus)
#define CPINLINE inline
#elif defined(_MSC_VER) || defined(__GNUC__)
#define CPINLINE __inline
#else
#define CPINLINE
#endif

#ifdef __MACH__
#undef CPINLINE
#define CPINLINE
#endif
#define CP_FIFO_NAME_LEN   200
#define CP_FIFO_NAME_PRE   "/tmp/con_pool_c2w_pipe"
#define CP_MMAP_NAME_PRE   "/tmp/con_pool_mmap"
#define CP_MMAP_NAME_LEN   100
#define SW_LOG_BUFFER_SIZE 1024
#define SW_PID_BUFFER_SIZE 100
#define SW_LOG_DATE_STRLEN  64
#define CP_LOG_FORMAT "[%s]\t%s\t\n"
#define FAILUREOR_MSG_SIZE 1024
#define MAX_TITLE_LENGTH   127
#define MAX_INI_LENGTH   1024

#define PID_FILE_PATH "/var/run/con_pool_"
#define cpLog(str,...)     \
                        do \
                            { \
                                char cp_error_str[FAILUREOR_MSG_SIZE];\
                                snprintf(cp_error_str,FAILUREOR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
                                char date_str[SW_LOG_DATE_STRLEN];\
                                time_t t;\
                                struct tm *p;\
                                t = time(NULL);\
                                p = localtime(&t);\
                                snprintf(date_str, SW_LOG_DATE_STRLEN, "%d-%02d-%02d %02d:%02d:%02d", p->tm_year + 1900, p->tm_mon + 1, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);\
                                fprintf(cp_log_fn, CP_LOG_FORMAT, date_str,cp_error_str); \
                                if(CPGC.daemonize == 0) fprintf(stdout, CP_LOG_FORMAT, date_str,cp_error_str); \
                           }while(0);

    typedef void (*cpSignalFunc)(int);
    typedef void (*cpQueueFunc) (int, siginfo_t *, void *);
    int cpLog_init(char *logfile);
    int pid_init();
    int set_pid(int pid);
    CPINLINE void cpSetNonBlock(int sock);
    void swSingalNone();
    CPINLINE int cpWrite(int fd, void *buf, int count);
    CPINLINE int cpSetTimeout(int sock, double timeout);
    cpSignalFunc cpSignalSet(int sig, cpSignalFunc func, int restart, int mask);
    int cpQueueSignalSet(int sig, cpQueueFunc func);
    void cpSettitle(char *title);
    zval * cpGetConfig(char *filename);
    zval * cpMD5(zval *arr);
    CPINLINE void cp_ser_and_setpro(zval *arr);
    CPINLINE int cpNetRead(int fd, void *buf, int len);
    CPINLINE int cpCreateFifo(char *file);
    CPINLINE int cpFifoRead(int pipe_fd_read, void *buf, int len);


#ifdef	__cplusplus
}
#endif

#endif	/* CONPFUNCTION_H */

