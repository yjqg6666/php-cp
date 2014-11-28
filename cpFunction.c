/*
  +----------------------------------------------------------------------+
  | common con pool                                                      |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | original: Tianfeng Han    modify:Xinhua Guo  <woshiguo35@sina.com>   |
  +----------------------------------------------------------------------+
 */

#include "php_connect_pool.h"


static char bufr[SW_LOG_BUFFER_SIZE];
static char bufpid[SW_PID_BUFFER_SIZE];

FILE *pid_fn = NULL;
int cp_error;
FILE *cp_log_fn = NULL;
char *cpArgv0 = NULL;

int cpLog_init(char *logfile) {
    cp_log_fn = fopen(logfile, "a+");
    if (cp_log_fn == NULL) {
        return FAILURE;
    }
    if (setvbuf(cp_log_fn, bufr, _IOLBF, SW_LOG_BUFFER_SIZE) < 0) {
        return FAILURE;
    }
    return SUCCESS;
}

int pid_init() {
    char pid_name[512] = {0};
    sprintf(pid_name, "%s%s.pid", PID_FILE_PATH, CPGC.title);
    pid_fn = fopen(pid_name, "w+");
    if (pid_fn == NULL) {
        cpLog("create pid file error");
        return FAILURE;
    }
    if (setvbuf(pid_fn, bufpid, _IONBF, SW_PID_BUFFER_SIZE) < 0) {
        return FAILURE;
    }
    return SUCCESS;
}

int set_pid(int pid) {
    fprintf(pid_fn, "%d\n", pid);
    return SUCCESS;
}

void swLog_free(void) {
    fclose(cp_log_fn);
}


CPINLINE int cpWrite(int fd, void *buf, int count) {
    int nwritten = 0, totlen = 0;
    while (totlen != count) {
        nwritten = write(fd, buf, count - totlen);
        if (nwritten > 0) {
            totlen += nwritten;
            buf += nwritten;
        } else if (nwritten == 0) {
            return totlen;
        } else {
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN) {
                usleep(1);
                continue;
            } else {
                return -1;
            }
        }

    }
    return totlen;
}

CPINLINE int cpFifoRead(int pipe_fd_read, void *buf, int len) {
    int n, total = 0;
    do {
        n = read(pipe_fd_read, buf + total, len);
        if (n > 0) {
            total += n;
            if (total == len) {
                break;
            }
        }
//        else {
//            cpLog("worker fifo recive error %d,len %d\n", errno, n);
//        }
    } while ((n < 0 && errno == EINTR) || n > 0);
    return total;
}

CPINLINE int cpNetRead(int fd, void *buf, int len) {
    int n, total = 0;
    do {
        n = recv(fd, buf + total, len, MSG_WAITALL);
        if (n > 0) {
            total += n;
            if (total == len) {
                break;
            }
        } else if (n == 0) {
            return 0;
        } 
//        else {
//            cpLog("worker recive error %d,len %d\n", errno, n);
//        }
    } while ((n < 0 && errno == EINTR) || n > 0);
    return total;
}

void cpSettitle(char *title) {

    assert(MAX_TITLE_LENGTH > strlen(title) + 5);

    int tlen = strlen(title);
    char buffer[MAX_TITLE_LENGTH];

    memset(buffer, 0, MAX_TITLE_LENGTH);
    if (tlen >= (MAX_TITLE_LENGTH - 1)) tlen = (MAX_TITLE_LENGTH - 1);
    memcpy(buffer, title, tlen);
    snprintf(cpArgv0, MAX_TITLE_LENGTH, "pool_%s", buffer);
}

//将套接字设置为非阻塞方式

CPINLINE void swSetNonBlock(int sock) {
    int opts, ret;
    do {
        opts = fcntl(sock, F_GETFL);
    } while (opts < 0 && errno == EINTR);
    if (opts < 0) {
        cpLog("fcntl(sock,GETFL) fail");
    }
    opts = opts | O_NONBLOCK;
    do {
        ret = fcntl(sock, F_SETFL, opts);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        cpLog("fcntl(sock,SETFL,opts) fail");
    }
}

CPINLINE void swSetBlock(int sock) {
    int opts, ret;
    do {
        opts = fcntl(sock, F_GETFL);
    } while (opts < 0 && errno == EINTR);

    if (opts < 0) {
        cpLog("fcntl(sock,GETFL) fail");
    }
    opts = opts & ~O_NONBLOCK;
    do {
        ret = fcntl(sock, F_SETFL, opts);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        cpLog("fcntl(sock,SETFL,opts) fail");
    }
}


CPINLINE int cpSetTimeout(int sock, double timeout) {
    int ret;
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeo, sizeof (timeo));
    if (ret < 0) {
        return FAILURE;
    }
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeo, sizeof (timeo));
    if (ret < 0) {
        return FAILURE;
    }
    return SUCCESS;
}

CPINLINE int cpCreateFifo(char *file) {
    int pipe_fd;
    int res;
    umask(0);
    if (access(file, F_OK) == -1) {
        res = mkfifo(file, 0666);
        if (res != 0) {
            cpLog("Could not create fifo %s Error: %s[%d]", file, strerror(errno), errno);
            return -1;
        }
    }
    pipe_fd = open(file, CP_PIPE_MOD);
    if (pipe_fd == -1) {
        cpLog("Could not open fifo %s Error: %s[%d]", file, strerror(errno), errno);
        return -1;
    }
    return pipe_fd;
}

/**
 * clear all singal
 */
void swSingalNone() {
    sigset_t mask;
    sigfillset(&mask);
    int ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (ret < 0) {
        cpLog("pthread_sigmask fail: %s", strerror(ret));
    }
}

zval * cpGetConfig(char *filename) {
    zval fun_name, **args[2], *retval, *file, *section;
    ZVAL_STRING(&fun_name, "parse_ini_file", 0);

    MAKE_STD_ZVAL(file);
    ZVAL_STRING(file, filename, 1);
    MAKE_STD_ZVAL(section);
    ZVAL_BOOL(section, 1);
    args[0] = &file;
    args[1] = &section;

    if (call_user_function_ex(CG(function_table), NULL, &fun_name, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS) {
        zval_ptr_dtor(&file);
        zval_ptr_dtor(&section);
        return NULL;
    }
    zval_ptr_dtor(&file);
    zval_ptr_dtor(&section);
    return retval;
}

cpSignalFunc cpSignalSet(int sig, cpSignalFunc func, int restart, int mask) {
    struct sigaction act, oact;
    act.sa_handler = func;
    if (mask) {
        sigfillset(&act.sa_mask);
    } else {
        sigemptyset(&act.sa_mask);
    }
    act.sa_flags = 0;
    //        act.sa_flags = SA_SIGINFO;
    if (sigaction(sig, &act, &oact) < 0) {
        return NULL;
    }
    return oact.sa_handler;
}

int cpQueueSignalSet(int sig, cpQueueFunc func) {
    struct sigaction act, oact;
    sigemptyset(&act.sa_mask);

    act.sa_sigaction = func;
    act.sa_flags = SA_SIGINFO;
    if (sigaction(sig, &act, &oact) < 0) {
        cpLog("sigaction error %d", errno);
        return FAILURE;
    }
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, CP_SIG_EVENT);
    sigprocmask(SIG_BLOCK, &block, NULL);

    return SUCCESS;
}

#ifndef HAVE_CLOCK_GETTIME
#ifdef __MACH__

int clock_gettime(clock_id_t which_clock, struct timespec *t) {
    // be more careful in a multithreaded environement
    if (!orwl_timestart) {
        mach_timebase_info_data_t tb = {0};
        mach_timebase_info(&tb);
        orwl_timebase = tb.numer;
        orwl_timebase /= tb.denom;
        orwl_timestart = mach_absolute_time();
    }
    double diff = (mach_absolute_time() - orwl_timestart) * orwl_timebase;
    t->tv_sec = diff * ORWL_NANO;
    t->tv_nsec = diff - (t->tv_sec * ORWL_GIGA);
    return 0;
}
#endif
#endif