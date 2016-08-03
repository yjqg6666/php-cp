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
  | Author: Xinhua Guo  <woshiguo35@sina.com>                            |
  +----------------------------------------------------------------------+
 */
#include "php_connect_pool.h"
#include <netdb.h>

static int client_open_log = 0;

int cpClient_close(cpClient *cli)
{
    int ret, fd = cli->sock;
    cli->sock = 0;
    ret = close(fd);
    if (ret < 0)
    {
        cpLog("client close fail. Error: %s[%d]", strerror(errno), errno);
    }
    //    CPGS = NULL;
    return ret;
}

int cpClient_recv(int sock, void *data, int len, int waitall)
{
    //    int flag = 0, ret;
    //    if (waitall == 1) {
    //        flag = MSG_WAITALL;
    //    }
    //
    //    ret = recv(cli->sock, data, len, flag);
    //
    //    if (ret < 0) {
    //        if (errno == EINTR) {
    //            ret = recv(cli->sock, data, len, flag);
    //        } else {
    //            return SUCCESS;
    //        }
    //    }
    return cpNetRead(sock, data, len);
}

int cpClient_send(int sock, char *data, int length, int flag)
{
    int written = 0;
    int n;

    assert(length > 0);
    assert(data != NULL);

    //总超时，for循环中计时
    while (written < length)
    {
        n = send(sock, data, length - written, flag);
        if (n < 0)
        {
            //中断
            if (errno == EINTR)
            {
                continue;
            }//让出
            else if (errno == EAGAIN)
            {
                usleep(1);
                continue;
            }
            else
            {
                return SUCCESS;
            }
        }
        written += n;
        data += n;
    }
    return written;
}

int cpClient_create(cpClient *cli)
{
    bzero(cli, sizeof (cpClient));
    cli->sock = socket(AF_INET, SOCK_STREAM, 0);

    int flag = 1;
    setsockopt(cli->sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof (flag));

    if (cli->sock < 0)
    {
        return FAILURE;
    }
    return SUCCESS;
}

static int swClient_inet_addr(struct sockaddr_in *sin, char *string)
{
    struct in_addr tmp;
    struct hostent *host_entry;

    if (inet_aton(string, &tmp))
    {
        sin->sin_addr.s_addr = tmp.s_addr;
    }
    else
    {
        if (!(host_entry = gethostbyname(string)))
        {
            cpLog("Host lookup failed. Error: %s[%d] ", strerror(errno), errno);
            return SUCCESS;
        }
        if (host_entry->h_addrtype != AF_INET)
        {
            cpLog("Host lookup failed: Non AF_INET domain returned on AF_INET socket");
            return 0;
        }
        memcpy(&(sin->sin_addr.s_addr), host_entry->h_addr_list[0], host_entry->h_length);
    }
    return SUCCESS;
}

int cpClient_connect(cpClient *cli, char *host, int port, double timeout)
{
    int ret;
    cli->serv_addr.sin_family = AF_INET;
    cli->serv_addr.sin_port = htons(port);

    if (swClient_inet_addr(&cli->serv_addr, host) < 0)
    {
        return SUCCESS;
    }

    cli->timeout = timeout;
    cpSetTimeout(cli->sock, timeout);

    //    int count = 0;
    while (1)
    {
        ret = connect(cli->sock, (struct sockaddr *) (&cli->serv_addr), sizeof (cli->serv_addr));
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            //            if (++count <= 15) {//防止重启代理导致的con refused
            //                usleep(100000);
            //                continue;
            //            }
        }
        break;
    }
    return ret;
}

static void log_process(zval *send_data, smart_str *buffer)
{
    zval *args = NULL, *method = NULL, *first = NULL;
    cp_zend_hash_find(Z_ARRVAL_P(send_data), ZEND_STRS("method"), (void **) &method);
    //    snprintf(buffer + strlen(buffer), CLIENT_LOG_BUFFER, "\nmethod:%s\n", Z_STRVAL_P(method));
    smart_str_appendl(buffer, "\nmethod:", 8);
    smart_str_appendl(buffer, Z_STRVAL_P(method), Z_STRLEN_P(method));
    cp_zend_hash_find(Z_ARRVAL_P(send_data), ZEND_STRS("args"), (void **) &args);
    if (cp_zend_hash_index_find(Z_ARRVAL_P(args), 0, (void**) &first) == SUCCESS)
    {
        if (Z_TYPE_P(first) == IS_STRING)
        {
            smart_str_appendl(buffer, "\nfirst arg:", 11);
            smart_str_appendl(buffer, Z_STRVAL_P(first), Z_STRLEN_P(first));
        }
    }
}

void log_write(zval *send_data, cpClient* cli)
{
    if (CPGS->max_hold_time_to_log)
    {
        log_process(send_data, &cli->slow_log_tmp);
    }
    if (CPGS->max_data_size_to_log)
    {
        log_process(send_data, &cli->big_data_tmp);
    }
}

void log_start(cpClient* cli)
{
    if (CPGS->max_hold_time_to_log)
    {
        gettimeofday(&cli->log_start, NULL);
        smart_str_appendl(&cli->slow_log_tmp, MAX_HOLD_START_STR, sizeof (MAX_HOLD_START_STR) - 1);
    }
    if (CPGS->max_data_size_to_log)
    {
        cli->current_len = 0;
        smart_str_appendl(&cli->big_data_tmp, MAX_DATA_START_STR, sizeof (MAX_DATA_START_STR) - 1);
    }
}

void log_end(cpClient* cli)
{
    if (CPGS->max_hold_time_to_log)
    {
        static struct timeval log_end;
        gettimeofday(&log_end, NULL);
        int ms = 1000 * (log_end.tv_sec - cli->log_start.tv_sec) + (log_end.tv_usec - cli->log_start.tv_usec) / 1000;
        if (CPGS->max_hold_time_to_log <= ms)
        {
            if (!client_open_log)
            {
                client_open_log = 1;
                cpLog_init(CPGS->log_file);
            }
            smart_str_appendl(&cli->slow_log_tmp, MAX_HOLD_END_STR, sizeof (MAX_HOLD_END_STR) - 1);
smart_str_0(&cli->slow_log_tmp);
#if PHP_MAJOR_VERSION < 7
            cpLog("%s\n\n", cli->slow_log_tmp.c);
#else
            cpLog("%s\n\n", ZSTR_VAL(cli->slow_log_tmp.s));
#endif
            smart_str_free(&cli->slow_log_tmp);
        }
    }
    if (CPGS->max_data_size_to_log && CPGS->max_data_size_to_log <= cli->current_len)
    {
        if (!client_open_log)
        {
            client_open_log = 1;
            cpLog_init(CPGS->log_file);
        }
        smart_str_appendl(&cli->big_data_tmp, MAX_DATA_END_STR, sizeof (MAX_DATA_END_STR) - 1);
smart_str_0(&cli->big_data_tmp);
#if PHP_MAJOR_VERSION < 7
        cpLog("%s\n\n", cli->big_data_tmp.c);
#else
        cpLog("%s\n\n", ZSTR_VAL(cli->big_data_tmp.s));
#endif
        smart_str_free(&cli->big_data_tmp);
    }
}

void log_increase_size(int size, cpClient* cli)
{
    if (CPGS->max_data_size_to_log)
    {
        cli->current_len += size;
    }
}
