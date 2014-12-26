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

int cpClient_close(cpClient *cli) {
    int ret, fd = cli->sock;
    cli->sock = 0;
    ret = close(fd);
    if (ret < 0)
    {
        cpLog("client close fail. Error: %s[%d]", strerror(errno), errno);
    }
    return ret;
}

int cpClient_recv(cpClient *cli, void *data, int len, int waitall) {
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
    return cpNetRead(cli->sock, data, len);
}

int cpClient_send(int sock, char *data, int length, int flag) {
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

int cpClient_create(cpClient *cli) {
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

static int swClient_inet_addr(struct sockaddr_in *sin, char *string) {
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

int cpClient_connect(cpClient *cli, char *host, int port, double timeout, int nonblock) {
    int ret;
    cli->serv_addr.sin_family = AF_INET;
    cli->serv_addr.sin_port = htons(port);

    if (swClient_inet_addr(&cli->serv_addr, host) < 0)
    {
        return SUCCESS;
    }

    cli->timeout = timeout;

    if (nonblock == 1)
    {
        swSetNonBlock(cli->sock);
    }
    else
    {
        cpSetTimeout(cli->sock, timeout);
    }

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
    if (ret >= 0)
    {
        cli->released = CP_FD_RELEASED;
    }
    return ret;
}