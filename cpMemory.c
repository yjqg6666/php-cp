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
  | Xinhua Guo  <woshiguo35@sina.com>|
  +----------------------------------------------------------------------+
 */

#include "php_connect_pool.h"

void *cp_mmap_calloc(int size)
{
    void *mem;
    int tmpfd = -1;
    int flag = MAP_SHARED;

#ifdef MAP_ANONYMOUS
    flag |= MAP_ANONYMOUS;
#else
    char *mapfile = NULL;
    if (mapfile == NULL)
    {
        mapfile = "/dev/zero";
    }
    if ((tmpfd = open(mapfile, O_RDWR)) < 0)
    {
        return NULL;
    }
    strncpy(object->mapfile, mapfile, SW_SHM_MMAP_FILE_LEN);
    object->tmpfd = tmpfd;
#endif

    mem = mmap(NULL, size, PROT_READ | PROT_WRITE, flag, tmpfd, 0);
#ifdef MAP_FAILED
    if (mem == MAP_FAILED)
#else
    if (!mem)
#endif
    {
        cpLog("mmap fail. Error: %s[%d]", strerror(errno), errno);
        return NULL;
    }
    else
    {
        bzero(mem, size);
        return mem;
    }
}

int cp_create_mmap_file(cpShareMemory *object)
{
    umask(0);
    int fd = open(object->mmap_name, O_RDWR | O_CREAT, S_IROTH | S_IWOTH);
    if (fd == -1)
    {
        cpLog("open fail. Error: %s[%d]", strerror(errno), errno);
        return -1;

    }
    ftruncate(fd, object->size); //extend 黑洞
    close(fd);
    return 0;
};

void* cp_mmap_calloc_with_file(cpShareMemory *object)
{

    int fd = open(object->mmap_name, O_RDWR);
    if (fd == -1)
    {
        cpLog("open fail. Error: %s[%d]", strerror(errno), errno);
        return NULL;

    }
    void *mem = mmap(NULL, object->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
#ifdef MAP_FAILED
    if (mem == MAP_FAILED)
#else
    if (!mem)
#endif
    {
        cpLog("mmap fail. Error: %s[%d]", strerror(errno), errno);
        return NULL;
    }
    else
    {
        //        bzero(mem, object->size);
        object->mem = mem;
        return mem;
    }

}


