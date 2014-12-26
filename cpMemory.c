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
  | original: Tianfeng Han    modify:Xinhua Guo  <woshiguo35@sina.com>|
  +----------------------------------------------------------------------+
 */

#include "php_connect_pool.h"

void *cp_mmap_calloc(int size) {
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

int cpShareMemory_sysv_create(cpShareMemory *object, int size, int key) {
    int shmid;
    void *mem = NULL;
    bzero(object, sizeof (cpShareMemory));

    if (key == 0)
    {
        key = IPC_PRIVATE;
    }
    if ((shmid = shmget(key, size, SHM_R | SHM_W | IPC_CREAT | 0666)) < 0)
    {
        cpLog("shmget Error: %s[%d]", strerror(errno), errno);
        return 0;
    }
    object->key = key;
    object->shmid = shmid;
    object->size = size;
    object->mem = mem;
    return shmid;
}

int cpShareMemory_sysv_free(cpShareMemory *object, int rm) {
    int ret = shmdt(object->mem);
    if (rm == 1)
    {
        shmctl(object->shmid, IPC_RMID, NULL);
    }
    object->mem = NULL;
    return ret;
}

