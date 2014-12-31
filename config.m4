dnl $Id$
dnl config.m4 for extension connect_pool

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(connect_pool, for connect_pool support,
[  --with-connect_pool             Include connect_pool support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(connect_pool, whether to enable connect_pool support,
dnl Make sure that the comment is aligned:
dnl [  --enable-connect_pool           Enable connect_pool support])

if test "$PHP_CONNECT_POOL" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-connect_pool -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/connect_pool.h"  # you most likely want to change this
  dnl if test -r $PHP_CONNECT_POOL/$SEARCH_FOR; then # path given as parameter
  dnl   CONNECT_POOL_DIR=$PHP_CONNECT_POOL
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for connect_pool files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       CONNECT_POOL_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$CONNECT_POOL_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the connect_pool distribution])
  dnl fi

  dnl # --with-connect_pool -> add include path
  dnl PHP_ADD_INCLUDE($CONNECT_POOL_DIR/include)

  dnl # --with-connect_pool -> check for lib and symbol presence
  dnl LIBNAME=connect_pool # you may want to change this
  dnl LIBSYMBOL=connect_pool # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $CONNECT_POOL_DIR/lib, CONNECT_POOL_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_CONNECT_POOLLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong connect_pool lib version or lib not found])
  dnl ],[
  dnl   -L$CONNECT_POOL_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(CONNECT_POOL_SHARED_LIBADD)

  PHP_NEW_EXTENSION(connect_pool, connect_pool.c cpServer.c cpWorker.c \
                    connect_pool_client.c \
                    cpFunction.c \
                    cpMemory.c \
                    cpNetWork.c \
                    cpClientNet.c \
                    cpPingWorker.c \
                    msgpack/msgpack.c \
                    msgpack/msgpack_pack.c\
                    msgpack/msgpack_unpack.c\
                    msgpack/msgpack_convert.c\
                    , $ext_shared)
  PHP_ADD_INCLUDE([$ext_srcdir/include])
fi
