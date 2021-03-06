#!/bin/bash
function log_ext()
{
    echo "[install_ext] $@" 1>&2
}

function install_ext()
{
    php_path="$2"
    php="$php_path/bin/php"
    phpize="$php_path/bin/phpize"
    phpcfg="$php_path/bin/php-config"
    if [ ! -f $phpcfg ]; then
        log_ext "invalid PHP path $php_path"
        return 1
    fi

    # change to extension path
    cd $1

    log_ext "ext_path: ${1}"
    log_ext "php_path: ${php_path}"
    log_ext "current_path: `pwd`"

    # configure, make
    $phpize && ./configure --with-php-config=$phpcfg && make install
    ret=$?

    if [ $ret -eq 0 ]; then
        log_ext "done"
    else
        log_ext "fail"
    fi
    cd "${CP_PATH}"

    return $ret
}

# main
if [ $# -ne 2 ]; then
    echo "usage: `basename $0` <extension-path> <php-path>"
    exit 1
fi

# argument
ext_path="$1"
if [ ! -d "$ext_path" ]; then
    log_ext "error: invalid extension-path \"$ext_path\""
    exit 1
fi
log_ext "ext_path: $ext_path"
php_path="$2"
if [ ! -d "$php_path" ]; then
    log_ext "error: invalid PHP path \"$php_path\""
    exit 1
fi
log_ext "php_path: $php_path"

# build
install_ext $ext_path $php_path
