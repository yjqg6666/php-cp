#!/bin/bash
function log_install()
{
    echo "[install_php] $@" 1>&2
}

function install_php_from_tar()
{
    tar="$2"
    src=`echo $tar | sed 's/^.*\/\?\(php-[0-9]\+\.[0-9]\+\.[0-9]\+\)\.tar\.gz$/\1/'`
    if [ -z "$src" ]; then
        return 1
    fi

    # prepare normal
    log_install "extract tar ball"
    rm -fr $src && tar zxf $tar

    # build
    echo "tar:"$3
    install_php $1 $src "$3"
}

function install_php()
{
    # init
    prefix=$1
    src=$2
    param_extra=$3
    echo "build:"$3
    echo $param_extra

    # version related
    version=`grep ' PHP_VERSION ' $src/main/php_version.h | sed 's/^#define PHP_VERSION "\([0-9a-zA-Z\.]\+\)".*$/\1/'`
    buildname="php-${version}"
    log_install "[$buildname] build"

    cd $src

    # prepare
    #param_general="--disable-all"
    here_dir=$(dirname "$0")
    conf_dir="${prefix}/${buildname}/config"
    conf_ext_dir="${conf_dir}/conf.d"
    [ ! -d "$conf_ext_dir" ] && mkdir -p -m 755 "$conf_ext_dir"
    cp "${prefix}/${buildname}/php.ini-production" "${conf_dir}/php.ini" && ${here_dir}/php_update_ini.sh "${conf_dir}/php.ini"

    param_general="--with-config-file-scan-dir=${conf_dir} --sysconfdir=${conf_dir} --with-config-file-path=${conf_dir}/php.ini --with-config-file-scan-dir=${conf_ext_dir}"
    param_sapi="--enable-cli --disable-cgi"
    cmd="./configure --quiet --prefix=${prefix}/${buildname} $param_general $param_sapi $param_extra"

    # configure
    log_install "[$buildname] configure"
    log_install "$cmd"
    $cmd

    log_install "[$buildname] make"
    # NOT DO a meaningless "make clean"! it's just extracted
    make --quiet --debug=basic 1>/dev/null && \
        make install
    ret=$?

    if [ $ret -eq 0 ]; then
        log_install "[$buildname] done"
    else
        log_install "[$buildname] fail"
    fi
    cd "${CP_PATH}"
}

# main
if [ $# -lt 2 ]; then
    echo "usage: `basename $0` <prefix> <php-tarfile>"
    exit 1
fi

# argument
prefix="$1"
if [ ! -d "$prefix" ]; then
    log_install "error: invalid prefix \"$prefix\""
    exit 1
fi
log_install "prefix: $prefix"
tarfile="$2"
if [ ! -f "$tarfile" ]; then
    log_install "error: invalid PHP tar file \"$tarfile\""
    exit 1
fi
log_install "tarfile: $tarfile"

extra_param="$3"
echo "main:${extra_param}"
[ -n "$extra_param" ] && log_install "extra param: ${extra_param}"

# install
install_php_from_tar $prefix $tarfile "$extra_param"
