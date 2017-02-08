#!/bin/bash
function log_update_config()
{
    echo "[update_php_config] $@" 1>&2
}

function update_php_config()
{
    file_path="$1"
    if [ ! -f $file_path ]; then
        log_update_config "PHP config file ${file_path} DO NOT exist"
        return 1
    fi
    sed -i -e "/^;date.timezone/c\date.timezone = Asia/Chongqing" "${file_path}"
    ret=$?

    if [ $ret -eq 0 ]; then
        log_update_config "done successfully"
    else
        log_update_config "failed"
    fi
    return $ret;
}

# install
update_php_config "$1"
