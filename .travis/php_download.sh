#!/bin/bash
function log_download()
{
    echo "[download_php] $@" 1>&2
}

function download_php()
{
    url="$1"
    tar="$2"

    wget -t3 -T3 -O "${tar}.tmp" "${url}"

    ret=$?
    if [ $ret -eq 0 ]; then
        mv -f ${tar}.tmp $tar
        log_download "done $tar"
    else
        rm -f ${tar}.tmp
        log_download "fail"
    fi

    return $ret
}


# main
if [ -z "$1" ]; then
    echo "usage: `basename $0` <ver.si.on>"
    exit 1
fi
version="$1"
log_download "version: $version"

# choose source
tar_file="php-${version}.tar.gz"
url="https://secure.php.net/get/${tar_file}/from/this/mirror"

# download
log_download "download from $url"
download_php "$url" "$tar_file"
