#!/bin/bash
export PHP_INSTALL_VERSION="5.3.29" &&
export CP_PATH=`pwd` &&

sudo apt-get install -qqy build-essential axel libcurl3-openssl-dev libxslt1-dev re2c libxml2 libxml2-dev bison libbz2-dev libreadline-dev libedit-dev libpng12-0 libpng12-dev libjpeg-dev libjpeg8-dev libjpeg8 libssl-dev openssl gettext libicu-dev libmhash-dev libmhash2 libmcrypt-dev libmcrypt4 uuid-dev net-tools &&

${CP_PATH}/.travis/php_download.sh ${PHP_INSTALL_VERSION} &&

export PHP_BUILD_CONF="--with-libedit --with-pear --enable-fpm --enable-mbstring --with-pcre-dir --enable-mysqlnd --enable-pdo --with-pdo-mysql --with-openssl --with-curl --enable-zip --enable-sockets --enable-bcmath --enable-calendar --enable-ftp --disable-intl --enable-mbstring --enable-pcntl" &&

${CP_PATH}/.travis/php_install.sh "${CP_PATH}" php-${PHP_INSTALL_VERSION}.tar.gz "$PHP_BUILD_CONF" &&

export PHP_PATH=${CP_PATH}/php-${PHP_INSTALL_VERSION} &&
export PHP_BIN_DIR=${PHP_PATH}/bin &&
export PATH="${PHP_BIN_DIR}:${PATH}" &&
export PHP_BIN=${PHP_BIN_DIR}/php &&
export REDIS_VERSION_INSTALL=3.1.1 &&

sudo mkdir -m 777 /var/log/php-connection-pool &&
chmod +x ${CP_PATH}/pool_server ${CP_PATH}/initd-php-connection-pool &&
sudo cp ${CP_PATH}/pool_server /usr/local/bin/pool_server &&
sudo cp ${CP_PATH}/config.ini.example /etc/pool.ini &&
${CP_PATH}/.travis/php_install_ext.sh "${CP_PATH}" "${PHP_PATH}" &&
if [ ! -f /bin/env ];then sudo ln -s /usr/bin/env /bin/env; fi &&
echo 'extension = connect_pool.so' > ${PHP_PATH}/config/conf.d/connect_pool.ini &&
git clone -b ${REDIS_VERSION_INSTALL} https://github.com/phpredis/phpredis.git && ${CP_PATH}/.travis/php_install_ext.sh "${CP_PATH}/phpredis" "${PHP_PATH}" && echo 'extension = redis.so' > ${PHP_PATH}/config/conf.d/redis.ini &&

$PHP_BIN -m &&
$PHP_BIN -m | grep -s connect_pool &&
$PHP_BIN -m | grep -s redis &&
sudo mkdir -m 777 /var/run/cp &&
sudo touch /var/run/php_connection_pool.pid && sudo chmod 777 /var/run/php_connection_pool.pid &&
${CP_PATH}/pool_server start &&

netstat -tlnp |grep 6253 &&
${CP_PATH}/pool_server status &&
env TEST_PHP_EXECUTABLE=$PHP_BIN $PHP_BIN "${PHP_PATH}/run-tests.php" -c "${PHP_PATH}/config/php.ini" --show-diff "${CP_PATH}/tests" |tee /tmp/php_cp_test.result && fail_num=$(grep -o -E "Tests\s+failed\s*:\s*[0-9]{1,}\s*\(" /tmp/php_cp_test.result |grep -o -E "[0-9]{1,}" -) && fail_num=$((fail_num+0)) && echo $fail_num && [ $fail_num -eq 0 ]
echo $?
