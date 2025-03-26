#/bin/bash

cd nginx
bash ./auto/configure --prefix=/opt/nginx \
  --with-debug \
  --with-cc-opt='-Wall -Werror -ggdb3 -gdwarf -O0 -fno-omit-frame-pointer' \
  --with-http_sub_module \
  --with-stream_ssl_preread_module \
  --with-http_realip_module \
  --with-stream_realip_module \
  --with-http_stub_status_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-http_ssl_module \
  --http-fastcgi-temp-path=/dev/null \
  --http-uwsgi-temp-path=/dev/null \
  --http-scgi-temp-path=/dev/null \
  --http-client-body-temp-path=logs/client-body-temp \
  --http-proxy-temp-path=logs/proxy-temp

make -j$(nproc)
make install
