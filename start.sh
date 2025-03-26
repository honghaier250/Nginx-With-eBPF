#!/bin/bash

sudo cp -a conf/* /opt/nginx/conf
sudo /opt/nginx/sbin/nginx -p /opt/nginx -c conf/nginx.conf -s stop
sleep 2
sudo /opt/nginx/sbin/nginx -p /opt/nginx -c conf/nginx.conf
