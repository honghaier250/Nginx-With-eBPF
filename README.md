# Nginx-With-eBPF
[第三届eBPF开发者大会](https://ebpftravel.com/index.html)主题分享：[基于eBPF的Nginx可观测性实践](./docs/基于eBPF的Nginx可观测性实践.pptx)


## 构建

```shell
sudo bash ./build_nginx.sh
sudo bash ./build_bpftrace.sh

sudo bash ./start_nginx.sh

# list all uprobe
sudo bpftrace -l 'uprobe:/opt/nginx/sbin/nginx:*'
```



## 工具集

tools/ngx_http_process_request.bt
---
用法:   `sudo bpftrace -I nginx_headers ngx_http_process_request.bt`

用途：探测Nginx请求URI

tools/ngx_func_latency.bt　
---
用法:   `sudo bpftrace -I nginx_headers ngx_func_latency.bt　nginx_func_name`

用途：探测Nginx指定函数执行时间

tools/ngx_ssl_sessoin_size.bt
---
用法:   `sudo bpftrace -I nginx_headers ngx_ssl_sessoin_size.bt`

用途：探测Nginx SSLSession尺寸

tools/ngx_request_phase_latency.bt
---
用法:   `sudo bpftrace -I nginx_headers ngx_request_phase_latency.bt`

用途：探测Nginx请求耗时与上游处理耗时

tools/ngx_accept_mutex.bt
---
用法:   `sudo bpftrace -I nginx_headers ngx_accept_mutex.bt`

用途：探测Nginx Worker进程对ngx_accept_mutex的持有情况

tools/ngx_requests_load_between_workers.bt
---
用法:   `sudo bpftrace -I nginx_headers ngx_requests_load_between_workers.bt`

用途：探测Nginx Worker进程间请求负载情况



## 拓展

- [bpftrace](https://github.com/bpftrace/bpftrace)



## 交流

![二维码](./wechat.png)

