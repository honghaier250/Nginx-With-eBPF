# nginx_with_ebpf
基于eBPF技术探测Nginx并拓展其能力。

## 依赖


## 构建

```shell
sudo bash ./build_nginx.sh
sudo bash ./build_bpftrace.sh
```

## 运行

```shell
sudo bash ./start.sh

# list all uprobe
sudo bpftrace -l 'uprobe:/opt/nginx/sbin/nginx:*'

```

## 拓展
- [bpftrace](https://github.com/bpftrace/bpftrace)



## 交流

![二维码](./wechat.png)


