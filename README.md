# eBPF HTTP Parser

## Installation (self-build)
requirements
- LLVM Clang 9
- Go runtime
```
$ make
$ ./parser
```

https://github.com/cilium/ebpf/blob/0d439865ca157accbc60cc6f3cbeb028fa7901cb/testdata/docker/Dockerfile
The Dockerfile of `cilium/ebpf` will be a reference for building environment.

## Supported hooks
- [x] HTTP with `sys_send()` / `sys_recv()`
- [x] HTTP with `sys_sendto()` / `sys_recvfrom()`
- [x] HTTP with `sys_write()` / `sys_read()`

## Unsupported hooks (ToDo)
- [ ] HTTPS with Golang `net/http` Library
- [ ] HTTPS with `OpenSSL`
- [ ] HTTPS with `LibreSSL`
- [ ] HTTPS with `GnuSSL`
- [ ] HTTPS with `BoringSSL`
- [ ] HTTP/2
