# lb-from-scratch-rust
librice/lb-from-scratch RUST implement

# Prerequisites
Docker Image: `library/maborosiii/lb-from-scratch-rust`

0. docker images `nginx:backend_1` change the output from nginx deafult html to print "backend_1", so does `nginx:backend_2`, print "backend_2"

1. start docker container
```sh
#!/bin/bash
docker run -d --name client nginx:alpine
docker run -d --privileged --security-opt seccomp=unconfined --name lb maborosiii/lb-from-scratch-rust
docker run -d --name backend_1 nginx:backend_1
docker run -d --name backend_2 nginx:backend_2
```
container's ip
|ip|conainer name|
|-|-|
|172.17.0.2|client|
|172.17.0.3|lb|
|172.17.0.4|backend_1|
|172.17.0.5|backend_2|

# start test
enter `client` container
```shell
$ docker exec -it client sh
$ curl 172.17.0.3 (lb ip)
```
watch the result which print "backend_1" or "backend2"
also watch the output from lb
```plain
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] before eth addr 2:42:ac:11:0:2 -> 2:42:ac:11:0:3
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] SRC IP: 172.17.0.3, DST IP: 172.17.0.4
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] after eth addr 2:42:ac:11:0:3 -> 2:42:ac:11:0:4
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] before eth addr 2:42:ac:11:0:4 -> 2:42:ac:11:0:3
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] SRC IP: 172.17.0.3, DST IP: 172.17.0.2
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] after eth addr 2:42:ac:11:0:3 -> 2:42:ac:11:0:2
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] before eth addr 2:42:ac:11:0:2 -> 2:42:ac:11:0:3
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] SRC IP: 172.17.0.3, DST IP: 172.17.0.5
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] after eth addr 2:42:ac:11:0:3 -> 2:42:ac:11:0:5
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] before eth addr 2:42:ac:11:0:5 -> 2:42:ac:11:0:3
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] SRC IP: 172.17.0.3, DST IP: 172.17.0.2
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] after eth addr 2:42:ac:11:0:3 -> 2:42:ac:11:0:2
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] before eth addr 2:42:ac:11:0:2 -> 2:42:ac:11:0:3
[2024-08-31T07:26:56Z INFO  lb_from_scratch_rust] SRC IP: 172.17.0.3, DST IP: 172.17.0.5
```

# NOTE
***this project just work in xdp `generic` mode, cannot work in xdp `native` mode***

***use `XdpFlags::SKB_MODE` instead of `XdpFlags::default()` and `XdpFlags::DRV_MODE`*** in aya user program