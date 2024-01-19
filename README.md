# INTRODUCTION
lwIP is a small independent implementation of the TCP/IP protocol suite. (https://savannah.nongnu.org/projects/lwip/)

lwIP supports TLS basing on mbedtls. (https://www.trustedfirmware.org/projects/mbed-tls/)

This project integrates OpenSSL into lwIP.

# HOW TO USE

Tested on CentOS 8

1. Install OpenSSL

```shell
yum install openssl openssl-devel
```

2. Create tap interface and net bridge.

```shell
ip tuntap add dev tap0 mode tap
ip link set tap0 up
brctl addbr lwipbridge
brctl addbr lwipbridge
brctl addif lwipbridge tap0
ip addr add 192.168.1.1/24 dev lwipbridge
ip link set dev lwipbridge up
```

3. Start an HTTPS server (e.g. Nginx) and listen on port 443.

4. Compile and run.

```shell
cd lwip
cp ./contrib/examples/example_app/lwipcfg.h.example ./contrib/examples/example_app/lwipcfg.h

# Uncomment "#define USE_DHCP 0" and "#define USE_AUTOIP 0", and set LWIP_OPENSSL_EXAMPLES_APP to 1
vim ./contrib/examples/example_app/lwipcfg.h

cd ./contrib/ports/unix/example_app/
mkdir build && cd build
cmake -DLWIP_DIR=../../../.. ..
make

# Run the test app
./example_app
```

When you run example_app, it will send an HTTPs request "GET /" to 192.168.1.1:443 (which is the IP of lwipbridge), and read the response then print it.

It also starts an HTTPs server listening on 192.168.1.200:443, and you can do "curl -k -v https://192.168.1.200/".
