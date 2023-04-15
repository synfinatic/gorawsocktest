# Go RAW Socket Test

Some test code using RAW sockets that doesn't work.

## Darwin/macOS
### C

* Can send UDP datagrams with our IP
* Can send UDP datagrams with a spoofed IP

### GoLang
* Can _NOT_ send UDP datagrams at all

## Linux
### C

* Can send UDP datagrams with our IP
* Can send UDP datagrams with a spoofed IP

### GoLang

* Can send UDP datagrams with our IP
* Can send UDP datagrams with a spoofed IP, _BUT_ they are always delievered 
    over loopback regardless if the socket is bound to a different interface.

## FreeBSD
### C

* Can send UDP datagrams with our IP
* Can send UDP datagrams with a spoofed IP

### GoLang
Untested

## Resources

* [rawip.txt](https://www.digiater.nl/openvms/decus/vmslt01b/sec/rawip.txt)
* [SOCK_RAW Demystified](https://sock-raw.org/papers/sock_raw)
* [Introduction to RAW-sockets](https://tuprints.ulb.tu-darmstadt.de/6243/1/TR-18.pdf)
* [traceroute source code](ftp://ftp.ee.lbl.gov/traceroute-1.4a12.tar.gz)