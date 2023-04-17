# Go RAW Socket Test

A little project to illustrate how `SOCK_RAW` sockets work on various operating systems.
All testing has been done on an x86_64/little endian architecture.

The C code is a simplified version of [traceroute](
ftp://ftp.ee.lbl.gov/traceroute-1.4a12.tar.gz).

```C
int s;
char [XXX]packet = {0x45, ...}; // IPv4 header and above
int pktlen = XXX;
int on = 1;

s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&pktlen, sizeof(pktlen));
setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));
struct sockaddr_in whereto;
whereto.sin_len = sizeof(struct sockaddr_in);
whereto.sin_family = AF_INET;
whereto.sin_addr.s_addr = inet_aton("x.x.x.x");

sendto(s, (char *)packet, packetlen, 0, &whereto, sizeof(whereto));
```

## Darwin/macOS

Testing indicates that the `IP.Length` field must be in _host byte order_ 
when you calculate the IP/UDP/TCP checksums and then write the packet to the socket.  Packets
with invalid `IP.Length` fields will be silently dropped by the kernel.

The TCP/UDP header lengths should still be in _network byte order_.


### C

* Can send UDP datagrams with our IP
* Can send UDP datagrams with a spoofed IP

### GoLang
* Can _NOT_ send UDP datagrams at all

## Linux

Testing indicates that the `IP.Length` field can be in _host OR network byte 
order_ when you calculate the IP/UDP/TCP checksums and then write the packet to the socket.

The TCP/UDP header lengths must always be in _network byte order_.

### C

* Can send UDP datagrams with our IP
* Can send UDP datagrams with a spoofed IP

### GoLang

* Can send UDP datagrams with our IP
* Can send UDP datagrams with a spoofed IP, _BUT_ they are always delievered 
    over loopback regardless if the socket is bound to a different interface.

## FreeBSD

Testing indicates that the `IP.Length` field must be in _network byte order_.
when you calculate the IP/UDP/TCP checksums and then write the packet to the socket.  Packets
with invalid `IP.Length` fields will generate an error by the kernel.

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
