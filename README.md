# Go RAW Socket Test

Some test code using RAW sockets that doesn't work.

### Darwin/macOS

 * Good: No errors.  
 * Bad: No packets are ever sent.

### Linux

 * Good: No errors.
 * Bad: All packets end up being delivered locally on loopback
 even if the dst ip is a remote host/network and/or you bind to another
 interface.

### FreeBSD

 * Good: No bugs!
 * Bad: Untested as of this writing.

## Resources

 * [rawip.txt](https://www.digiater.nl/openvms/decus/vmslt01b/sec/rawip.txt)
 * [SOCK_RAW Demystified](https://sock-raw.org/papers/sock_raw)
