//go:build freebsd || dragonfly || netbsd || openbsd
// +build freebsd dragonfly netbsd openbsd

package main

import (
	"net"
	"syscall"
)

func bind_device(s int, iface *net.Interface) {
	addrs, err := iface.Addrs()
	if err != nil {
		log.WithError(err).Fatalf("unable to get addresses")
	}
	var addr net.IP
	for _, a := range addrs {
		if addr, _, err = net.ParseCIDR(a.String()); err != nil {
			log.WithError(err).Fatalf("unable to parse %s", a.String())
		}
		if addr.To4() != nil {
			break
		}
	}
	if addr == nil {
		log.Fatalf("unable to bind to %s", iface.Name)
	}

	sa := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]},
	}
	if err = syscall.Bind(s, &sa); err != nil {
		log.WithError(err).Fatalf("unable to bind")
	}
}
