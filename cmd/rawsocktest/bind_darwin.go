//go:build darwin
// +build darwin

package main

import (
	"net"
	"syscall"
)

func bind_device(s int, iface *net.Interface) {
	if err := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_BOUND_IF, iface.Index); err != nil {
		log.WithError(err).Fatalf("unable to IP_BOUND_IF")
	}
}
