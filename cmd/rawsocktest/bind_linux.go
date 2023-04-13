//go:build linux
// +build linux

package main

import (
	"net"
	"syscall"
)

func bind_device(s int, iface *net.Interface) {
	if err := syscall.SetsockoptString(s, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name); err != nil {
		log.WithError(err).Fatalf("unable to SO_BINDTODEVICE")
	}
}
