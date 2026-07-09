package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" Phantom ./programs/phantom.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" Egress ./programs/phantom_egress.c

// Loader manages eBPF program loading and attachment
type Loader struct {
	PhantomObjs *PhantomObjects
	EgressObjs  *EgressObjects
	xdpLink     link.Link
}

// NewLoader creates a new eBPF loader
func NewLoader() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to lock memory: %w", err)
	}

	phantomObjs := &PhantomObjects{}
	if err := LoadPhantomObjects(phantomObjs, nil); err != nil {
		return nil, fmt.Errorf("failed to load phantom objects: %w", err)
	}

	return &Loader{
		PhantomObjs: phantomObjs,
	}, nil
}

// LoadEgress loads the egress eBPF program
func (l *Loader) LoadEgress() error {
	egressObjs := &EgressObjects{}
	if err := LoadEgressObjects(egressObjs, nil); err != nil {
		return fmt.Errorf("failed to load egress objects: %w", err)
	}
	l.EgressObjs = egressObjs
	return nil
}

// AttachXDP attaches XDP program to network interface
func (l *Loader) AttachXDP(ifaceIndex int) (link.Link, error) {
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   l.PhantomObjs.PhantomProg,
		Interface: ifaceIndex,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP: %w", err)
	}
	l.xdpLink = xdpLink
	return xdpLink, nil
}

// Close cleans up eBPF resources
func (l *Loader) Close() error {
	if l.xdpLink != nil {
		if err := l.xdpLink.Close(); err != nil {
			return err
		}
	}
	if l.PhantomObjs != nil {
		l.PhantomObjs.Close()
	}
	if l.EgressObjs != nil {
		l.EgressObjs.Close()
	}
	return nil
}

