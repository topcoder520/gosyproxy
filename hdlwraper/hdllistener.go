package hdlwraper

import (
	"net"
)

type Hdllistener struct {
	C net.Conn
}

// Accept waits for and returns the next connection to the listener.
func (l *Hdllistener) Accept() (conn net.Conn, err error) {
	conn = l.C
	l.C = nil
	err = nil
	return
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Hdllistener) Close() error {
	return nil
}

// Addr returns the listener's network address.
func (l *Hdllistener) Addr() net.Addr {
	return nil
}
