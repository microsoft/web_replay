// Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.

package webreplay

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

const defaultIdleTimeout = 5 * time.Minute

type tcpKeepAliveListener struct {
	ma *MultipleArchive
	*net.TCPListener
}

type keepAliveConn struct {
	idleTimeout    time.Duration
	idleTimeoutSet bool
	serverName     string
	ln             *tcpKeepAliveListener
	*net.TCPConn
}

func GetTCPKeepAliveListener(host string, port int, ma *MultipleArchive) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:%d", host, port))
	if err != nil {
		return nil, err
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}

	return tcpKeepAliveListener{ma, ln}, nil
}

func ConnStateHook(c net.Conn, state http.ConnState) {
	tlsConn, ok := c.(*tls.Conn)

	if !ok {
		return
	}

	keepAliveConn, ok := tlsConn.NetConn().(*keepAliveConn)

	if !ok || keepAliveConn.idleTimeoutSet {
		return
	}

	switch state {
	case http.StateActive:
		keepAliveConn.serverName = tlsConn.ConnectionState().ServerName
	case http.StateIdle:
		if keepAliveConn.ln.ma != nil {
			idleTimeout, err := keepAliveConn.ln.ma.FindIdleTimeout(keepAliveConn.serverName)
			if err == nil {
				keepAliveConn.idleTimeout = idleTimeout
			}
		}
		keepAliveConn.idleTimeoutSet = true
	}
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	return createKeepAliveConn(tc, &ln), nil
}

func createKeepAliveConn(c *net.TCPConn, ln *tcpKeepAliveListener) net.Conn {
	c.SetKeepAlive(false)

	return &keepAliveConn{
		idleTimeout:    defaultIdleTimeout,
		idleTimeoutSet: false,
		ln:             ln,
		TCPConn:        c,
	}
}

func (c *keepAliveConn) Read(b []byte) (n int, err error) {
	n, err = c.TCPConn.Read(b)
	if err == nil {
		c.updateDeadline()
	}
	return n, err
}

func (c *keepAliveConn) Write(b []byte) (n int, err error) {
	n, err = c.TCPConn.Write(b)
	if err == nil {
		c.updateDeadline()
	}
	return n, err
}

func (c *keepAliveConn) updateDeadline() {
	c.TCPConn.SetDeadline(time.Now().Add(c.idleTimeout))
}
