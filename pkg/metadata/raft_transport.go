// Copyright 2026 TTBT Enterprises LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metadata

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/hashicorp/raft"
)

// TLSStreamLayer implements raft.StreamLayer interface for mTLS.
type TLSStreamLayer struct {
	listener  net.Listener
	config    *tls.Config // Server config
	dialer    *net.Dialer
	advertise net.Addr
}

func NewTLSStreamLayer(bindAddr string, advertise net.Addr, config *tls.Config) (*TLSStreamLayer, error) {
	listener, err := tls.Listen("tcp", bindAddr, config)
	if err != nil {
		return nil, err
	}

	if advertise == nil {
		advertise = listener.Addr()
	}

	return &TLSStreamLayer{
		listener:  listener,
		config:    config,
		dialer:    &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
		advertise: advertise,
	}, nil
}

// Dial implements the StreamLayer interface.
func (t *TLSStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	clientConfig := t.config.Clone()
	clientConfig.InsecureSkipVerify = true
	return tls.DialWithDialer(dialer, "tcp", string(address), clientConfig)
}

// Accept implements the net.Listener interface.
func (t *TLSStreamLayer) Accept() (net.Conn, error) {
	return t.listener.Accept()
}

// Close implements the net.Listener interface.
func (t *TLSStreamLayer) Close() error {
	return t.listener.Close()
}

// Addr implements the net.Listener interface.
func (t *TLSStreamLayer) Addr() net.Addr {
	return t.advertise
}
