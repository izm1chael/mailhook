// Package testserver provides a fake IMAP server for integration testing.
// It uses the go-imap/v2 imapserver package (already a project dependency) to
// present a minimal TLS-IMAP server that the real Listener and Manager code can
// connect to without a live mail server.
package testserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// Message is a fake email delivered to the server inbox.
type Message struct {
	Raw     []byte // full RFC822 bytes
	UID     imap.UID
	Seen    bool
	Deleted bool
}

// Server is a minimal TLS IMAP server for testing.
type Server struct {
	mu       sync.RWMutex
	msgs     []*Message
	sessions []*session
	notify   chan struct{} // closed + replaced each time a message is delivered
	nextUID  imap.UID

	srv      *imapserver.Server
	listener net.Listener
	tlsCert  *tls.Certificate // kept for TLSClientConfig
	done     chan struct{}
}

// New starts a fake IMAP server on a random loopback port with a self-signed TLS cert.
// Call Close() when done.
func New(username, password string) (*Server, error) {
	cert, tlsCfg, err := selfSignedTLS()
	if err != nil {
		return nil, fmt.Errorf("testserver: TLS setup: %w", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("testserver: listen: %w", err)
	}

	fs := &Server{
		notify:  make(chan struct{}),
		nextUID: 1,
		done:    make(chan struct{}),
		tlsCert: cert,
	}

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			s := &session{server: fs, username: username, password: password}
			fs.mu.Lock()
			fs.sessions = append(fs.sessions, s)
			fs.mu.Unlock()
			return s, nil, nil
		},
		Caps:      imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIdle: {}},
		TLSConfig: tlsCfg,
	})

	_ = tlsCfg // used via ln
	fs.srv = srv
	fs.listener = ln

	go func() {
		srv.Serve(ln) //nolint:errcheck
		close(fs.done)
	}()
	return fs, nil
}

// Addr returns "host:port" the server is listening on.
func (fs *Server) Addr() string { return fs.listener.Addr().String() }

// Host returns just the host part of the listen address.
func (fs *Server) Host() string {
	host, _, _ := net.SplitHostPort(fs.listener.Addr().String())
	return host
}

// Port returns the listen port as an int.
func (fs *Server) Port() int {
	_, portStr, _ := net.SplitHostPort(fs.listener.Addr().String())
	var p int
	fmt.Sscan(portStr, &p)
	return p
}

// Deliver injects a raw RFC822 message into the INBOX and notifies any IDLing sessions.
func (fs *Server) Deliver(raw []byte) {
	fs.mu.Lock()
	uid := fs.nextUID
	fs.nextUID++
	fs.msgs = append(fs.msgs, &Message{Raw: raw, UID: uid})
	old := fs.notify
	fs.notify = make(chan struct{})
	fs.mu.Unlock()
	close(old) // wakes all sessions currently in Idle()
}

// Messages returns a snapshot of all delivered messages.
func (fs *Server) Messages() []*Message {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := make([]*Message, len(fs.msgs))
	copy(out, fs.msgs)
	return out
}

// Close shuts down the server.
func (fs *Server) Close() error {
	fs.listener.Close()
	<-fs.done
	return nil
}

// TLSClientConfig returns a *tls.Config that trusts the server's self-signed cert.
func (fs *Server) TLSClientConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(fs.tlsCert.Leaf)
	return &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

// ---- session ----

type session struct {
	server   *Server
	username string
	password string
	selected bool // INBOX selected
}

func (s *session) Close() error { return nil }

func (s *session) Login(username, password string) error {
	if username == s.username && password == s.password {
		return nil
	}
	return imapserver.ErrAuthFailed
}

func (s *session) Select(mailbox string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	s.selected = true
	s.server.mu.RLock()
	n := uint32(len(s.server.msgs))
	s.server.mu.RUnlock()
	return &imap.SelectData{
		Flags:       []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted},
		PermanentFlags: []imap.Flag{imap.FlagSeen},
		NumMessages: n,
		UIDValidity: 1,
		UIDNext:     imap.UID(n + 1),
	}, nil
}

func (s *session) Create(_ string, _ *imap.CreateOptions) error { return nil }
func (s *session) Delete(_ string) error                        { return nil }
func (s *session) Rename(_, _ string) error                     { return nil }
func (s *session) Subscribe(_ string) error                     { return nil }
func (s *session) Unsubscribe(_ string) error                   { return nil }

func (s *session) List(w *imapserver.ListWriter, _ string, patterns []string, _ *imap.ListOptions) error {
	return w.WriteList(&imap.ListData{Mailbox: "INBOX", Delim: '/'})
}

func (s *session) Status(mailbox string, opts *imap.StatusOptions) (*imap.StatusData, error) {
	s.server.mu.RLock()
	n := uint32(len(s.server.msgs))
	s.server.mu.RUnlock()
	d := &imap.StatusData{Mailbox: mailbox}
	if opts.NumMessages {
		d.NumMessages = &n
	}
	uid := imap.UID(n + 1)
	if opts.UIDNext {
		d.UIDNext = uid
	}
	if opts.UIDValidity {
		d.UIDValidity = 1
	}
	return d, nil
}

func (s *session) Append(_ string, r imap.LiteralReader, _ *imap.AppendOptions) (*imap.AppendData, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	s.server.Deliver(raw)
	s.server.mu.RLock()
	uid := s.server.msgs[len(s.server.msgs)-1].UID
	s.server.mu.RUnlock()
	return &imap.AppendData{UID: uid, UIDValidity: 1}, nil
}

func (s *session) Poll(w *imapserver.UpdateWriter, _ bool) error {
	s.server.mu.RLock()
	n := uint32(len(s.server.msgs))
	s.server.mu.RUnlock()
	return w.WriteNumMessages(n)
}

func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	for {
		s.server.mu.RLock()
		notifyCh := s.server.notify
		s.server.mu.RUnlock()

		select {
		case <-stop:
			return nil
		case <-notifyCh:
			s.server.mu.RLock()
			n := uint32(len(s.server.msgs))
			s.server.mu.RUnlock()
			if err := w.WriteNumMessages(n); err != nil {
				return err
			}
		}
	}
}

func (s *session) Unselect() error { s.selected = false; return nil }

func (s *session) Expunge(_ *imapserver.ExpungeWriter, uidSet *imap.UIDSet) error {
	s.server.mu.Lock()
	defer s.server.mu.Unlock()

	kept := s.server.msgs[:0]
	for _, m := range s.server.msgs {
		if !m.Deleted {
			kept = append(kept, m)
			continue
		}
		// If a UID set was provided (UID EXPUNGE), only remove those UIDs.
		if uidSet != nil && !uidSet.Contains(m.UID) {
			kept = append(kept, m)
		}
	}
	s.server.msgs = kept
	return nil
}

func (s *session) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	s.server.mu.RLock()
	msgs := s.server.msgs
	s.server.mu.RUnlock()

	wantUnseen := false
	for _, f := range criteria.NotFlag {
		if f == imap.FlagSeen {
			wantUnseen = true
		}
	}

	if numKind == imapserver.NumKindUID {
		var uids []imap.UID
		for _, m := range msgs {
			if wantUnseen && m.Seen {
				continue
			}
			// If the criteria includes a UID filter, check all sets (AND semantics).
			matched := true
			for _, us := range criteria.UID {
				if !us.Contains(m.UID) {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			uids = append(uids, m.UID)
		}
		return &imap.SearchData{All: imap.UIDSetNum(uids...)}, nil
	}

	var seqNums []uint32
	for i, m := range msgs {
		if wantUnseen && m.Seen {
			continue
		}
		seqNums = append(seqNums, uint32(i+1))
	}
	return &imap.SearchData{All: imap.SeqSetNum(seqNums...)}, nil
}

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	s.server.mu.RLock()
	msgs := s.server.msgs
	s.server.mu.RUnlock()

	for i, m := range msgs {
		seqNum := uint32(i + 1)
		switch ns := numSet.(type) {
		case imap.SeqSet:
			if !ns.Contains(seqNum) {
				continue
			}
		case imap.UIDSet:
			if !ns.Contains(m.UID) {
				continue
			}
		default:
			continue
		}
		rw := w.CreateMessage(seqNum)
		if options.UID {
			rw.WriteUID(m.UID)
		}
		rw.WriteFlags(func() []imap.Flag {
			if m.Seen {
				return []imap.Flag{imap.FlagSeen}
			}
			return nil
		}())
		for _, bs := range options.BodySection {
			wc := rw.WriteBodySection(bs, int64(len(m.Raw)))
			wc.Write(m.Raw) //nolint:errcheck
			wc.Close()      //nolint:errcheck
		}
		rw.Close() //nolint:errcheck
	}
	return nil
}

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	s.server.mu.Lock()
	defer s.server.mu.Unlock()

	applyFlags := func(m *Message) {
		for _, f := range flags.Flags {
			switch f {
			case imap.FlagSeen:
				m.Seen = flags.Op != imap.StoreFlagsDel
			case imap.FlagDeleted:
				m.Deleted = flags.Op != imap.StoreFlagsDel
			}
		}
	}

	switch ns := numSet.(type) {
	case imap.SeqSet:
		for i, m := range s.server.msgs {
			if ns.Contains(uint32(i + 1)) {
				applyFlags(m)
			}
		}
	case imap.UIDSet:
		for _, m := range s.server.msgs {
			if ns.Contains(m.UID) {
				applyFlags(m)
			}
		}
	}
	return nil
}

func (s *session) Copy(numSet imap.NumSet, _ string) (*imap.CopyData, error) {
	// Assign a new UID to the copy so callers can capture the destination UID
	// from CopyData.DestUIDs (needed by MoveToQuarantine's UID capture logic).
	s.server.mu.Lock()
	newUID := s.server.nextUID
	s.server.nextUID++
	s.server.mu.Unlock()

	// Both SourceUIDs and DestUIDs must be non-empty for the COPYUID response
	// code to encode correctly. Extract source UIDs from the incoming NumSet.
	var srcUIDs imap.UIDSet
	if us, ok := numSet.(imap.UIDSet); ok {
		srcUIDs = us
	} else {
		srcUIDs = imap.UIDSetNum(newUID - 1) // fallback for SeqSet calls
	}

	return &imap.CopyData{
		UIDValidity: 1,
		SourceUIDs:  srcUIDs,
		DestUIDs:    imap.UIDSetNum(newUID),
	}, nil
}

// ---- TLS helpers ----

func selfSignedTLS() (*tls.Certificate, *tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	pub := key.Public()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	cert.Leaf = leaf
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return &cert, tlsCfg, nil
}
