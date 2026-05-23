package imap_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/config"
	imaplib "github.com/izm1chael/mailhook/imap"
	"github.com/izm1chael/mailhook/imap/testserver"
)

// rawEmail is a minimal RFC822 message for injection.
const rawEmail = "From: alice@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: Integration test\r\n" +
	"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
	"Message-ID: <test-001@example.com>\r\n" +
	"\r\n" +
	"Hello from the testserver integration test.\r\n"

func TestManagerDeliverEmail(t *testing.T) {
	srv, err := testserver.New("testuser", "testpass")
	if err != nil {
		t.Fatalf("testserver.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck

	acfg := config.AccountConfig{
		Name:          "test-account",
		Host:          srv.Host(),
		Port:          srv.Port(),
		User:          "testuser",
		Pass:          "testpass",
		Mailbox:       "INBOX",
		Quarantine:    "Quarantine",
		TLSSkipVerify: true,
	}

	var (
		mu       sync.Mutex
		received [][]byte
		done     = make(chan struct{})
	)

	onEmail := func(_ context.Context, accountName string, raw []byte, uid uint32, mailbox string) {
		mu.Lock()
		received = append(received, raw)
		n := len(received)
		mu.Unlock()
		if n == 1 {
			close(done)
		}
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := imaplib.NewManager(ctx, nil, log)
	if err := mgr.Start(acfg, onEmail); err != nil {
		t.Fatalf("Manager.Start: %v", err)
	}

	// Wait a moment for the listener to connect and enter IDLE.
	time.Sleep(200 * time.Millisecond)

	srv.Deliver([]byte(rawEmail))

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for email delivery callback")
	}

	mu.Lock()
	got := received[0]
	mu.Unlock()

	if string(got) != rawEmail {
		t.Errorf("raw email mismatch:\ngot  %q\nwant %q", got, rawEmail)
	}
}

// TestListenerNoDuplicateDispatch verifies F-055: each message is dispatched
// exactly once, even when multiple SEARCH UNSEEN polls occur before the first
// batch is fully processed (the old seq-number dedup could yield 2–4× dispatches).
func TestListenerNoDuplicateDispatch(t *testing.T) {
	srv, err := testserver.New("testuser", "testpass")
	if err != nil {
		t.Fatalf("testserver.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck

	acfg := config.AccountConfig{
		Name:          "dedup-test",
		Host:          srv.Host(),
		Port:          srv.Port(),
		User:          "testuser",
		Pass:          "testpass",
		Mailbox:       "INBOX",
		Quarantine:    "Quarantine",
		TLSSkipVerify: true,
	}

	// dispatchCounts maps UID → number of times onEmail was called for that UID.
	var dispatchCounts sync.Map
	var totalDispatched atomic.Int32
	const want = 2

	onEmail := func(_ context.Context, _ string, _ []byte, uid uint32, _ string) {
		key := fmt.Sprintf("%d", uid)
		val, _ := dispatchCounts.LoadOrStore(key, new(atomic.Int32))
		val.(*atomic.Int32).Add(1)
		totalDispatched.Add(1)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := imaplib.NewManager(ctx, nil, log)
	if err := mgr.Start(acfg, onEmail); err != nil {
		t.Fatalf("Manager.Start: %v", err)
	}

	// Wait for listener to connect and enter IDLE before delivering messages.
	time.Sleep(200 * time.Millisecond)

	msg1 := "From: a@example.com\r\nSubject: msg1\r\n\r\nBody1\r\n"
	msg2 := "From: b@example.com\r\nSubject: msg2\r\n\r\nBody2\r\n"
	srv.Deliver([]byte(msg1))
	srv.Deliver([]byte(msg2))

	// Wait until both messages have been dispatched at least once.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if totalDispatched.Load() >= want {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Give any spurious re-dispatches a window to arrive.
	time.Sleep(300 * time.Millisecond)

	total := totalDispatched.Load()
	if total < want {
		t.Fatalf("expected %d dispatches, got %d (messages not received)", want, total)
	}
	if total > want {
		t.Errorf("duplicate dispatch detected: expected %d total dispatches, got %d", want, total)
	}

	dispatchCounts.Range(func(key, val any) bool {
		count := val.(*atomic.Int32).Load()
		if count != 1 {
			t.Errorf("UID %s dispatched %d times, want 1", key, count)
		}
		return true
	})
}

// TestActionsMessageExists verifies the MessageExists helper used by F-054's
// verify-before-revert logic: after a Move error, we check the SOURCE mailbox
// for absence (not the destination, since MOVE reassigns UIDs).
func TestActionsMessageExists(t *testing.T) {
	srv, err := testserver.New("testuser", "testpass")
	if err != nil {
		t.Fatalf("testserver.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck

	acfg := config.AccountConfig{
		Name:          "exists-test",
		Host:          srv.Host(),
		Port:          srv.Port(),
		User:          "testuser",
		Pass:          "testpass",
		Mailbox:       "INBOX",
		Quarantine:    "Quarantine",
		TLSSkipVerify: true,
	}

	srv.Deliver([]byte("From: x@example.com\r\nSubject: exists\r\n\r\nBody\r\n"))

	// UID 1 is the first delivered message (testserver nextUID starts at 1).
	knownUID := uint32(1)
	unknownUID := uint32(9999)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	actions := imaplib.NewActions(acfg, log)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	// Message present — MessageExists returns true.
	if ok, err := actions.MessageExists(ctx, "INBOX", knownUID); err != nil {
		t.Fatalf("MessageExists(known): unexpected error: %v", err)
	} else if !ok {
		t.Error("MessageExists(known): expected true, got false")
	}

	// Non-existent UID — MessageExists returns false.
	if ok, err := actions.MessageExists(ctx, "INBOX", unknownUID); err != nil {
		t.Fatalf("MessageExists(unknown): unexpected error: %v", err)
	} else if ok {
		t.Error("MessageExists(unknown): expected false, got true")
	}
}

// TestListenerNoDuplicateDispatchCrossCall verifies F-055 cross-call dedup:
// inFlight must persist across fetchUnseen invocations so a message dispatched
// in a connect-time fetch is not re-dispatched when an IDLE notification
// triggers a second fetch before the first message is marked \Seen.
func TestListenerNoDuplicateDispatchCrossCall(t *testing.T) {
	srv, err := testserver.New("testuser", "testpass")
	if err != nil {
		t.Fatalf("testserver.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck

	acfg := config.AccountConfig{
		Name:          "crosscall-dedup",
		Host:          srv.Host(),
		Port:          srv.Port(),
		User:          "testuser",
		Pass:          "testpass",
		Mailbox:       "INBOX",
		Quarantine:    "Quarantine",
		TLSSkipVerify: true,
	}

	var dispatchCounts sync.Map
	var total atomic.Int32

	// Slow callback: keeps the message UNSEEN (seenCh not drained) while we
	// trigger a second IDLE notification — reproducing the cross-call window.
	onEmail := func(_ context.Context, _ string, _ []byte, uid uint32, _ string) {
		time.Sleep(150 * time.Millisecond)
		key := fmt.Sprintf("%d", uid)
		val, _ := dispatchCounts.LoadOrStore(key, new(atomic.Int32))
		val.(*atomic.Int32).Add(1)
		total.Add(1)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mgr := imaplib.NewManager(ctx, nil, log)
	if err := mgr.Start(acfg, onEmail); err != nil {
		t.Fatalf("Manager.Start: %v", err)
	}

	// Wait for listener to connect and enter IDLE.
	time.Sleep(200 * time.Millisecond)

	// Deliver message 1 → IDLE notification → fetchUnseen dispatches it (slow callback).
	srv.Deliver([]byte("From: a@example.com\r\nSubject: msg1\r\n\r\nBody1\r\n"))
	// Brief pause: dispatch goroutine starts but slow callback has not finished,
	// so msg1 is still UNSEEN on the server.
	time.Sleep(30 * time.Millisecond)

	// Deliver message 2 → second IDLE notification → second fetchUnseen call.
	// Without listener-scoped inFlight, msg1 would be re-dispatched here.
	srv.Deliver([]byte("From: b@example.com\r\nSubject: msg2\r\n\r\nBody2\r\n"))

	// Wait for both callbacks to finish (2 × 150 ms + slack).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if total.Load() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Allow window for any spurious re-dispatches.
	time.Sleep(200 * time.Millisecond)

	got := total.Load()
	if got < 2 {
		t.Fatalf("expected 2 dispatches, got %d (messages not received)", got)
	}
	if got > 2 {
		t.Errorf("duplicate dispatch (F-055 cross-call): expected 2, got %d", got)
	}

	dispatchCounts.Range(func(key, val any) bool {
		if n := val.(*atomic.Int32).Load(); n != 1 {
			t.Errorf("UID %s dispatched %d times, want 1", key, n)
		}
		return true
	})
}

// TestMoveToQuarantineReturnsNewUID verifies F-056: MoveToQuarantine now
// returns the new UID assigned by the server in the destination folder so
// callers can persist it and Release/Delete can address the correct message.
func TestMoveToQuarantineReturnsNewUID(t *testing.T) {
	srv, err := testserver.New("testuser", "testpass")
	if err != nil {
		t.Fatalf("testserver.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck

	acfg := config.AccountConfig{
		Name:          "newuid-test",
		Host:          srv.Host(),
		Port:          srv.Port(),
		User:          "testuser",
		Pass:          "testpass",
		Mailbox:       "INBOX",
		Quarantine:    "Quarantine",
		TLSSkipVerify: true,
	}

	srv.Deliver([]byte("From: attacker@evil.com\r\nSubject: phish\r\n\r\nClick here\r\n"))

	// UID 1 is the first message; the server assigns nextUID (2+) to the copy.
	originalUID := uint32(1)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	actions := imaplib.NewActions(acfg, log)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	newUID, newMailbox, err := actions.MoveToQuarantine(ctx, "INBOX", originalUID)
	if err != nil {
		t.Fatalf("MoveToQuarantine: unexpected error: %v", err)
	}
	if newUID == 0 {
		t.Error("MoveToQuarantine: expected newUID > 0, got 0 (COPYUID not captured)")
	}
	if newUID == originalUID {
		t.Errorf("MoveToQuarantine: newUID (%d) == originalUID (%d); MOVE should reassign UIDs", newUID, originalUID)
	}
	if newMailbox != "Quarantine" {
		t.Errorf("MoveToQuarantine: newMailbox = %q, want \"Quarantine\"", newMailbox)
	}

	// Message must have left the source — MessageExists(INBOX, originalUID) should be false.
	if stillThere, err := actions.MessageExists(ctx, "INBOX", originalUID); err != nil {
		t.Fatalf("MessageExists: unexpected error: %v", err)
	} else if stillThere {
		t.Error("MessageExists(INBOX, originalUID): expected false after move, got true")
	}
}

func TestManagerTest(t *testing.T) {
	srv, err := testserver.New("testuser", "testpass")
	if err != nil {
		t.Fatalf("testserver.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := imaplib.NewManager(context.Background(), nil, log)

	good := config.AccountConfig{
		Host: srv.Host(), Port: srv.Port(),
		User: "testuser", Pass: "testpass",
		TLSSkipVerify: true,
	}
	if err := mgr.Test(context.Background(), good); err != nil {
		t.Errorf("Test with valid creds: unexpected error: %v", err)
	}

	bad := good
	bad.Pass = "wrongpass"
	if err := mgr.Test(context.Background(), bad); err == nil {
		t.Error("Test with wrong creds: expected error, got nil")
	}
}
