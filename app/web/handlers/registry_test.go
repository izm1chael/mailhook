package handlers

import (
	"context"
	"sync"
	"testing"
)

// stubActions is a no-op IMAPActions for testing.
type stubActions struct{ name string }

func (s *stubActions) MoveToQuarantine(_ context.Context, _ string, _ uint32) (uint32, string, error) {
	return 0, "", nil
}
func (s *stubActions) ReleaseToInbox(_ context.Context, _ uint32) error                  { return nil }
func (s *stubActions) DeleteMessage(_ context.Context, _ string, _ uint32) error          { return nil }
func (s *stubActions) BulkReleaseToInbox(_ context.Context, _ []uint32) error             { return nil }
func (s *stubActions) BulkDeleteMessages(_ context.Context, _ string, _ []uint32) error   { return nil }

// stubProcessor is a no-op EmailProcessor for testing.
type stubProcessor struct{ name string }

func (s *stubProcessor) Process(_ context.Context, _ string, _ []byte, _ uint32, _ string) {}

func TestRegistry_AddGetRemove(t *testing.T) {
	r := NewAccountRegistry()

	act := &stubActions{name: "acct1-act"}
	proc := &stubProcessor{name: "acct1-proc"}

	r.Add("acct1", act, proc)

	gotAct, ok := r.GetActions("acct1")
	if !ok {
		t.Fatal("GetActions: expected ok=true after Add")
	}
	if gotAct != act {
		t.Error("GetActions: returned wrong actions")
	}

	gotProc, ok := r.GetProcessor("acct1")
	if !ok {
		t.Fatal("GetProcessor: expected ok=true after Add")
	}
	if gotProc != proc {
		t.Error("GetProcessor: returned wrong processor")
	}

	r.Remove("acct1")

	if _, ok := r.GetActions("acct1"); ok {
		t.Error("GetActions: expected ok=false after Remove")
	}
	if _, ok := r.GetProcessor("acct1"); ok {
		t.Error("GetProcessor: expected ok=false after Remove")
	}
}

func TestRegistry_AddOverwrites(t *testing.T) {
	r := NewAccountRegistry()

	r.Add("acct1", &stubActions{name: "v1"}, &stubProcessor{name: "v1"})

	newAct := &stubActions{name: "v2"}
	r.Add("acct1", newAct, &stubProcessor{name: "v2"})

	got, ok := r.GetActions("acct1")
	if !ok {
		t.Fatal("GetActions: expected ok=true")
	}
	if got.(*stubActions).name != "v2" {
		t.Errorf("Add should overwrite: got %q, want %q", got.(*stubActions).name, "v2")
	}
}

func TestRegistry_MissingAccount(t *testing.T) {
	r := NewAccountRegistry()

	if _, ok := r.GetActions("nonexistent"); ok {
		t.Error("GetActions: expected ok=false for missing account")
	}
	if _, ok := r.GetProcessor("nonexistent"); ok {
		t.Error("GetProcessor: expected ok=false for missing account")
	}
}

func TestRegistry_RemoveNonexistent(t *testing.T) {
	r := NewAccountRegistry()
	// Should not panic
	r.Remove("does-not-exist")
}

// TestRegistry_ConcurrentAccess verifies no data races under concurrent Add/Remove/Get.
func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewAccountRegistry()
	const goroutines = 20
	const accounts = 5

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := "acct" + string(rune('0'+id%accounts))
			act := &stubActions{}
			proc := &stubProcessor{}
			r.Add(name, act, proc)
			r.GetActions(name)
			r.GetProcessor(name)
			if id%3 == 0 {
				r.Remove(name)
			}
		}(i)
	}
	wg.Wait()
}
