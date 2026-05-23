package feeds

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileSafe_WritesCorrectContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.csv")
	data := []byte("hello,world\n")

	if err := writeFileSafe(path, data, 0o640); err != nil {
		t.Fatalf("writeFileSafe: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}
}

func TestWriteFileSafe_NoTempFileRemains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.csv")

	if err := writeFileSafe(path, []byte("data"), 0o640); err != nil {
		t.Fatalf("writeFileSafe: %v", err)
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file still exists after successful writeFileSafe")
	}
}

func TestWriteFileSafe_FailsOnBadDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent", "deep", "cache.csv")
	if err := writeFileSafe(path, []byte("x"), 0o640); err == nil {
		t.Error("expected error writing to non-existent directory, got nil")
	}
}
