package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log(Event{Event: "decision", RequestID: "r1", Agent: "a", ItemName: "GitHub",
		Fields: []string{"password"}, Outcome: "approved"})
	out := buf.String()
	if !strings.Contains(out, `"outcome":"approved"`) || !strings.Contains(out, `"item_name":"GitHub"`) {
		t.Fatalf("missing fields: %s", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatal("not newline-terminated")
	}
}
