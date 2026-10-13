package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApprovalKeyboardLayout(t *testing.T) {
	buttons := []Button{
		{Text: "✅ Allow once", CallbackData: "a:nonce"},
		{Text: "Approve for 15 min", CallbackData: "a15:nonce"},
		{Text: "Approve for 1h", CallbackData: "a60:nonce"},
		{Text: "Approve forever", CallbackData: "af:nonce"},
		{Text: "⛔ Decline", CallbackData: "d:nonce"},
	}
	type request struct {
		ReplyMarkup struct {
			InlineKeyboard [][]Button `json:"inline_keyboard"`
		} `json:"reply_markup"`
	}
	requests := make(chan request, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		requests <- body
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/bottest/sendMessage" {
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":123}}`))
		} else {
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		}
	}))
	defer srv.Close()
	c := New("test", srv.URL, srv.Client())
	id, err := c.SendMessage(context.Background(), 42, "request", buttons)
	if err != nil || id != 123 {
		t.Fatalf("send: %d %v", id, err)
	}
	if err := c.EditMessageText(context.Background(), 42, id, "approved"); err != nil {
		t.Fatal(err)
	}
	rows := (<-requests).ReplyMarkup.InlineKeyboard
	if len(rows) != len(buttons) {
		t.Fatalf("rows: %v", rows)
	}
	for i, row := range rows {
		if len(row) != 1 || row[0] != buttons[i] {
			t.Fatalf("row %d: %v", i, row)
		}
	}
	if len((<-requests).ReplyMarkup.InlineKeyboard) != 0 {
		t.Fatal("resolved prompt retained buttons")
	}
}
