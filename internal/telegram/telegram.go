// Package telegram is a tiny Telegram Bot API client covering only what the
// approval flow needs: sendMessage, editMessageText, answerCallbackQuery and
// getUpdates long polling. No webhook / inbound port is required.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to the Bot API. The token is never included in returned errors.
type Client struct {
	base string // e.g. https://api.telegram.org
	tok  string
	hc   *http.Client
}

// New creates a client. baseURL defaults to https://api.telegram.org.
func New(token, baseURL string, hc *http.Client) *Client {
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), tok: token, hc: hc}
}

// User is a Telegram user.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	First    string `json:"first_name"`
}

// Chat is a Telegram chat.
type Chat struct {
	ID int64 `json:"id"`
}

// Message is a (partial) Telegram message.
type Message struct {
	MessageID int    `json:"message_id"`
	From      *User  `json:"from"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}

// CallbackQuery is an inline button press.
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

// Update is a (partial) Telegram update.
type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
}

// Button is an inline keyboard button.
type Button struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type apiResp struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
	ErrorCode   int             `json:"error_code"`
}

// ErrConflict means another consumer (webhook or second instance) is using getUpdates.
var ErrConflict = errors.New("telegram: conflict: another getUpdates consumer or a webhook is active for this bot")

func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+c.tok+"/"+method, bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: bad request URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		// url.Error embeds the full URL (including the bot token). Strip it.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("telegram %s: %v", method, ue.Err)
		}
		return fmt.Errorf("telegram %s: request failed", method)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var r apiResp
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("telegram %s: HTTP %d", method, resp.StatusCode)
	}
	if !r.OK {
		if r.ErrorCode == http.StatusConflict {
			return ErrConflict
		}
		return fmt.Errorf("telegram %s: %d %s", method, r.ErrorCode, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// SendMessage sends plain text (no parse mode, so agent-supplied text cannot
// inject formatting or links) with optional inline buttons, one per row.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string, buttons []Button) (int, error) {
	p := map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true}
	if len(buttons) > 0 {
		rows := make([][]Button, 0, len(buttons))
		for _, button := range buttons {
			rows = append(rows, []Button{button})
		}
		p["reply_markup"] = map[string]any{"inline_keyboard": rows}
	}
	var m Message
	if err := c.call(ctx, "sendMessage", p, &m); err != nil {
		return 0, err
	}
	return m.MessageID, nil
}

// EditMessageText replaces a message's text and removes its inline keyboard.
func (c *Client) EditMessageText(ctx context.Context, chatID int64, messageID int, text string) error {
	return c.call(ctx, "editMessageText", map[string]any{
		"chat_id": chatID, "message_id": messageID, "text": text, "disable_web_page_preview": true,
		"reply_markup": map[string]any{"inline_keyboard": [][]Button{}},
	}, nil)
}

// AnswerCallbackQuery acknowledges a button press (shows a toast to the presser).
func (c *Client) AnswerCallbackQuery(ctx context.Context, id, text string) error {
	return c.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

// GetUpdates long-polls for updates.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeoutSec int) ([]Update, error) {
	var ups []Update
	err := c.call(ctx, "getUpdates", map[string]any{
		"offset": offset, "timeout": timeoutSec,
		"allowed_updates": []string{"callback_query", "message"},
	}, &ups)
	return ups, err
}

// GetMe verifies the token.
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	var u User
	if err := c.call(ctx, "getMe", map[string]any{}, &u); err != nil {
		return nil, err
	}
	return &u, nil
}
