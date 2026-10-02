// Package notify sends Apprise-style notifications (title, body, type) to
// an HTTP endpoint such as Lookout's /notify/<key> or apprise-api.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var client = &http.Client{Timeout: 15 * time.Second}

// Send posts one notification. kind is info, success, warning or failure.
// An empty url sends nothing.
func Send(ctx context.Context, url, kind, title, body string) error {
	if url == "" {
		return nil
	}
	raw, _ := json.Marshal(map[string]string{"title": title, "body": body, "type": kind, "tag": "gatehouse"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// The URL holds a key: report the failure without it.
		return fmt.Errorf("could not reach the notify URL")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("the notify URL answered HTTP %d", resp.StatusCode)
	}
	return nil
}
