// Package docker starts, stops and inspects containers through the Docker
// API, for scale-to-zero. Those three calls are all Gatehouse makes, so a
// socket proxy that allows only them works too.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	http *http.Client
	base string
}

// New takes a socket path (/var/run/docker.sock), unix:///path or
// tcp://host:port (a socket proxy).
func New(host string) *Client {
	if rest, ok := strings.CutPrefix(host, "tcp://"); ok {
		return &Client{
			http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}},
			base: "http://" + rest,
		}
	}
	socket := strings.TrimPrefix(host, "unix://")
	return &Client{
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
				DisableKeepAlives: true,
			},
		},
		base: "http://docker",
	}
}

// State is what scale-to-zero needs to know about a container.
type State struct {
	Running bool   `json:"running"`
	Status  string `json:"status"` // running, exited, …
	Health  string `json:"health"` // healthy, unhealthy, starting, or ""
}

func (c *Client) do(ctx context.Context, method, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("docker: %v", err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 400 {
		var e struct{ Message string }
		if json.Unmarshal(msg, &e) == nil && e.Message != "" {
			return resp.StatusCode, fmt.Errorf("docker: %s", e.Message)
		}
		return resp.StatusCode, fmt.Errorf("docker answered HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (c *Client) State(ctx context.Context, name string) (State, error) {
	var info struct {
		State struct {
			Status  string
			Running bool
			Health  *struct{ Status string }
		}
	}
	if _, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", &info); err != nil {
		return State{}, err
	}
	st := State{Running: info.State.Running, Status: info.State.Status}
	if info.State.Health != nil {
		st.Health = info.State.Health.Status
	}
	return st, nil
}

// Start starts a container; one already running is fine.
func (c *Client) Start(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/start", nil)
	return err
}

// Stop stops a container, giving it 10 seconds to exit cleanly.
func (c *Client) Stop(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/stop?t=10", nil)
	return err
}
