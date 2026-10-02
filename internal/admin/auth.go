package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Every /api/ call needs the admin token: as a bearer token (Foyer,
// scripts) or as the session cookie a browser gets by entering it once.

const cookieName = "gatehouse_session"

// sessionValue derives the cookie from the token, so changing the token
// signs every browser out and the cookie never holds the token itself.
func sessionValue(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("gatehouse-session-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func bearer(r *http.Request) (string, bool) {
	b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(b), ok
}

func (s *Server) authenticated(r *http.Request) bool {
	if b, ok := bearer(r); ok {
		return equal(b, s.Token)
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return equal(c.Value, s.session)
	}
	return false
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			writeError(w, http.StatusUnauthorized, "sign in with the Gatehouse token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireDiscovery also accepts the read-only discovery token, so Foyer
// and Lookout don't need the admin token.
func (s *Server) requireDiscovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := bearer(r); ok && s.DiscoveryToken != "" && equal(b, s.DiscoveryToken) {
			next.ServeHTTP(w, r)
			return
		}
		s.requireAuth(next).ServeHTTP(w, r)
	})
}

// sameOrigin refuses state-changing requests that a browser sent from
// another origin. Requests without these headers (Foyer, curl) rely on the
// token they carry.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			site := r.Header.Get("Sec-Fetch-Site")
			if site != "" && site != "same-origin" && site != "none" {
				writeError(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host {
					writeError(w, http.StatusForbidden, "cross-origin request refused")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

type sessionInfo struct {
	Authenticated bool `json:"authenticated"`
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, sessionInfo{Authenticated: s.authenticated(r)})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, 4<<10, &body) {
		return
	}
	if !equal(strings.TrimSpace(body.Token), s.Token) {
		time.Sleep(500 * time.Millisecond) // slow down guessing
		writeError(w, http.StatusUnauthorized, "wrong token")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.session, Path: "/",
		MaxAge: 365 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	writeJSON(w, http.StatusOK, sessionInfo{Authenticated: true})
}

func (s *Server) logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	w.WriteHeader(http.StatusNoContent)
}
