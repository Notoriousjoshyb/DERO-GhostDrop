package app

import (
	"fmt"
	"net/url"
	"strings"
)

// FormatDropURI builds ghostdrop://drop/<id>?relay=<r>&token=<t>.
func FormatDropURI(id, relay, token string) string {
	v := url.Values{}
	if relay != "" {
		v.Set("relay", relay)
	}
	if token != "" {
		v.Set("token", token)
	}
	u := "ghostdrop://drop/" + id
	if len(v) > 0 {
		u += "?" + v.Encode()
	}
	return u
}

// DropRef is a parsed ghostdrop:// URI.
type DropRef struct {
	ID    string
	Relay string
	Token string
}

// ParseDropURI parses ghostdrop://drop/<id>[?relay=&token=].
// It also accepts a bare drop ID ("GD-...") for convenience.
func ParseDropURI(s string) (DropRef, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "GD-") && !strings.Contains(s, "://") {
		if !validDropID(s) {
			return DropRef{}, fmt.Errorf("bad drop id %q", s)
		}
		return DropRef{ID: strings.ToUpper(s)}, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return DropRef{}, fmt.Errorf("bad drop URL: %w", err)
	}
	if u.Scheme != "ghostdrop" {
		return DropRef{}, fmt.Errorf("bad scheme %q, want ghostdrop://", u.Scheme)
	}
	rest := strings.TrimPrefix(u.Opaque, "drop/")
	if u.Opaque == "" {
		rest = strings.TrimPrefix(u.Path, "/")
		rest = strings.TrimPrefix(rest, "drop/")
	}
	id := strings.ToUpper(strings.Trim(rest, "/"))
	if !validDropID(id) {
		return DropRef{}, fmt.Errorf("bad drop id %q", rest)
	}
	q := u.Query()
	return DropRef{ID: id, Relay: q.Get("relay"), Token: q.Get("token")}, nil
}

func validDropID(id string) bool {
	if len(id) != 15 || !strings.HasPrefix(id, "GD-") {
		return false
	}
	for _, c := range id[3:] {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
