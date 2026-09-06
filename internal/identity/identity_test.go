package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	idAddr  = "dero1q" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef"
	idAddr2 = "dero1q" + "0011223344556677889900aabbccddeeff0011223344556677889900aabbcc"
)

func TestAddGetList(t *testing.T) {
	s := NewStore()
	if err := s.Add(Contact{Name: "Alice", DeroName: "alice.dero", Address: idAddr, Trust: TrustKnown}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("ALICE")
	if err != nil || got.Address != idAddr {
		t.Fatalf("get = %+v,%v", got, err)
	}
	if n := len(s.List()); n != 1 {
		t.Fatalf("list len = %d; want 1", n)
	}
	if err := s.Add(Contact{Name: "alice", Address: idAddr2}); !errors.Is(err, ErrExists) {
		t.Fatalf("dup err = %v; want ErrExists", err)
	}
	if err := s.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed get err = %v; want ErrNotFound", err)
	}
}

func TestAddRejectsInvalid(t *testing.T) {
	s := NewStore()
	for _, c := range []Contact{
		{Name: "", Address: idAddr},
		{Name: "Bob", Address: "bogus"},
		{Name: "Bob", Address: idAddr, DeroName: "not a name"},
	} {
		if err := s.Add(c); !errors.Is(err, ErrInvalidContact) {
			t.Fatalf("add %+v err = %v; want ErrInvalidContact", c, err)
		}
	}
}

func TestBlockedRejected(t *testing.T) {
	s := NewStore()
	s.Block(idAddr)
	if !s.IsBlocked(idAddr) {
		t.Fatal("IsBlocked must hit blocked address")
	}
	if err := s.Add(Contact{Name: "Mallory", Address: idAddr}); !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked address add err = %v; want ErrBlocked", err)
	}
	s2 := NewStore()
	s2.Block("evil.dero")
	if err := s2.Add(Contact{Name: "Evil", DeroName: "evil.dero", Address: idAddr2}); !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked name add err = %v; want ErrBlocked", err)
	}
	s2.Unblock("evil.dero")
	if s2.IsBlocked("evil.dero") {
		t.Fatal("Unblock must clear")
	}
	if err := s2.Add(Contact{Name: "Evil", DeroName: "evil.dero", Address: idAddr2}); err != nil {
		t.Fatalf("post-unblock add err = %v", err)
	}
}

func TestTrustLevels(t *testing.T) {
	if TrustNone.String() != "none" || TrustKnown.String() != "known" || TrustVerified.String() != "verified" {
		t.Fatal("TrustLevel strings wrong")
	}
	s := NewStore()
	if err := s.Add(Contact{Name: "Bob", Address: idAddr2}); err != nil {
		t.Fatal(err)
	}
	if s.LocallyVerified(idAddr2) {
		t.Fatal("unverified contact must not count as verified")
	}
	if err := s.SetTrust("bob", TrustVerified); err != nil {
		t.Fatal(err)
	}
	if !s.LocallyVerified(idAddr2) {
		t.Fatal("TrustVerified contact must count as locally verified")
	}
	if err := s.SetTrust("ghost", TrustKnown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown trust err = %v; want ErrNotFound", err)
	}
}

func TestResolveLocalVerifiedShortCircuits(t *testing.T) {
	s := NewStore()
	if err := s.Add(Contact{Name: "Alice", DeroName: "alice.dero", Address: idAddr, Trust: TrustVerified}); err != nil {
		t.Fatal(err)
	}
	called := false
	lookup := func(ctx context.Context, in string) (string, bool, error) {
		called = true
		return "", false, errors.New("must not dial daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := s.Resolve(ctx, lookup, "alice.dero")
	if err != nil || addr != idAddr || !verified {
		t.Fatalf("resolve = %q,%v,%v", addr, verified, err)
	}
	if called {
		t.Fatal("local verified contact must not trigger daemon lookup")
	}
}

func TestResolveUnverifiedStaysUnverified(t *testing.T) {
	s := NewStore()
	if err := s.Add(Contact{Name: "Bob", Address: idAddr2, Trust: TrustKnown}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := s.Resolve(ctx, nil, idAddr2)
	if err != nil || addr != idAddr2 || verified {
		t.Fatalf("known-but-unverified resolve = %q,%v,%v; want addr,false", addr, verified, err)
	}
}

func TestResolveDelegatesToDaemon(t *testing.T) {
	s := NewStore()
	lookup := func(ctx context.Context, in string) (string, bool, error) {
		if in == "captain.dero" {
			return idAddr, true, nil
		}
		return "", false, errors.New("nope")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, verified, err := s.Resolve(ctx, lookup, "captain.dero")
	if err != nil || addr != idAddr || !verified {
		t.Fatalf("daemon resolve = %q,%v,%v", addr, verified, err)
	}
}

func TestResolveBlockedRejectedBeforeLookup(t *testing.T) {
	s := NewStore()
	s.Block("mallory.dero")
	called := false
	lookup := func(ctx context.Context, in string) (string, bool, error) {
		called = true
		return idAddr, true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := s.Resolve(ctx, lookup, "mallory.dero"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked resolve err = %v; want ErrBlocked", err)
	}
	if called {
		t.Fatal("blocked identity must be rejected before any lookup")
	}
}

func TestHooks(t *testing.T) {
	s := NewStore()
	var got []string
	s.RegisterHook(func(e Event) { got = append(got, e.Type) })
	_ = s.Add(Contact{Name: "A", Address: idAddr})
	_ = s.SetTrust("A", TrustKnown)
	_ = s.Remove("A")
	s.Block("x.dero")
	joined := strings.Join(got, ",")
	for _, want := range []string{EventAdded, EventTrusted, EventRemoved, EventBlocked} {
		if !strings.Contains(joined, want) {
			t.Fatalf("hooks = %q; missing %q", joined, want)
		}
	}
}
