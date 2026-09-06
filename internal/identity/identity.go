// Package identity manages local Ghostdrop contacts and the block list.
//
// Trust model: TrustNone < TrustKnown < TrustVerified. verified=true is
// handed out ONLY for daemon-confirmed mappings (see dero) or for contacts
// the user explicitly marked TrustVerified (local trust override). Nothing
// here ever fabricates verification.
//
// Block list: any send/resolve path MUST consult IsBlocked first; blocked
// identities are rejected with ErrBlocked before any network call.
package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"ghostdrop/internal/dero"
)

var (
	// ErrBlocked rejects any operation on a blocked identity.
	ErrBlocked = errors.New("identity: blocked")
	// ErrInvalidContact marks contacts that fail Validate.
	ErrInvalidContact = errors.New("identity: invalid contact")
	// ErrExists marks duplicate contact names.
	ErrExists = errors.New("identity: contact already exists")
	// ErrNotFound marks unknown contact names.
	ErrNotFound = errors.New("identity: contact not found")
)

// TrustLevel is the local trust tier for a contact.
type TrustLevel int

const (
	// TrustNone is the default: known address-book entry, unverified.
	TrustNone TrustLevel = iota
	// TrustKnown was seen before / user-recognized, still unverified.
	TrustKnown
	// TrustVerified was explicitly verified by the user (local trust
	// override) or confirmed via daemon. Only this tier resolves verified.
	TrustVerified
)

// String renders the tier for UI/logs (never logs addresses/keys).
func (t TrustLevel) String() string {
	switch t {
	case TrustVerified:
		return "verified"
	case TrustKnown:
		return "known"
	default:
		return "none"
	}
}

// Contact is one address-book entry.
type Contact struct {
	Name     string     `json:"name"`
	DeroName string     `json:"dero_name,omitempty"`
	Address  string     `json:"address"`
	Trust    TrustLevel `json:"trust"`
	Notes    string     `json:"notes,omitempty"`
}

// Validate checks name presence, address shape, and optional DERO name shape.
func (c Contact) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidContact)
	}
	if !dero.ValidateAddress(c.Address) {
		return fmt.Errorf("%w: bad address for %q", ErrInvalidContact, c.Name)
	}
	if c.DeroName != "" && !dero.ValidateName(c.DeroName) {
		return fmt.Errorf("%w: bad dero name for %q", ErrInvalidContact, c.Name)
	}
	if c.Trust < TrustNone || c.Trust > TrustVerified {
		return fmt.Errorf("%w: bad trust level for %q", ErrInvalidContact, c.Name)
	}
	return nil
}

// Event types emitted to registered hooks.
const (
	EventAdded     = "added"
	EventRemoved   = "removed"
	EventTrusted   = "trusted"
	EventBlocked   = "blocked"
	EventUnblocked = "unblocked"
)

// Event describes one store mutation. Hooks are local persistence/UI sync
// points ("local store hooks").
type Event struct {
	Type    string
	Contact Contact
}

// Hook receives store events. It must be fast and non-blocking.
type Hook func(Event)

// LookupFunc resolves a name/address remotely (normally
// (*dero.DaemonClient).ResolveNameOrAddress). Injected so Resolve stays
// testable without HTTP.
type LookupFunc func(ctx context.Context, nameOrAddr string) (address string, verified bool, err error)

// Store is a concurrency-safe in-memory contact + block list store.
type Store struct {
	mu          sync.RWMutex
	contacts    map[string]Contact // key: lowercased display name
	blockedAddr map[string]bool    // key: lowercased address
	blockedName map[string]bool    // key: lowercased name/handle
	hooks       []Hook
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{
		contacts:    make(map[string]Contact),
		blockedAddr: make(map[string]bool),
		blockedName: make(map[string]bool),
	}
}

// RegisterHook appends a local store hook fired on every mutation.
func (s *Store) RegisterHook(h Hook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = append(s.hooks, h)
}

func (s *Store) emit(e Event) {
	s.mu.RLock()
	hooks := append([]Hook(nil), s.hooks...)
	s.mu.RUnlock()
	for _, h := range hooks {
		h(e)
	}
}

func normKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Add validates and inserts a contact. Blocked addresses/names/handles are
// rejected with ErrBlocked; duplicate names with ErrExists.
func (s *Store) Add(c Contact) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if s.IsBlocked(c.Address) || (c.DeroName != "" && s.IsBlocked(c.DeroName)) || s.IsBlocked(c.Name) {
		return fmt.Errorf("%w: %q", ErrBlocked, c.Name)
	}
	key := normKey(c.Name)
	s.mu.Lock()
	if _, dup := s.contacts[key]; dup {
		s.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrExists, c.Name)
	}
	s.contacts[key] = c
	s.mu.Unlock()
	s.emit(Event{Type: EventAdded, Contact: c})
	return nil
}

// Get returns the contact by display name (case-insensitive).
func (s *Store) Get(name string) (Contact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.contacts[normKey(name)]
	if !ok {
		return Contact{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return c, nil
}

// Remove deletes a contact by display name.
func (s *Store) Remove(name string) error {
	s.mu.Lock()
	c, ok := s.contacts[normKey(name)]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	delete(s.contacts, normKey(name))
	s.mu.Unlock()
	s.emit(Event{Type: EventRemoved, Contact: c})
	return nil
}

// List returns all contacts sorted by name.
func (s *Store) List() []Contact {
	s.mu.RLock()
	out := make([]Contact, 0, len(s.contacts))
	for _, c := range s.contacts {
		out = append(out, c)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SetTrust changes a contact's tier (e.g. explicit user verification).
func (s *Store) SetTrust(name string, level TrustLevel) error {
	if level < TrustNone || level > TrustVerified {
		return fmt.Errorf("%w: bad trust level", ErrInvalidContact)
	}
	s.mu.Lock()
	key := normKey(name)
	c, ok := s.contacts[key]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	c.Trust = level
	s.contacts[key] = c
	s.mu.Unlock()
	s.emit(Event{Type: EventTrusted, Contact: c})
	return nil
}

// Block adds an address, DERO name, or display name to the block list.
func (s *Store) Block(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	s.mu.Lock()
	if dero.ValidateAddress(id) {
		s.blockedAddr[normKey(id)] = true
	} else {
		s.blockedName[normKey(id)] = true
	}
	s.mu.Unlock()
	s.emit(Event{Type: EventBlocked, Contact: Contact{Name: id}})
}

// Unblock removes an identifier from the block list.
func (s *Store) Unblock(id string) {
	s.mu.Lock()
	delete(s.blockedAddr, normKey(id))
	delete(s.blockedName, normKey(id))
	s.mu.Unlock()
	s.emit(Event{Type: EventUnblocked, Contact: Contact{Name: id}})
}

// IsBlocked reports whether an address, DERO name, or display name is blocked.
func (s *Store) IsBlocked(id string) bool {
	k := normKey(id)
	if k == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockedAddr[k] || s.blockedName[k]
}

// LocallyVerified reports whether address belongs to a TrustVerified contact
// (the local trust override half of the verification policy).
func (s *Store) LocallyVerified(address string) bool {
	want := normKey(address)
	if want == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.contacts {
		if normKey(c.Address) == want && c.Trust == TrustVerified {
			return true
		}
	}
	return false
}

// Resolve maps a display name, DERO name, or raw address to a payout address.
// Blocked identities are rejected before any lookup. Local verified contacts
// short-circuit with verified=true (local trust override) without network.
// Otherwise it delegates to lookup (daemon-confirmed when verified=true).
func (s *Store) Resolve(ctx context.Context, lookup LookupFunc, nameOrAddr string) (address string, verified bool, err error) {
	in := strings.TrimSpace(nameOrAddr)
	if in == "" {
		return "", false, fmt.Errorf("%w: empty identity", ErrInvalidContact)
	}
	if s.IsBlocked(in) {
		return "", false, fmt.Errorf("%w: %q", ErrBlocked, in)
	}
	if dero.ValidateAddress(in) {
		return in, s.LocallyVerified(in), nil
	}
	norm := normKey(in)
	s.mu.RLock()
	var hit *Contact
	for _, c := range s.contacts {
		if normKey(c.DeroName) == norm && norm != "" || normKey(c.Name) == norm {
			cp := c
			hit = &cp
			break
		}
	}
	s.mu.RUnlock()
	if hit != nil {
		if s.IsBlocked(hit.Address) {
			return "", false, fmt.Errorf("%w: %q", ErrBlocked, in)
		}
		return hit.Address, hit.Trust == TrustVerified, nil
	}
	if lookup == nil {
		return "", false, fmt.Errorf("%w: %q", dero.ErrNameNotFound, in)
	}
	addr, ver, err := lookup(ctx, in)
	if err != nil {
		return "", false, err
	}
	if s.IsBlocked(addr) {
		return "", false, fmt.Errorf("%w: %q", ErrBlocked, in)
	}
	return addr, ver, nil
}
