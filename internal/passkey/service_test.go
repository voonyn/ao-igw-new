package passkey

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The challenge lives in Redis and in no table, so the cache is the whole
// ceremony. This file proves the two rules that come with that: a cache the
// gateway cannot write refuses the start, and a finish with no challenge behind
// it refuses the answer.
//
// It also proves the origin rule, which decides whether a key pair is created at
// all. A credential made under an origin the RP ID does not cover is a Factor no
// sign-in can answer, and no later check can undo it.

const (
	testTenantID = "11111111-1111-1111-1111-111111111111"
	testUserID   = "22222222-2222-2222-2222-222222222222"
	testHost     = "auth.example.com"
	testOrigin   = "https://auth.example.com"
)

// errCache is a cache that answers every call with the same failure. It stands
// in for Redis being down.
type errCache struct{ err error }

func (c errCache) Get(context.Context, string) (string, error) { return "", c.err }

func (c errCache) Set(context.Context, string, string, time.Duration) error { return c.err }

func (c errCache) SetNX(context.Context, string, string, time.Duration) (bool, error) {
	return false, c.err
}

func (c errCache) AllowInWindow(context.Context, string, int, time.Duration) (bool, error) {
	return false, c.err
}

func (c errCache) Del(context.Context, ...string) error { return c.err }

func (c errCache) Ping(context.Context) error { return c.err }

func (c errCache) Close() error { return nil }

// emptyCache is a cache that holds nothing. Every read is a miss, which is what
// an expired challenge and an answered one both look like.
type emptyCache struct{ errCache }

func (emptyCache) Get(context.Context, string) (string, error) { return "", cache.ErrCacheMiss }

func (emptyCache) Set(context.Context, string, string, time.Duration) error { return nil }

func (emptyCache) Del(context.Context, ...string) error { return nil }

// recordingCache is a cache that keeps what it was given, so a test can read
// what one ceremony stored.
type recordingCache struct {
	emptyCache
	stored map[string]string
}

func (c recordingCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	c.stored[key] = value
	return nil
}

// newTestService builds a service whose every dependency answers, except the
// cache the caller names.
func newTestService(t *testing.T, ceremony cache.Client) *Service {
	t.Helper()

	log, _ := logger.NewObserved()
	return NewService(Deps{
		Account: func(context.Context, string, string) (string, error) {
			return "person@example.com", nil
		},
		List: func(context.Context, string, string) ([]Credential, error) {
			return nil, nil
		},
		Origins: func(context.Context, string) ([]string, error) {
			return []string{testOrigin}, nil
		},
		Budget:   func(context.Context, string, string) error { return nil },
		Ceremony: ceremony,
		Log:      log,
	})
}

// TestRegisterStart_CacheFailureRefusesTheCeremony proves that a challenge
// nobody could store refuses the ceremony.
//
// A ceremony that proceeds without a stored challenge is not a ceremony: the
// finish would have nothing to compare the answer against.
func TestRegisterStart_CacheFailureRefusesTheCeremony(t *testing.T) {
	svc := newTestService(t, errCache{err: errors.New("redis is down")})

	who := Principal{UserID: testUserID}
	_, err := svc.registerStart(context.Background(), testTenantID, testHost, testOrigin, who)

	if !errors.Is(err, ErrCeremonyUnavailable) {
		t.Errorf("the start answered %v, want %v", err, ErrCeremonyUnavailable)
	}
}

// TestRegisterFinish_NoChallengeIsRefused proves that an answer with no
// challenge behind it is refused.
//
// An expired challenge, one that was already answered, and one a later start
// replaced all reach this path, and the person is told the same thing: start
// again.
func TestRegisterFinish_NoChallengeIsRefused(t *testing.T) {
	svc := newTestService(t, emptyCache{})

	who := Principal{UserID: testUserID}
	_, err := svc.registerFinish(
		context.Background(), testTenantID, testHost, testOrigin, "Laptop", who,
		[]byte(`{"id":"aaaa","rawId":"aaaa","type":"public-key"}`), nil)

	if !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("the finish answered %v, want %v", err, ErrChallengeExpired)
	}
}

// TestRegisterStart_BudgetIsSpentFirst proves that a start spends the shared
// guessing budget before it does anything else.
//
// A start is the request that costs the gateway work. Without the budget, a
// valid token asks for challenges without end.
func TestRegisterStart_BudgetIsSpentFirst(t *testing.T) {
	spent := errors.New("the budget is spent")

	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		Budget: func(context.Context, string, string) error { return spent },
		// Every other dependency fails the test if it is reached. The budget is
		// spent before the origin is checked and before a row is read.
		Origins: func(context.Context, string) ([]string, error) {
			t.Error("the origins were read before the budget was spent")
			return nil, nil
		},
		List: func(context.Context, string, string) ([]Credential, error) {
			t.Error("the passkeys were read before the budget was spent")
			return nil, nil
		},
		Log: log,
	})

	who := Principal{UserID: testUserID}
	_, err := svc.registerStart(context.Background(), testTenantID, testHost, testOrigin, who)

	if !errors.Is(err, spent) {
		t.Errorf("the start answered %v, want %v", err, spent)
	}
}

// TestRegisterStart_TheOverrideReplacesTheDerivedRPID proves the development
// path.
//
// A host such as localhost has no registrable domain, so nothing is derived and
// no ceremony could run. The override names the RP ID instead, and the front end
// origin is then covered by it.
func TestRegisterStart_TheOverrideReplacesTheDerivedRPID(t *testing.T) {
	const (
		devHost   = "localhost:8080"
		devOrigin = "http://localhost:3001"
	)

	log, _ := logger.NewObserved()
	stored := make(map[string]string)
	svc := NewService(Deps{
		Account: func(context.Context, string, string) (string, error) {
			return "person@example.com", nil
		},
		List:    func(context.Context, string, string) ([]Credential, error) { return nil, nil },
		Origins: func(context.Context, string) ([]string, error) { return []string{devOrigin}, nil },
		Budget:  func(context.Context, string, string) error { return nil },
		// The derived answer for this host is empty, so a start that succeeds
		// proves that the override is what supplied the RP ID.
		RPIDOverride: "localhost",
		Ceremony:     recordingCache{stored: stored},
		Log:          log,
	})

	who := Principal{UserID: testUserID}
	creation, err := svc.registerStart(context.Background(), testTenantID, devHost, devOrigin, who)
	if err != nil {
		t.Fatalf("the start answered %v, want the options", err)
	}

	if creation.Response.RelyingParty.ID != "localhost" {
		t.Errorf("the options name rp id %q, want %q",
			creation.Response.RelyingParty.ID, "localhost")
	}
	if len(stored) != 1 {
		t.Errorf("the start stored %d challenges, want 1", len(stored))
	}
}

// TestCovers proves which origins one RP ID may run a ceremony from.
//
// A device binds its key pair to the RP ID, so an origin outside it can neither
// create a Passkey this tenant can use nor answer a challenge with one.
func TestCovers(t *testing.T) {
	origins := []string{
		"https://auth.example.com",
		"https://portal.example.com",
		// The deployment console, on a domain of its own. The RP ID of this
		// tenant does not reach it, so no ceremony of this tenant runs there.
		"https://console.gateway.test",
	}

	kept := covers("example.com", origins)
	want := []string{"https://auth.example.com", "https://portal.example.com"}
	if len(kept) != len(want) {
		t.Fatalf("the rp id kept %v, want %v", kept, want)
	}
	for i := range want {
		if kept[i] != want[i] {
			t.Errorf("kept[%d] is %q, want %q", i, kept[i], want[i])
		}
	}

	// The suffix must break on a label. Otherwise a device would bind to a
	// domain somebody else owns.
	if kept := covers("ample.com", origins); len(kept) != 0 {
		t.Errorf("the rp id ample.com kept %v, want nothing", kept)
	}

	// A development RP ID names the host itself, port and all origins aside.
	if kept := covers("localhost", []string{"http://localhost:3001"}); len(kept) != 1 {
		t.Errorf("the rp id localhost kept %v, want the front end origin", kept)
	}
}

// TestServed proves the comparison of one origin against the list. It ignores
// case and a trailing slash, which is what a canonical origin comparison is.
func TestServed(t *testing.T) {
	allowed := []string{"https://auth.example.com"}

	cases := map[string]bool{
		"https://auth.example.com":  true,
		"https://auth.example.com/": true,
		"https://AUTH.example.com":  true,
		"https://evil.example.com":  false,
		"":                          false,
	}

	for origin, want := range cases {
		if got := served(origin, allowed); got != want {
			t.Errorf("served(%q) is %v, want %v", origin, got, want)
		}
	}
}

// TestRegisterStart_AnUncoveredOriginIsRefused proves that a browser calling
// from an origin the RP ID does not cover creates no key pair.
//
// A Passkey made there is a Factor no sign-in of this tenant can answer, and no
// later check can undo it.
func TestRegisterStart_AnUncoveredOriginIsRefused(t *testing.T) {
	svc := newTestService(t, emptyCache{})

	who := Principal{UserID: testUserID}
	_, err := svc.registerStart(
		context.Background(), testTenantID, testHost, "https://not-this-tenant.test", who)

	if !errors.Is(err, ErrOriginRefused) {
		t.Errorf("the start answered %v, want %v", err, ErrOriginRefused)
	}
}

// TestRegisterStart_NoOriginHeaderStillRuns proves that a call with no origin
// runs the ceremony.
//
// The Portal BFF forwards the call server to server, so no browser origin
// reaches this route. The finish still compares the origin the device signed
// against the list the RP ID covers, which is where the rule is enforced.
func TestRegisterStart_NoOriginHeaderStillRuns(t *testing.T) {
	svc := newTestService(t, emptyCache{})

	who := Principal{UserID: testUserID}
	creation, err := svc.registerStart(context.Background(), testTenantID, testHost, "", who)
	if err != nil {
		t.Fatalf("the start answered %v, want the options", err)
	}
	if creation.Response.RelyingParty.ID != "example.com" {
		t.Errorf("the options name rp id %q, want %q",
			creation.Response.RelyingParty.ID, "example.com")
	}
}
