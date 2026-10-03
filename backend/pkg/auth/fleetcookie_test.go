/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/auth"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/cache"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/kubeconfig"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fleetTokenCookieName / fleetRefCookieName mirror the names fleetcookie.go
// writes. They are spelled out literally rather than imported so that a rename
// of the cookie scheme has to be made deliberately in both places: the names
// are persisted in users' browsers, so changing one silently would log every
// existing session out.
func fleetTokenCookieName(key string, chunk int) string {
	return fmt.Sprintf("headlamp-auth-fleet.%s.%d", key, chunk)
}

func fleetRefCookieName(cluster string) string {
	return "headlamp-auth-fleet.ref." + cluster
}

// setCookies attaches cookies to a request as a browser would, with no path
// information: the server sees only names and values, which is why the trust
// boundary cannot be re-derived at read time from the path.
func setCookies(r *http.Request, nameValues map[string]string) {
	for name, value := range nameValues {
		// G124: a cookie on an outgoing request carries only name=value. Secure,
		// HttpOnly and SameSite are response-side attributes that AddCookie does
		// not serialize, so setting them here would assert nothing. The code
		// under test sets them, and TestSetFleetTokenCookie_* asserts it does.
		r.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec
	}
}

// liveCookies returns the cookies set on w that are actually being stored,
// skipping the expiry (MaxAge<=0) headers used to clear previous state.
func liveCookies(t *testing.T, w *httptest.ResponseRecorder) map[string]*http.Cookie {
	t.Helper()

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	out := map[string]*http.Cookie{}

	for _, ck := range resp.Cookies() {
		if ck.MaxAge > 0 && ck.Value != "" {
			out[ck.Name] = ck
		}
	}

	return out
}

// expiredCookies returns the names of cookies w is clearing.
func expiredCookies(t *testing.T, w *httptest.ResponseRecorder) map[string]bool {
	t.Helper()

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	out := map[string]bool{}

	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			out[ck.Name] = true
		}
	}

	return out
}

func TestFleetCookieKey(t *testing.T) {
	keyA := auth.FleetCookieKey(testIssuerA, testClientFoo)

	assert.Len(t, keyA, 16, "key length is baked into cookie names and must stay stable")
	assert.Equal(t, keyA, auth.FleetCookieKey(testIssuerA, testClientFoo),
		"key must be deterministic: it has to resolve to the same cookie on every request")

	assert.NotEqual(t, keyA, auth.FleetCookieKey(testIssuerB, testClientFoo),
		"a different issuer is a different identity and must not share a cookie")
	assert.NotEqual(t, keyA, auth.FleetCookieKey(testIssuerA, testClientBar),
		"a different client ID is a different identity and must not share a cookie")

	// The digest is taken over issuer and client-id with a separator so the two
	// fields cannot be slid into one another to forge a colliding key.
	assert.NotEqual(t,
		auth.FleetCookieKey("https://idp.example.com/a", "b"),
		auth.FleetCookieKey("https://idp.example.com/", "ab"),
		"field boundaries must be part of the digest")

	assert.Empty(t, auth.FleetCookieKey("", testClientFoo),
		"an incomplete identity has no fleet cookie")
	assert.Empty(t, auth.FleetCookieKey(testIssuerA, ""),
		"an incomplete identity has no fleet cookie")
}

// A cluster name can legally contain hyphens, so a hyphen-separated fleet
// prefix would be forgeable by naming a cluster after it. The scheme uses dots,
// which SanitizeClusterName strips, making the collision unrepresentable.
func TestFleetCookieNameCannotBeForgedByAClusterName(t *testing.T) {
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	// A cluster named to impersonate the shared token cookie.
	hostile := "fleet-" + key
	perCluster := fmt.Sprintf("headlamp-auth-%s.0", auth.SanitizeClusterName(hostile))

	assert.NotEqual(t, fleetTokenCookieName(key, 0), perCluster,
		"a cluster name must not be able to produce the shared token cookie's name")

	// And one named to impersonate another cluster's ref cookie.
	hostileRef := "fleet-ref-victim"
	perClusterRef := fmt.Sprintf("headlamp-auth-%s.0", auth.SanitizeClusterName(hostileRef))

	assert.NotEqual(t, fleetRefCookieName("victim"), perClusterRef,
		"a cluster name must not be able to produce another cluster's ref cookie name")
}

func TestGetTokenFromCookie_ReadsFleetTokenViaRefCookie(t *testing.T) {
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/dev/api", nil)

	setCookies(r, map[string]string{
		fleetRefCookieName("dev"):    key,
		fleetTokenCookieName(key, 0): testBroadcastToken,
	})

	token, err := auth.GetTokenFromCookie(r, "dev")
	require.NoError(t, err)
	assert.Equal(t, testBroadcastToken, token,
		"a cluster holding a ref cookie must resolve the shared token")
}

// The whole point of the shared cookie is that one login covers many clusters,
// so a token longer than one chunk must reassemble in order.
func TestGetTokenFromCookie_ReassemblesChunkedFleetToken(t *testing.T) {
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/dev/api", nil)

	setCookies(r, map[string]string{
		fleetRefCookieName("dev"):    key,
		fleetTokenCookieName(key, 0): "head.",
		fleetTokenCookieName(key, 1): "middle.",
		fleetTokenCookieName(key, 2): "tail",
	})

	token, err := auth.GetTokenFromCookie(r, "dev")
	require.NoError(t, err)
	assert.Equal(t, "head.middle.tail", token)
}

// This is the trust boundary. The shared cookie is sent for every cluster path,
// so a cluster trusting a different identity provider receives it in its
// request. Without a ref cookie of its own it must not be able to use it.
func TestGetTokenFromCookie_IgnoresFleetTokenWithoutARefCookie(t *testing.T) {
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/other/api", nil)

	// "other" belongs to a different IdP, so it was never enrolled; the browser
	// still sends it the shared cookie because of the shared /clusters path.
	setCookies(r, map[string]string{
		fleetTokenCookieName(key, 0): testBroadcastToken,
	})

	token, err := auth.GetTokenFromCookie(r, "other")
	require.NoError(t, err)
	assert.Empty(t, token,
		"a cluster that was never enrolled must not read another identity's token")
}

func TestGetTokenFromCookie_IgnoresRefCookieNamingAnAbsentFleetCookie(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/dev/api", nil)

	setCookies(r, map[string]string{
		fleetRefCookieName("dev"): auth.FleetCookieKey(testIssuerA, testClientFoo),
	})

	token, err := auth.GetTokenFromCookie(r, "dev")
	require.NoError(t, err)
	assert.Empty(t, token, "a dangling ref cookie must resolve to no token, not an error")
}

// A ref cookie value becomes part of a cookie name, so only the exact shape
// FleetCookieKey produces is accepted.
//
// Each case plants the cookie the hostile value would resolve to, so the
// assertion fails if the shape check is removed rather than passing merely
// because the name happened to match nothing.
//
// This asserts name-injection hygiene, not a trust boundary: the lookup
// namespace "headlamp-auth-fleet.<value>.<n>" contains nothing but fleet
// cookies, so no value could redirect the read to a different cookie family in
// the first place. The boundary itself is the ref cookie's existence, covered
// by TestGetTokenFromCookie_IgnoresFleetTokenWithoutARefCookie.
func TestGetTokenFromCookie_RejectsRefCookieValuesThatAreNotKeys(t *testing.T) {
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	for _, hostile := range []string{
		key + ".0",                   // an extra separator smuggled in
		"fleet." + key,               // the prefix repeated
		strings.ToUpper(key),         // right characters, wrong case
		key[:8],                      // right alphabet, wrong length
		strings.Repeat("z", 16) + "", // right length, not hex
	} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/dev/api", nil)

		setCookies(r, map[string]string{
			fleetRefCookieName("dev"): hostile,
			// The cookie an unvalidated lookup would find.
			fmt.Sprintf("headlamp-auth-fleet.%s.0", hostile): testBroadcastToken,
		})

		token, err := auth.GetTokenFromCookie(r, "dev")
		require.NoError(t, err)
		assert.Emptyf(t, token,
			"ref cookie value %q is not a key and must not be used to build a cookie name", hostile)
	}
}

// An empty ref cookie resolves to no token and no error, which is the state a
// cluster is in before it has been enrolled.
func TestGetTokenFromCookie_IgnoresEmptyRefCookie(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/dev/api", nil)

	setCookies(r, map[string]string{fleetRefCookieName("dev"): ""})

	token, err := auth.GetTokenFromCookie(r, "dev")
	require.NoError(t, err)
	assert.Empty(t, token)
}

// Rollout safety: a session that predates fleet mode still holds a per-cluster
// cookie, and that cookie must keep working.
func TestGetTokenFromCookie_PrefersPerClusterCookieOverFleet(t *testing.T) {
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/dev/api", nil)

	setCookies(r, map[string]string{
		"headlamp-auth-dev.0":        "per-cluster-token",
		fleetRefCookieName("dev"):    key,
		fleetTokenCookieName(key, 0): testBroadcastToken,
	})

	token, err := auth.GetTokenFromCookie(r, "dev")
	require.NoError(t, err)
	assert.Equal(t, "per-cluster-token", token)
}

func TestSetFleetTokenCookie_ScopedToAllClustersButNotTheWholeSite(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc-callback", nil)
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	auth.SetFleetTokenCookie(w, r, key, testBroadcastToken, "", 3600)

	got := liveCookies(t, w)
	ck, ok := got[fleetTokenCookieName(key, 0)]
	require.True(t, ok, "shared token cookie must be set")

	// "/clusters" is sent for every /clusters/<name>/... request, but is not
	// attached to /config or the static assets the way "/" would be.
	assert.Equal(t, "/clusters", ck.Path)
	assert.True(t, ck.HttpOnly, "the token must not be readable from JavaScript")
	assert.Equal(t, http.SameSiteStrictMode, ck.SameSite)
}

func TestSetFleetTokenCookie_HonorsBaseURL(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/headlamp/oidc-callback", nil)
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	auth.SetFleetTokenCookie(w, r, key, testBroadcastToken, "/headlamp", 3600)

	got := liveCookies(t, w)
	ck, ok := got[fleetTokenCookieName(key, 0)]
	require.True(t, ok)
	assert.Equal(t, "/headlamp/clusters", ck.Path,
		"the shared cookie must sit under the base URL or it will not be sent at all")
}

func TestSetFleetRefCookie_ScopedToOneCluster(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc-callback", nil)
	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	auth.SetFleetRefCookie(w, r, "dev", key, "", 3600)

	got := liveCookies(t, w)
	ck, ok := got[fleetRefCookieName("dev")]
	require.True(t, ok)

	// Scoping the ref to one cluster is what stops the browser offering it to
	// any other cluster, which is how the write-time check keeps holding at
	// read time.
	assert.Equal(t, "/clusters/dev", ck.Path)
	assert.Equal(t, key, ck.Value)
	assert.True(t, ck.HttpOnly)
}

// Fleet mode's headline property: the token is stored once no matter how many
// clusters share the identity, instead of once per cluster.
func TestBroadcastOIDCToken_FleetModeStoresTheTokenOnce(t *testing.T) {
	store := kubeconfig.NewContextStore()
	for _, ctx := range []*kubeconfig.Context{
		newOIDCContext("src", testIssuerA, testClientFoo),
		newOIDCContext("sib-1", testIssuerA, testClientFoo),
		newOIDCContext("sib-2", testIssuerA, testClientFoo),
		newOIDCContext("other-idp", testIssuerB, testClientFoo),
	} {
		require.NoError(t, store.AddContext(ctx))
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc-callback", nil)

	auth.BroadcastOIDCToken(auth.BroadcastOIDCTokenParams{
		Writer:          w,
		Request:         r,
		KubeConfigStore: store,
		SourceCluster:   "src",
		Token:           testBroadcastToken,
		SessionTTL:      3600,
		UseFleetCookie:  true,
	})

	key := auth.FleetCookieKey(testIssuerA, testClientFoo)
	got := liveCookies(t, w)

	// Exactly one copy of the token, not one per cluster.
	tokenCookies := 0

	for name := range got {
		if strings.HasPrefix(name, "headlamp-auth-fleet.") && !strings.HasPrefix(name, "headlamp-auth-fleet.ref.") {
			tokenCookies++
		}
	}

	assert.Equal(t, 1, tokenCookies, "the token must be stored once for the whole fleet")
	assert.Equal(t, testBroadcastToken, got[fleetTokenCookieName(key, 0)].Value)

	// The source and every matching sibling are enrolled; the cluster on a
	// different IdP is not.
	for _, cluster := range []string{"src", "sib-1", "sib-2"} {
		ck, ok := got[fleetRefCookieName(cluster)]
		assert.Truef(t, ok, "%s shares the identity and must be enrolled", cluster)

		if ok {
			assert.Equal(t, key, ck.Value)
		}
	}

	_, enrolled := got[fleetRefCookieName("other-idp")]
	assert.False(t, enrolled, "a cluster on a different IdP must not be enrolled")

	// No per-cluster copies of the token were written.
	for _, cluster := range []string{"src", "sib-1", "sib-2", "other-idp"} {
		_, ok := got[fmt.Sprintf("headlamp-auth-%s.0", cluster)]
		assert.Falsef(t, ok, "%s must not get its own copy of the token in fleet mode", cluster)
	}
}

// GetTokenFromCookie reads the per-cluster cookie first, so an enrolled cluster
// that still holds one would be pinned to a token the shared cookie no longer
// matches. Enrollment has to expire it, and must do so without reading the
// request: at /oidc-callback the browser sends no /clusters/<name> cookies, so
// a read-then-clear loop sees nothing to clear.
func TestBroadcastOIDCToken_FleetModeExpiresShadowingPerClusterCookies(t *testing.T) {
	store := kubeconfig.NewContextStore()
	for _, ctx := range []*kubeconfig.Context{
		newOIDCContext("src", testIssuerA, testClientFoo),
		newOIDCContext("sib-1", testIssuerA, testClientFoo),
	} {
		require.NoError(t, store.AddContext(ctx))
	}

	w := httptest.NewRecorder()
	// No cookies attached, exactly as on the real /oidc-callback request.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc-callback", nil)

	auth.BroadcastOIDCToken(auth.BroadcastOIDCTokenParams{
		Writer:          w,
		Request:         r,
		KubeConfigStore: store,
		SourceCluster:   "src",
		Token:           testBroadcastToken,
		SessionTTL:      3600,
		UseFleetCookie:  true,
	})

	expired := expiredCookies(t, w)
	for _, cluster := range []string{"src", "sib-1"} {
		assert.Truef(t, expired[fmt.Sprintf("headlamp-auth-%s.0", cluster)],
			"%s's per-cluster cookie must be expired even though the request did not carry it", cluster)
	}
}

// Fleet mode is opt-in on top of broadcast, so with it off the behavior from
// the original broadcast feature must be exactly preserved.
func TestBroadcastOIDCToken_WithoutFleetModeWritesPerClusterCookies(t *testing.T) {
	store := kubeconfig.NewContextStore()
	for _, ctx := range []*kubeconfig.Context{
		newOIDCContext("src", testIssuerA, testClientFoo),
		newOIDCContext("sib-1", testIssuerA, testClientFoo),
	} {
		require.NoError(t, store.AddContext(ctx))
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc-callback", nil)

	auth.BroadcastOIDCToken(auth.BroadcastOIDCTokenParams{
		Writer:          w,
		Request:         r,
		KubeConfigStore: store,
		SourceCluster:   "src",
		Token:           testBroadcastToken,
		SessionTTL:      3600,
	})

	got := liveCookies(t, w)

	ck, ok := got["headlamp-auth-sib-1.0"]
	require.True(t, ok, "sibling must still get its own cookie when fleet mode is off")
	assert.Equal(t, testBroadcastToken, ck.Value)

	for name := range got {
		assert.NotContains(t, name, "fleet", "no fleet cookie may be written when fleet mode is off")
	}
}

// fleetMiddleware builds the OIDC refresh middleware over a store, capturing
// the Authorization header the request carries by the time it reaches the
// wrapped handler.
func fleetMiddleware(
	t *testing.T, store kubeconfig.ContextStore, sharedCookie bool, seen *string,
) http.Handler {
	t.Helper()

	config := auth.OIDCTokenRefreshConfig{
		KubeConfigStore:       store,
		Cache:                 cache.New[interface{}](),
		TelemetryHandler:      &telemetry.RequestHandler{},
		OidcUseTokenBroadcast: true,
		OidcSharedTokenCookie: sharedCookie,
		SessionTTL:            3600,
	}

	return auth.NewOIDCTokenRefreshMiddleware(config)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			*seen = r.Header.Get("Authorization")

			w.WriteHeader(http.StatusOK)
		}))
}

// A cluster added to the kubeconfig after the user logged in was never a
// broadcast target, so it holds no cookie of its own. Because the shared token
// cookie is sent for every cluster path, first contact can admit it to the
// session instead of sending the user back to a login screen for a fleet that
// is already authenticated.
func TestFleetEnrollment_AdmitsAClusterAddedAfterLogin(t *testing.T) {
	store := kubeconfig.NewContextStore()
	require.NoError(t, store.AddContext(newOIDCContext("added-later", testIssuerA, testClientFoo)))

	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	var seen string

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/added-later/api/v1/pods", nil)
	// Only the shared cookie: no ref cookie, because this cluster did not exist
	// when the broadcast ran.
	setCookies(r, map[string]string{fleetTokenCookieName(key, 0): testBroadcastToken})

	w := httptest.NewRecorder()
	fleetMiddleware(t, store, true, &seen).ServeHTTP(w, r)

	assert.Equal(t, "Bearer "+testBroadcastToken, seen,
		"the request itself must be authenticated, not just the next one")

	ck, ok := liveCookies(t, w)[fleetRefCookieName("added-later")]
	require.True(t, ok, "the cluster must be enrolled so storeless readers work afterwards")
	assert.Equal(t, key, ck.Value)
}

// Enrollment reads the cluster's own issuer and client-id from the store, which
// is the same check the login-time broadcast applies. A cluster trusting a
// different IdP therefore cannot be admitted, even though the browser sends it
// the shared cookie.
func TestFleetEnrollment_RefusesAClusterOnADifferentIdP(t *testing.T) {
	store := kubeconfig.NewContextStore()
	require.NoError(t, store.AddContext(newOIDCContext("other-idp", testIssuerB, testClientFoo)))

	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	var seen string

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/other-idp/api/v1/pods", nil)
	setCookies(r, map[string]string{fleetTokenCookieName(key, 0): testBroadcastToken})

	w := httptest.NewRecorder()
	fleetMiddleware(t, store, true, &seen).ServeHTTP(w, r)

	assert.Empty(t, seen, "a cluster on a different IdP must not be given the token")

	_, ok := liveCookies(t, w)[fleetRefCookieName("other-idp")]
	assert.False(t, ok, "a cluster on a different IdP must not be enrolled")
}

// A non-OIDC cluster has no identity to match, so it is never enrolled.
func TestFleetEnrollment_RefusesANonOIDCCluster(t *testing.T) {
	store := kubeconfig.NewContextStore()
	require.NoError(t, store.AddContext(newNonOIDCContext("static-token")))

	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	var seen string

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/static-token/api/v1/pods", nil)
	setCookies(r, map[string]string{fleetTokenCookieName(key, 0): testBroadcastToken})

	w := httptest.NewRecorder()
	fleetMiddleware(t, store, true, &seen).ServeHTTP(w, r)

	assert.Empty(t, seen)
	assert.Empty(t, liveCookies(t, w))
}

// Internal contexts are per-user stateless clusters whose store keys embed a
// NUL-separated user ID that SanitizeClusterName collapses, so two different
// users' contexts can sanitize to the same cookie name. They are excluded from
// enrollment for the same reason the broadcast excludes them.
func TestFleetEnrollment_RefusesInternalContexts(t *testing.T) {
	store := kubeconfig.NewContextStore()
	require.NoError(t, store.AddContext(newInternalOIDCContext("stateless", testIssuerA, testClientFoo)))

	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	var seen string

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/stateless/api/v1/pods", nil)
	setCookies(r, map[string]string{fleetTokenCookieName(key, 0): testBroadcastToken})

	w := httptest.NewRecorder()
	fleetMiddleware(t, store, true, &seen).ServeHTTP(w, r)

	assert.Empty(t, seen, "an internal context must never be enrolled from a shared cookie")
	assert.Empty(t, liveCookies(t, w))
}

// With the shared-cookie mode off, no enrollment happens at all, so the flag is
// a genuine off switch rather than only changing where the token is stored.
func TestFleetEnrollment_DoesNothingWhenSharedCookieModeIsOff(t *testing.T) {
	store := kubeconfig.NewContextStore()
	require.NoError(t, store.AddContext(newOIDCContext("added-later", testIssuerA, testClientFoo)))

	key := auth.FleetCookieKey(testIssuerA, testClientFoo)

	var seen string

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/added-later/api/v1/pods", nil)
	setCookies(r, map[string]string{fleetTokenCookieName(key, 0): testBroadcastToken})

	w := httptest.NewRecorder()
	fleetMiddleware(t, store, false, &seen).ServeHTTP(w, r)

	assert.Empty(t, seen)
	assert.Empty(t, liveCookies(t, w))
}
