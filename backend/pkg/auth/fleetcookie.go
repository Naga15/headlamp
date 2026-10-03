/*
Copyright 2025 The Kubernetes Authors.

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

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Fleet cookies let one OIDC login serve a whole fleet with a single stored
// token instead of one full copy per cluster.
//
// Two cookies are involved:
//
//   - The fleet token cookie, "headlamp-auth-fleet.<key>.<n>", holds the token
//     (chunked exactly like the per-cluster cookie). It is set at path
//     "/clusters", so the browser sends it on requests for every cluster.
//
//   - A fleet ref cookie, "headlamp-auth-fleet.ref.<cluster>", holds only
//     <key>. It is set at path "/clusters/<cluster>", so the browser sends it
//     for that one cluster.
//
// Both names carry two dots, and the per-cluster cookie
// ("headlamp-auth-<cluster>.<n>") carries exactly one, because
// SanitizeClusterName strips dots from cluster names. That is what keeps the
// three families from colliding: hyphen-separated prefixes would not, since a
// cluster named "fleet-<key>" sanitizes to a legal cluster name that would
// otherwise produce a fleet token cookie's exact name. A fleet ref cookie
// cannot be mistaken for a fleet token cookie either, as a key is always
// fleetKeyLength hex characters and so is never the literal "ref".
//
// <key> is derived from the OIDC issuer URL and client ID, so the token cookie
// is named after the identity that issued it rather than after any cluster.
// One login writes it once, one refresh updates it once, and every cluster
// holding a matching ref cookie reads it.
//
// The ref cookie is what keeps the trust boundary intact. A fleet token cookie
// is readable at every cluster path, so on its own it would hand the token to
// clusters trusting a different identity provider. A cluster only consults it
// if it carries a ref cookie naming that key, and ref cookies are written
// solely to clusters that passed the same issuer + client-id check
// BroadcastOIDCToken applies (see broadcastToTarget). Enforcing the boundary
// when the cookie is written, rather than when it is read, is what lets
// GetTokenFromCookie resolve a fleet token without consulting the kubeconfig
// store: a cluster cannot be sent a ref cookie it did not qualify for, and the
// browser will not send another cluster's ref cookie in its place.
//
// Residual limitation: that argument holds because only the server writes ref
// cookies, and they are HttpOnly. An actor who can plant cookies in the user's
// browser directly could point a cluster at a shared token belonging to an
// identity that cluster does not trust, causing Headlamp to forward that token
// to an apiserver which should not see it. The key is derived from the issuer
// URL and client ID, both public, so it is guessable; the shape check in
// GetTokenFromFleetCookie is name-injection hygiene and not a defense against
// this. Note that cookie-planting already lets an actor overwrite per-cluster
// auth cookies upstream today, so this is the same trust assumption Headlamp's
// existing cookie scheme makes, applied to one more cookie. Deployments that
// cannot rely on it should leave --oidc-shared-token-cookie off.
const (
	// fleetCookiePrefix names the shared token cookie.
	fleetCookiePrefix = "headlamp-auth-fleet."
	// fleetRefCookiePrefix names the per-cluster pointer at the shared cookie.
	fleetRefCookiePrefix = "headlamp-auth-fleet.ref."
	// fleetKeyLength is how many hex characters of the issuer+client-id digest
	// are kept in the cookie name. 16 hex characters (64 bits) keeps the name
	// short while leaving collisions between the handful of identity providers
	// one Headlamp instance serves beyond practical concern.
	fleetKeyLength = 16
)

// FleetCookieKey derives the shared-cookie key for an OIDC identity.
//
// The digest is over "<issuer>\n<clientID>" so that the two fields cannot be
// confused with one another, and it is truncated to fleetKeyLength characters.
// It returns "" when either field is empty, since a fleet cookie is only
// meaningful for a fully specified identity; callers must treat that as "no
// fleet cookie for this cluster" rather than as a usable key.
//
// This is a naming scheme, not a security measure. The key is visible in the
// cookie name and is not meant to hide the issuer or client ID, both of which
// are already public values; it exists to give the shared cookie a stable,
// cookie-safe name tied to an identity rather than to a cluster.
func FleetCookieKey(issuer, clientID string) string {
	if issuer == "" || clientID == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(issuer + "\n" + clientID))

	return hex.EncodeToString(sum[:])[:fleetKeyLength]
}

// isFleetKey reports whether a value has the exact shape FleetCookieKey
// produces: fleetKeyLength lowercase hex characters.
func isFleetKey(value string) bool {
	if len(value) != fleetKeyLength {
		return false
	}

	for i := range len(value) {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

// GetFleetCookiePath returns the path shared by every cluster, including
// baseURL. The shared token cookie is set here so that it is sent for all
// clusters, and deliberately not at "/" so that it is not attached to
// unauthenticated endpoints such as /config or the static assets.
func GetFleetCookiePath(baseURL string) string {
	if baseURL != "" {
		return "/" + strings.Trim(baseURL, "/") + "/clusters"
	}

	return "/clusters"
}

// SetFleetTokenCookie stores the token once, under a key naming the OIDC
// identity that issued it, at the path shared by all clusters.
func SetFleetTokenCookie(
	w http.ResponseWriter, r *http.Request, fleetKey, token, baseURL string, sessionTTL int,
) {
	if fleetKey == "" || token == "" {
		return
	}

	ClearFleetTokenCookie(w, r, fleetKey, baseURL)

	secure := IsSecureContext(r)
	path := GetFleetCookiePath(baseURL)

	for i, chunk := range splitToken(token, chunkSize) {
		// G124: Secure is set from IsSecureContext so localhost development still works;
		// HttpOnly and SameSite are set unconditionally.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec
			Name:     fmt.Sprintf("%s%s.%d", fleetCookiePrefix, fleetKey, i),
			Value:    chunk,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			Path:     path,
			MaxAge:   sessionTTL,
		})
	}
}

// SetFleetRefCookie points one cluster at a shared token cookie.
//
// Callers must only call this for a cluster that has passed the same issuer +
// client-id check as a broadcast target; it is the write-time half of the trust
// boundary described at the top of this file.
func SetFleetRefCookie(
	w http.ResponseWriter, r *http.Request, cluster, fleetKey, baseURL string, sessionTTL int,
) {
	sanitizedCluster := SanitizeClusterName(cluster)
	if sanitizedCluster == "" || fleetKey == "" {
		return
	}

	// G124: Secure is set from IsSecureContext so localhost development still works;
	// HttpOnly and SameSite are set unconditionally.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec
		Name:     fleetRefCookiePrefix + sanitizedCluster,
		Value:    fleetKey,
		HttpOnly: true,
		Secure:   IsSecureContext(r),
		SameSite: http.SameSiteStrictMode,
		Path:     GetCookiePath(baseURL, cluster),
		MaxAge:   sessionTTL,
	})
}

// GetTokenFromFleetCookie reassembles the token a cluster's ref cookie points
// at. It returns ("", nil) when the cluster has no ref cookie or the shared
// cookie it names is absent, which is the normal state for a cluster that is
// not part of a fleet or whose session has expired.
func GetTokenFromFleetCookie(r *http.Request, cluster string) (string, error) {
	sanitizedCluster := SanitizeClusterName(cluster)
	if sanitizedCluster == "" {
		return "", errors.New("invalid cluster name")
	}

	ref, err := r.Cookie(fleetRefCookiePrefix + sanitizedCluster)
	if err != nil {
		return "", nil
	}

	// The ref cookie is written by SetFleetRefCookie, but it arrives from the
	// client, so its value is untrusted input that is about to become part of a
	// cookie name. Require the exact shape FleetCookieKey produces rather than
	// merely a safe character set, so nothing else can be substituted for a key.
	if !isFleetKey(ref.Value) {
		return "", nil
	}

	return fleetTokenByKey(r, ref.Value), nil
}

// fleetTokenByKey reassembles the shared token stored under a key, or returns
// "" if the request carries no cookie for it.
//
// Callers are responsible for having established that the requesting cluster is
// entitled to this key — either from a ref cookie the browser sent for that
// cluster, or by matching the cluster's own kubeconfig OIDC config. The shared
// cookie is sent for every cluster path, so reading it without one of those
// checks would cross the trust boundary described above.
func fleetTokenByKey(r *http.Request, fleetKey string) string {
	if fleetKey == "" {
		return ""
	}

	var token strings.Builder

	for i := 0; ; i++ {
		cookie, err := r.Cookie(fmt.Sprintf("%s%s.%d", fleetCookiePrefix, fleetKey, i))
		if err != nil {
			break
		}

		token.WriteString(cookie.Value)
	}

	return token.String()
}

// ClearFleetTokenCookie expires every chunk of a shared token cookie. It only
// clears chunks the request actually carries, which is why it is safe to call
// before writing a shorter token: chunks beyond the new length are expired
// rather than left behind as stale trailing cookies.
func ClearFleetTokenCookie(w http.ResponseWriter, r *http.Request, fleetKey, baseURL string) {
	if fleetKey == "" {
		return
	}

	secure := IsSecureContext(r)
	path := GetFleetCookiePath(baseURL)

	for i := 0; ; i++ {
		name := fmt.Sprintf("%s%s.%d", fleetCookiePrefix, fleetKey, i)
		if _, err := r.Cookie(name); err != nil {
			break
		}

		// G124: Secure is set from IsSecureContext so localhost development still works;
		// HttpOnly and SameSite are set unconditionally.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec
			Name:     name,
			Value:    "",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			Path:     path,
			MaxAge:   -1,
		})
	}
}

// maxBlindClearChunks bounds how many chunk indices are expired without first
// confirming they exist. A token is chunked at chunkSize (3800) bytes, so eight
// indices cover ~30KB, well past any JWT a browser will carry and past the
// per-cookie limits of every current browser.
const maxBlindClearChunks = 8

// clearTokenCookieChunksBlind expires a cluster's per-cluster token cookie
// chunks without reading the request first.
//
// ClearTokenCookie stops at the first chunk index the request does not carry,
// which makes it a no-op on paths where the browser does not send cluster-
// scoped cookies at all — notably /oidc-callback, where cookies live under
// /clusters/<cluster> and so are invisible. Enrollment happens on exactly that
// path, so it cannot rely on reading: it has to expire the cookies it means to
// replace unconditionally. Expiring a chunk that was never set is harmless, as
// the browser simply has nothing to remove.
func clearTokenCookieChunksBlind(w http.ResponseWriter, r *http.Request, cluster, baseURL string) {
	sanitizedCluster := SanitizeClusterName(cluster)
	if sanitizedCluster == "" {
		return
	}

	secure := IsSecureContext(r)
	path := GetCookiePath(baseURL, cluster)

	for i := range maxBlindClearChunks {
		// G124: Secure is set from IsSecureContext so localhost development still works;
		// HttpOnly and SameSite are set unconditionally.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec
			Name:     fmt.Sprintf("headlamp-auth-%s.%d", sanitizedCluster, i),
			Value:    "",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			Path:     path,
			MaxAge:   -1,
		})
	}
}

// ClearFleetRefCookie expires one cluster's pointer at a shared token cookie,
// removing that cluster from the fleet without touching the shared token or any
// other cluster.
func ClearFleetRefCookie(w http.ResponseWriter, r *http.Request, cluster, baseURL string) {
	sanitizedCluster := SanitizeClusterName(cluster)
	if sanitizedCluster == "" {
		return
	}

	name := fleetRefCookiePrefix + sanitizedCluster
	if _, err := r.Cookie(name); err != nil {
		return
	}

	// G124: Secure is set from IsSecureContext so localhost development still works;
	// HttpOnly and SameSite are set unconditionally.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec
		Name:     name,
		Value:    "",
		HttpOnly: true,
		Secure:   IsSecureContext(r),
		SameSite: http.SameSiteStrictMode,
		Path:     GetCookiePath(baseURL, cluster),
		MaxAge:   -1,
	})
}
