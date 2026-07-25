// Package authz implements the Kawai edge-authz status-code adapter.
//
// POST /api/v1/authz/tenant is called by Ory Oathkeeper's remote_json
// authorizer to verify workspace membership BEFORE the request reaches any
// upstream service (Hatchet itself or pREST). It checks the Hatchet
// TenantMember table directly — the single source of truth for workspace
// membership — and answers with an HTTP status code (200 allow / 403 deny)
// because Oathkeeper's remote_json keys on the status, not the body.
//
// The endpoint is unauthenticated and MUST only be reachable on loopback
// (Oathkeeper and Hatchet both bind localhost). It is registered OUTSIDE the
// OpenAPI spec middleware chain (no populator/authn/authz) so it can serve
// as the trust root for those very middlewares.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hatchet-dev/hatchet/pkg/config/server"
)

// permissionLevel ranks Hatchet roles so that a higher role implies all lower
// permissions: OWNER (3) > ADMIN (2) > MEMBER (1). A request for permission P
// is allowed iff the member's level >= required level for P.
const (
	levelMember = 1
	levelAdmin  = 2
	levelOwner  = 3
)

func roleLevel(role string) int {
	switch role {
	case "OWNER":
		return levelOwner
	case "ADMIN":
		return levelAdmin
	case "MEMBER":
		return levelMember
	default:
		return 0
	}
}

func permissionLevel(permission string) int {
	switch permission {
	case "manage":
		return levelOwner
	case "write":
		return levelAdmin
	case "view":
		return levelMember
	default:
		return levelMember
	}
}

// TenantAuthzHandler returns the Oathkeeper remote_json adapter. It reads
// {user (email), tenant (uuid), permission} from the request body, resolves
// the TenantMember by email+tenantId, and answers 200/403.
//
// Semantics:
//   - empty tenant → 200 (personal scope, upstream scopes by user_id only);
//   - member found with sufficient role → 200;
//   - member not found or insufficient role → 403;
//   - any error → 403 (fail closed).
func TenantAuthzHandler(config *server.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			User       string `json:"user"`
			Tenant     string `json:"tenant"`
			Permission string `json:"permission"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.User == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if body.Tenant == "" {
			w.WriteHeader(http.StatusOK)
			return
		}

		tenantUUID, err := uuid.Parse(body.Tenant)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		required := permissionLevel(body.Permission)

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		member, err := config.V1.Tenant().GetTenantMemberByEmail(ctx, tenantUUID, body.User)
		if err != nil || member == nil {
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				// Expected for non-members (pgx.ErrNoRows) — deny, do not log loudly.
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if roleLevel(string(member.Role)) < required {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
