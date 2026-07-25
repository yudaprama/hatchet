// Package kawai implements edge-trusted authentication for Hatchet so the Kawai
// web SPA can call Hatchet's tenant-scoped API directly through the Ory
// Oathkeeper edge — no per-request Hatchet API token.
//
// Model: Hatchet tenant == Kawai workspace (same UUID), Hatchet tenant member
// == workspace member. The edge injects the Kratos identity as X-User-Id, the
// real Kratos email as X-User-Email, and the active workspace as X-Workspace-Id
// (after a membership authorization check via the /api/v1/authz/workspace
// adapter). This package then JIT-provisions the matching Hatchet user (using
// the real Kratos email) so Hatchet's authn/authz accepts the request.
//
// Tenants and memberships are created EXPLICITLY via Hatchet's own API
// (POST /api/v1/tenants makes the creator OWNER; invite-accept adds members).
// The provision middleware only ensures the Hatchet User row exists — it does
// NOT auto-create tenants or memberships (the edge adapter denies requests for
// workspaces the user is not a member of before they reach Hatchet).
//
// SECURITY: this trusts the edge-injected headers. The Hatchet API MUST be
// bound on loopback behind Oathkeeper (which strips any client-supplied copy of
// the headers); never expose it publicly with edge auth enabled.
package kawai

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	apimiddleware "github.com/hatchet-dev/hatchet/api/v1/server/middleware"
	"github.com/hatchet-dev/hatchet/pkg/repository"
	"github.com/hatchet-dev/hatchet/pkg/repository/sqlcv1"
)

// Repo is the subset of the Hatchet V1 repository this package needs. It is
// satisfied by server config's V1 repository (repository.Repository).
type Repo interface {
	User() repository.UserRepository
	Tenant() repository.TenantRepository
}

// Config controls edge-auth behavior. Zero values fall back to sane defaults.
type Config struct {
	// UserHeader carries the Kratos identity id (default "X-User-Id").
	UserHeader string
	// EmailHeader carries the Kratos identity email (default "X-User-Email").
	// Used as the Hatchet user's email so invite-accept email matching works.
	EmailHeader string
	// WorkspaceHeader carries the active workspace id (default "X-Workspace-Id").
	WorkspaceHeader string
	// EmailDomain is the synthetic email suffix for provisioned users when the
	// email header is absent (loopback/internal callers). Default "kawai.local".
	EmailDomain string
	// DefaultRole is the tenant role granted to explicitly-provisioned members
	// (default "ADMIN"). Not used for JIT auto-provisioning anymore —
	// memberships are created via tenant:create (OWNER) or invite-accept.
	DefaultRole string
}

func (c Config) withDefaults() Config {
	if c.UserHeader == "" {
		c.UserHeader = "X-User-Id"
	}
	if c.EmailHeader == "" {
		c.EmailHeader = "X-User-Email"
	}
	if c.WorkspaceHeader == "" {
		c.WorkspaceHeader = "X-Workspace-Id"
	}
	if c.EmailDomain == "" {
		c.EmailDomain = "kawai.local"
	}
	if c.DefaultRole == "" {
		c.DefaultRole = string(sqlcv1.TenantMemberRoleADMIN)
	}
	return c
}

// Provisioner performs idempotent get-or-create of the Hatchet user, tenant and
// membership that mirror a Kawai identity + workspace.
type Provisioner struct {
	repo Repo
	cfg  Config
	l    *zerolog.Logger
}

func NewProvisioner(repo Repo, cfg Config, l *zerolog.Logger) *Provisioner {
	return &Provisioner{repo: repo, cfg: cfg.withDefaults(), l: l}
}

// resolveEmail returns the user's real email from the edge header, falling back
// to the deterministic synthetic email only for loopback/internal callers that
// don't carry the X-User-Email header (e.g. gRPC workers with bearer tenant UUID).
func (p *Provisioner) resolveEmail(c echo.Context, kawaiUserID string) string {
	if email := strings.TrimSpace(c.Request().Header.Get(p.cfg.EmailHeader)); email != "" {
		return strings.ToLower(email)
	}
	return strings.ToLower(kawaiUserID) + "@" + p.cfg.EmailDomain
}

// userEmail is the fallback synthetic email for callers without a request context.
func (p *Provisioner) userEmail(kawaiUserID string) string {
	return strings.ToLower(kawaiUserID) + "@" + p.cfg.EmailDomain
}

// EnsureUser returns the Hatchet user matching the given email, creating it on
// first sight. The user is created email-verified with no password/OAuth — it
// is only ever authenticated upstream by the edge.
func (p *Provisioner) EnsureUser(ctx context.Context, email, name string) (*sqlcv1.User, error) {
	u, err := p.repo.User().GetUserByEmail(ctx, email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	verified := true
	if name == "" {
		name = email
	}
	created, err := p.repo.User().CreateUser(ctx, &repository.CreateUserOpts{
		Email:         email,
		EmailVerified: &verified,
		Name:          &name,
	})
	if err != nil {
		return nil, fmt.Errorf("create edge user: %w", err)
	}
	return created, nil
}

// EnsureTenant returns the Hatchet tenant whose id equals the workspace UUID,
// creating it on first sight.
func (p *Provisioner) EnsureTenant(ctx context.Context, workspaceID string) (*sqlcv1.Tenant, error) {
	wsUUID, err := uuid.Parse(strings.TrimSpace(workspaceID))
	if err != nil {
		return nil, fmt.Errorf("invalid workspace id %q: %w", workspaceID, err)
	}

	t, err := p.repo.Tenant().GetTenantByID(ctx, wsUUID)
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get tenant by id: %w", err)
	}

	created, err := p.repo.Tenant().CreateTenant(ctx, &repository.CreateTenantOpts{
		ID:   &wsUUID,
		Name: workspaceID,
		Slug: wsUUID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("create edge tenant: %w", err)
	}
	return created, nil
}

// EnsureMembership verifies the user is a member of the tenant. With edge auth,
// the Oathkeeper /api/v1/authz/workspace adapter checks membership BEFORE the
// request reaches Hatchet — so a missing membership here is an anomaly (edge
// bypassed). Fail-closed: return error instead of auto-creating.
func (p *Provisioner) EnsureMembership(ctx context.Context, tenantID, userID uuid.UUID) error {
	m, err := p.repo.Tenant().GetTenantMemberByUserID(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("get tenant member: %w", err)
	}
	if m == nil {
		return fmt.Errorf("not a member of tenant %s", tenantID)
	}
	return nil
}

// tenantIDFromRequest prefers the {tenant} path param (what the populator and
// routing use) and falls back to the workspace header.
func (p *Provisioner) tenantIDFromRequest(c echo.Context) string {
	if id := strings.TrimSpace(c.Param("tenant")); id != "" {
		return id
	}
	return strings.TrimSpace(c.Request().Header.Get(p.cfg.WorkspaceHeader))
}

// Middleware returns a Hatchet MiddlewareFunc that JIT-provisions the Hatchet
// user for edge requests. It MUST be registered before the populator.
//
// Tenants and memberships are created EXPLICITLY via Hatchet's API
// (tenant:create, invite-accept) — this middleware only ensures the Hatchet
// User row exists so the populator and authn/authz can resolve c.Set("user").
// Requests without the identity header pass through untouched so local
// API-token (bearer) callers are unaffected.
func (p *Provisioner) Middleware() apimiddleware.MiddlewareFunc {
	return func(_ *apimiddleware.RouteInfo) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := strings.TrimSpace(c.Request().Header.Get(p.cfg.UserHeader))

			// Not an edge-authenticated request — leave bearer/cookie auth alone.
			if userID == "" {
				return nil
			}

			email := p.resolveEmail(c, userID)
			user, err := p.EnsureUser(c.Request().Context(), email, userID)
			if err != nil {
				p.l.Error().Err(err).Msg("kawai: provision user failed")
				return echo.NewHTTPError(http.StatusInternalServerError, "could not provision identity")
			}

			c.Set("user", user)
			return nil
		}
	}
}

// Authenticator implements server.CustomAuthenticator for edge-trusted requests.
type Authenticator struct {
	prov *Provisioner
}

func NewAuthenticator(prov *Provisioner) *Authenticator {
	return &Authenticator{prov: prov}
}

// Authenticate resolves the Hatchet user from the edge identity + email headers.
// The provision middleware has normally already created it; EnsureUser keeps
// this safe if the route skipped provisioning.
func (a *Authenticator) Authenticate(c echo.Context, _ *apimiddleware.RouteInfo) error {
	userID := strings.TrimSpace(c.Request().Header.Get(a.prov.cfg.UserHeader))
	if userID == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing edge identity header")
	}

	email := a.prov.resolveEmail(c, userID)
	user, err := a.prov.EnsureUser(c.Request().Context(), email, userID)
	if err != nil {
		a.prov.l.Error().Err(err).Msg("kawai: authenticate resolve user failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "could not resolve identity")
	}

	c.Set("user", user)
	return nil
}

// Authorize enforces that the resolved user is a member of the request's tenant.
// The edge /api/v1/authz/workspace adapter already checked membership before
// the request reached Hatchet; this is defense-in-depth. Non-tenant-scoped
// routes (no tenant in context) are allowed — the edge authenticated the user.
func (a *Authenticator) Authorize(c echo.Context, _ *apimiddleware.RouteInfo) error {
	tenant, ok := c.Get("tenant").(*sqlcv1.Tenant)
	if !ok {
		return nil
	}

	user, ok := c.Get("user").(*sqlcv1.User)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "no identity resolved")
	}

	member, err := a.prov.repo.Tenant().GetTenantMemberByUserID(c.Request().Context(), tenant.ID, user.ID)
	if err != nil || member == nil {
		return echo.NewHTTPError(http.StatusForbidden, "not a member of this workspace")
	}

	return nil
}

// CookieAuthorizerHook is a no-op for edge auth (cookie auth is not used).
func (a *Authenticator) CookieAuthorizerHook(_ echo.Context, _ *apimiddleware.RouteInfo) error {
	return nil
}
