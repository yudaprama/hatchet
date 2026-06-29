// Package kawai implements edge-trusted authentication for Hatchet so the Kawai
// web SPA can call Hatchet's tenant-scoped API directly through the Ory
// Oathkeeper edge — no per-request Hatchet API token.
//
// Model: Hatchet tenant == Kawai workspace (same UUID), Hatchet tenant member
// == workspace member. The edge injects the Kratos identity as X-User-Id and
// the active workspace as X-Workspace-Id (after a Keto workspace authorization
// check, exactly like the prest-workspace rules). This package then:
//
//   - JIT-provisions the matching Hatchet user (email <id>@<domain>), tenant
//     (id = workspace UUID) and membership in a middleware that runs BEFORE the
//     populator (which loads {tenant} by id and would 404 on a missing tenant);
//   - resolves c.Set("user") in a CustomAuthenticator so Hatchet's authn/authz
//     accepts the request and scopes it to the workspace's tenant.
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
	// UserHeader carries the Kratos identity (default "X-User-Id").
	UserHeader string
	// WorkspaceHeader carries the active workspace id (default "X-Workspace-Id").
	WorkspaceHeader string
	// EmailDomain is the synthetic email suffix for provisioned users
	// (default "kawai.local"). The local part is the Kratos identity id.
	EmailDomain string
	// DefaultRole is the tenant role granted to JIT-provisioned members
	// (default "ADMIN"). Authorization for customAuth routes is enforced by
	// membership existence (see Authenticator.Authorize), so the role only has
	// to be a valid Hatchet role; finer per-workspace role mapping is a follow-up.
	DefaultRole string
}

func (c Config) withDefaults() Config {
	if c.UserHeader == "" {
		c.UserHeader = "X-User-Id"
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

// userEmail maps a Kratos identity id to its deterministic Hatchet email.
func (p *Provisioner) userEmail(kawaiUserID string) string {
	return strings.ToLower(kawaiUserID) + "@" + p.cfg.EmailDomain
}

// EnsureUser returns the Hatchet user for a Kawai identity, creating it on first
// sight. The user is created email-verified with no password/OAuth — it is only
// ever authenticated upstream by the edge.
func (p *Provisioner) EnsureUser(ctx context.Context, kawaiUserID string) (*sqlcv1.User, error) {
	email := p.userEmail(kawaiUserID)

	u, err := p.repo.User().GetUserByEmail(ctx, email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	verified := true
	name := kawaiUserID
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

// EnsureMembership makes the user a member of the tenant if not already.
func (p *Provisioner) EnsureMembership(ctx context.Context, tenantID, userID uuid.UUID) error {
	m, err := p.repo.Tenant().GetTenantMemberByUserID(ctx, tenantID, userID)
	if err == nil && m != nil {
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("get tenant member: %w", err)
	}

	if _, err := p.repo.Tenant().CreateTenantMember(ctx, tenantID, &repository.CreateTenantMemberOpts{
		Role:   p.cfg.DefaultRole,
		UserId: userID,
	}); err != nil {
		return fmt.Errorf("create tenant membership: %w", err)
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

// Middleware returns a Hatchet MiddlewareFunc that JIT-provisions the
// user/tenant/membership for edge requests. It MUST be registered before the
// populator. Requests without the identity header pass through untouched so
// local API-token (bearer) callers are unaffected.
func (p *Provisioner) Middleware() apimiddleware.MiddlewareFunc {
	return func(_ *apimiddleware.RouteInfo) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := strings.TrimSpace(c.Request().Header.Get(p.cfg.UserHeader))
			tenantID := p.tenantIDFromRequest(c)

			// Not an edge-authenticated request — leave bearer/cookie auth alone.
			if userID == "" {
				return nil
			}

			ctx := c.Request().Context()

			user, err := p.EnsureUser(ctx, userID)
			if err != nil {
				p.l.Error().Err(err).Msg("kawai: provision user failed")
				return echo.NewHTTPError(http.StatusInternalServerError, "could not provision identity")
			}

			// User-scoped (non-tenant) endpoints: just stash the user.
			if tenantID == "" {
				c.Set("user", user)
				return nil
			}

			tenant, err := p.EnsureTenant(ctx, tenantID)
			if err != nil {
				p.l.Error().Err(err).Msg("kawai: provision tenant failed")
				return echo.NewHTTPError(http.StatusInternalServerError, "could not provision workspace tenant")
			}

			if err := p.EnsureMembership(ctx, tenant.ID, user.ID); err != nil {
				p.l.Error().Err(err).Msg("kawai: provision membership failed")
				return echo.NewHTTPError(http.StatusInternalServerError, "could not provision workspace membership")
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

// Authenticate resolves the Hatchet user from the edge identity header. The
// provision middleware has normally already created it; EnsureUser keeps this
// safe if the route skipped provisioning.
func (a *Authenticator) Authenticate(c echo.Context, _ *apimiddleware.RouteInfo) error {
	userID := strings.TrimSpace(c.Request().Header.Get(a.prov.cfg.UserHeader))
	if userID == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing edge identity header")
	}

	user, err := a.prov.EnsureUser(c.Request().Context(), userID)
	if err != nil {
		a.prov.l.Error().Err(err).Msg("kawai: authenticate resolve user failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "could not resolve identity")
	}

	c.Set("user", user)
	return nil
}

// Authorize enforces that the resolved user is a member of the request's tenant.
// Tenant-level permission (view/write) was already checked at the edge via Keto;
// here we only confirm Hatchet-side membership exists. Non-tenant-scoped routes
// (no tenant in context) are allowed — the edge already authenticated the user.
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
