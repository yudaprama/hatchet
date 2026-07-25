package middleware

import (
	"context"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/hatchet-dev/hatchet/pkg/analytics"
	"github.com/hatchet-dev/hatchet/pkg/config/server"
	"github.com/hatchet-dev/hatchet/pkg/telemetry"
)

type GRPCAuthN struct {
	config *server.ServerConfig

	l *zerolog.Logger
}

func NewAuthN(config *server.ServerConfig) *GRPCAuthN {
	return &GRPCAuthN{
		config: config,
		l:      config.Logger,
	}
}

func (a *GRPCAuthN) Middleware(ctx context.Context) (context.Context, error) {
	// Kawai edge auth: workers pass the tenant UUID as the bearer "token"
	// (no JWT). The gRPC API is loopback-only behind Oathkeeper, so we trust
	// the caller and resolve the tenant by ID directly.
	if a.config.Auth.EdgeAuthEnabled {
		return a.edgeAuthMiddleware(ctx)
	}

	forbidden := status.Errorf(codes.Unauthenticated, "invalid auth token")
	token, err := auth.AuthFromMD(ctx, "bearer")

	if err != nil {
		a.l.Debug().Ctx(ctx).Err(err).Msgf("error getting bearer token from request: %s", err)
		return nil, forbidden
	}

	tenantId, tokenUUID, err := a.config.Auth.JWTManager.ValidateTenantToken(ctx, token)

	if err != nil {
		a.l.Debug().Ctx(ctx).Err(err).Msgf("error validating tenant token: %s", err)

		return nil, forbidden
	}

	ctx = context.WithValue(ctx, analytics.APITokenIDKey, tokenUUID)
	ctx = context.WithValue(ctx, analytics.TenantIDKey, tenantId)

	span := trace.SpanFromContext(ctx)
	telemetry.WithAttributes(span,
		telemetry.AttributeKV{Key: "tenant.id", Value: tenantId},
	)

	source := analytics.SourceGRPC
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(analytics.SourceMetadataKey); len(vals) > 0 {
			source = analytics.Source(vals[0])
		}
	}
	ctx = context.WithValue(ctx, analytics.SourceKey, source)

	queriedTenant, err := a.config.V1.Tenant().GetTenantByID(ctx, tenantId)

	if err != nil {
		a.l.Debug().Ctx(ctx).Err(err).Msgf("error getting tenant by id: %s", err)
		return nil, forbidden
	}

	return context.WithValue(ctx, "tenant", queriedTenant), nil
}

// edgeAuthMiddleware resolves the tenant from a bare tenant UUID passed as the
// bearer "token" — no JWT validation. Workers are trusted internal callers on
// loopback; the REST API path is gated by Oathkeeper edge auth separately.
func (a *GRPCAuthN) edgeAuthMiddleware(ctx context.Context) (context.Context, error) {
	forbidden := status.Errorf(codes.Unauthenticated, "invalid auth token")
	token, err := auth.AuthFromMD(ctx, "bearer")

	if err != nil {
		a.l.Debug().Ctx(ctx).Err(err).Msgf("edge auth: missing bearer token: %s", err)
		return nil, forbidden
	}

	tenantUUID, err := uuid.Parse(token)
	if err != nil {
		a.l.Debug().Ctx(ctx).Err(err).Msg("edge auth: bearer is not a valid tenant UUID")
		return nil, forbidden
	}

	queriedTenant, err := a.config.V1.Tenant().GetTenantByID(ctx, tenantUUID)
	if err != nil {
		a.l.Debug().Ctx(ctx).Err(err).Msg("edge auth: tenant not found")
		return nil, forbidden
	}

	ctx = context.WithValue(ctx, analytics.TenantIDKey, tenantUUID)
	// Rate limiter keys on APITokenIDKey — use the tenant UUID so each tenant
	// gets its own rate limit bucket.
	ctx = context.WithValue(ctx, analytics.APITokenIDKey, tenantUUID)

	span := trace.SpanFromContext(ctx)
	telemetry.WithAttributes(span,
		telemetry.AttributeKV{Key: "tenant.id", Value: tenantUUID},
	)

	source := analytics.SourceGRPC
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(analytics.SourceMetadataKey); len(vals) > 0 {
			source = analytics.Source(vals[0])
		}
	}
	ctx = context.WithValue(ctx, analytics.SourceKey, source)

	return context.WithValue(ctx, "tenant", queriedTenant), nil
}
