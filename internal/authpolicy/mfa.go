package authpolicy

import (
	"context"
	"fmt"

	"alphaomega/identitygateway/internal/platform/logger"
)

// MFARequired reports whether the resolved policy of one level demands a Second
// Factor. An empty orgID reads the tenant default.
//
// It is the function value the sign-in takes, so the login stack imports nothing
// from this package. It resolves both levels, the way Enforce does, because an
// organization override that the console reports as set must be honoured at
// sign-in.
//
// A failed policy read is logged here and nowhere else. The caller receives the
// error as an opaque value it cannot classify, so this is the last layer that
// can name the tenant and the organization the read was for. The caller refuses
// the step on it: a policy nobody could read must never read as "no factor
// required".
func (s *Service) MFARequired(ctx context.Context, tenantID, orgID string) (bool, error) {
	s.log.Debug("read the mfa requirement",
		logger.String("tenant_id", tenantID),
		logger.String("org_id", orgID), logger.RequestID(ctx))

	view, err := s.resolved(ctx, tenantID, orgID)
	if err != nil {
		s.log.Error("read the auth policy to check the mfa requirement",
			logger.String("tenant_id", tenantID),
			logger.String("org_id", orgID), logger.Err(err))
		return false, fmt.Errorf("read the auth policy of %s/%s: %w", tenantID, orgID, err)
	}

	s.log.Debug("read the mfa requirement",
		logger.String("tenant_id", tenantID), logger.String("org_id", orgID),
		logger.Bool("mfa_required", view.MfaRequired), logger.RequestID(ctx))
	return view.MfaRequired, nil
}
