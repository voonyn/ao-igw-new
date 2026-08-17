package oidc

import (
	"context"
	"reflect"
	"testing"

	"alphaomega/identitygateway/internal/platform/logger"
)

// claimsSvc builds the service over fixed mappers and one fixed person. It
// stands in for the two repository reads, which both need a database.
func claimsSvc(t *testing.T, mappers []ClaimMapper, profile UserProfile) *ClaimsService {
	t.Helper()
	log, _ := logger.NewObserved()

	return NewClaimsService(ClaimsDeps{
		Mappers: func(context.Context, string, []string) ([]ClaimMapper, error) {
			return mappers, nil
		},
		Profile: func(context.Context, string, string) (UserProfile, error) {
			return profile, nil
		},
		Log: log,
	})
}

// TestClaimsDelivery covers the two delivery flags of a standard attribute
// mapper. A claim reaches the ID token, the userinfo answer, or both, and the
// flags alone decide it.
func TestClaimsDelivery(t *testing.T) {
	svc := claimsSvc(t,
		[]ClaimMapper{
			{ClaimName: "email", SourceType: SourceStandard, SourceKey: "email", InUserInfo: true},
			{ClaimName: "given_name", SourceType: SourceStandard, SourceKey: "given_name", InIDToken: true},
			{ClaimName: "family_name", SourceType: SourceStandard, SourceKey: "family_name", InIDToken: true, InUserInfo: true},
		},
		UserProfile{Email: "person@example.com", FirstName: "Ada", LastName: "Lovelace"},
	)

	got, err := svc.Claims(context.Background(), "tenant-1", "user-1", []string{"openid", "profile", "email"})
	if err != nil {
		t.Fatalf("claims: %v", err)
	}

	wantIDToken := map[string]any{"given_name": "Ada", "family_name": "Lovelace"}
	if !reflect.DeepEqual(got.IDToken, wantIDToken) {
		t.Errorf("the ID token carries %v, want %v", got.IDToken, wantIDToken)
	}

	wantUserInfo := map[string]any{"email": "person@example.com", "family_name": "Lovelace"}
	if !reflect.DeepEqual(got.UserInfo, wantUserInfo) {
		t.Errorf("userinfo carries %v, want %v", got.UserInfo, wantUserInfo)
	}
}

// TestClaimsBag covers source type 2. The value comes from the custom
// attribute bag of the person, and a key the bag does not hold releases
// nothing.
func TestClaimsBag(t *testing.T) {
	svc := claimsSvc(t,
		[]ClaimMapper{
			{ClaimName: "department", SourceType: SourceBag, SourceKey: "department", InUserInfo: true},
			{ClaimName: "cost_centre", SourceType: SourceBag, SourceKey: "cost_centre", InUserInfo: true},
		},
		UserProfile{Attributes: map[string]any{"department": "flight ops"}},
	)

	got, err := svc.Claims(context.Background(), "tenant-1", "user-1", []string{"openid"})
	if err != nil {
		t.Fatalf("claims: %v", err)
	}

	want := map[string]any{"department": "flight ops"}
	if !reflect.DeepEqual(got.UserInfo, want) {
		t.Errorf("userinfo carries %v, want %v", got.UserInfo, want)
	}
}

// TestClaimsSkipped covers the mappers this release does not release. A source
// type of 3 or 4, a standard key outside the whitelist, and an attribute the
// person leaves empty all release nothing.
func TestClaimsSkipped(t *testing.T) {
	svc := claimsSvc(t,
		[]ClaimMapper{
			{ClaimName: "groups", SourceType: 3, SourceKey: "members", InUserInfo: true},
			{ClaimName: "tier", SourceType: 4, InUserInfo: true},
			{ClaimName: "password_hash", SourceType: SourceStandard, SourceKey: "password_hash", InUserInfo: true},
			{ClaimName: "locale", SourceType: SourceStandard, SourceKey: "locale", InUserInfo: true},
			{ClaimName: "updated_at", SourceType: SourceStandard, SourceKey: "updated_at", InUserInfo: true},
		},
		UserProfile{FirstName: "Ada"},
	)

	got, err := svc.Claims(context.Background(), "tenant-1", "user-1", []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("claims: %v", err)
	}

	if len(got.UserInfo) != 0 {
		t.Errorf("userinfo carries %v, want nothing", got.UserInfo)
	}
	if len(got.IDToken) != 0 {
		t.Errorf("the ID token carries %v, want nothing", got.IDToken)
	}
}
