package http

import (
	"context"
	"time"

	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/user"
	"alphaomega/identitygateway/internal/userfederation"
	"alphaomega/identitygateway/internal/utils"
)

// directoryPerson writes the local rows of the person one first bind creates.
//
// The composition sits here, and not in either module, because the provider
// domain must not import the user domain: it takes the write as a function
// value, and this is where the crossing is wired.
//
// All three writes run on the caller's transaction, so the person, the profile,
// the membership, and the Federation Link land whole or not at all. A username
// another live account of the tenant holds fails the first write and leaves
// nothing behind.
//
// The row is a human account in the initial active state, and it holds no
// password hash: a person the directory owns has no local password, ever, and an
// account written in state 5 could never set one.
//
// The membership carries no role, so the person reaches nothing in the console
// until an administrator grants one. The row itself is written because the
// roster of an organization reads organization_members, so a person with
// users.org_id set and no membership would belong to an organization that never
// lists them. It is the shape every other person of this gateway holds, and
// MemberService.Add grants the first role on top of it.
//
// The email address is not marked verified. It is a trust claim that states what
// this gateway verified, and this gateway verified nothing: it read the value
// from a directory.
func directoryPerson(users *user.Repository, orgs *organization.Repository) userfederation.PersonCreator {
	return func(ctx context.Context, p userfederation.Person) (string, error) {
		now := time.Now().UTC()
		row := user.User{
			ID:        utils.NewUUIDv7(),
			TenantID:  p.TenantID,
			OrgID:     p.OrgID,
			Username:  p.Username,
			UserType:  user.TypeHuman,
			State:     user.StateActive,
			CreatedAt: now,
		}
		if err := users.Insert(ctx, row); err != nil {
			return "", err
		}
		if err := users.InsertHuman(ctx, user.Human{
			UserID:      row.ID,
			TenantID:    p.TenantID,
			FirstName:   p.FirstName,
			LastName:    p.LastName,
			DisplayName: p.DisplayName,
			Email:       p.Email,
			CreatedAt:   now,
		}); err != nil {
			return "", err
		}
		if err := orgs.InsertMembership(ctx, organization.Membership{
			TenantID:  p.TenantID,
			OrgID:     p.OrgID,
			UserID:    row.ID,
			Roles:     []string{},
			CreatedAt: now,
		}); err != nil {
			return "", err
		}
		return row.ID, nil
	}
}
