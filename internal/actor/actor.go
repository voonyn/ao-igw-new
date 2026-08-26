// Package actor holds the person behind one administrative request.
//
// It is a leaf: it imports nothing of its own, so every domain can name the
// type. The shape lived in nine domain packages before, one identical copy
// each, and a field added to one copy reached none of the others.
//
// The reader is middlewares.ActorFrom, and it is not here. Reading the person
// takes a fiber.Ctx, and internal/tenant, internal/oidc and internal/audit
// cannot import internal/api/http/middlewares: the tenant middleware imports
// internal/oidc for the provider config of the resolved tenant, so the import
// would close a cycle. The type is a leaf and the reader sits with the
// middleware that put the values on the request.
package actor

// Actor is the person behind one administrative request.
//
// The IP and the user agent reach the audit trail, so a change is traceable to
// where it came from. A read records nothing, so a read path leaves both empty.
type Actor struct {
	TenantID  string
	UserID    string
	IP        string
	UserAgent string
}
