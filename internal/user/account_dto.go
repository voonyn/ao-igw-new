package user

// ProfileBody is what a self-service profile update carries: the four identity
// fields a person edits about themselves.
//
// The body names no account. The write reaches the subject of the caller's
// token, so a field that named another person would be ignored anyway, and the
// shape says so.
//
// Nothing here credentials a sign-in. The username, the email address, and the
// password are not writable, and neither is the phone number: the portal calls
// this route from the identity form only.
//
// Locale is the field name the portal sends. It is stored in
// user_humans.preferred_language, which the console calls lang.
type ProfileBody struct {
	FirstName   string `json:"firstName" validate:"max=255"`
	LastName    string `json:"lastName" validate:"max=255"`
	DisplayName string `json:"displayName" validate:"max=255"`
	Locale      string `json:"locale" validate:"max=20"`
}
