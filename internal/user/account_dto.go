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

// PasswordBody is what a self-service password change carries: the password the
// person holds now, and the one they want next.
//
// The body names no account. The write reaches the subject of the caller's
// token, exactly as the profile write does.
//
// Both fields are bounded at 72 characters. That is the widest password bcrypt
// stores, counted in characters here so the bound reads as the person typed it.
// The byte ceiling behind it belongs to the policy check, which every password
// write runs, so a 72-character password of accented letters is refused there
// and never reaches the hash step.
//
// Neither field reaches a log line, at any level and in any environment.
type PasswordBody struct {
	CurrentPassword string `json:"currentPassword" validate:"required,max=72"`
	NewPassword     string `json:"newPassword" validate:"required,max=72"`
}

// PasswordStateView says whether the person holds a local password.
//
// The portal reads it to decide whether to offer the password change. A person
// the Directory owns holds no local password: the directory holds the credential
// and the rules that govern it, so the control is hidden rather than shown and
// refused.
//
// It carries no hash and no policy. The answer says one thing and nothing more.
type PasswordStateView struct {
	Local bool `json:"local"`
}
