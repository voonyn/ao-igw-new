package notification

// The delivery every tenant falls back to when it configured nothing. They
// repeat the column defaults of notification_settings, so a tenant with a row
// and a tenant without one are governed by the same numbers.
const (
	TransportLog              = "log"
	TransportSMTP             = "smtp"
	DefaultSMTPPort           = 587
	DefaultTLSMode            = "starttls"
	DefaultSendTimeoutSeconds = 10
)

// SettingsBody is the body of one delivery write. The console submits the whole
// form, so every field except the password replaces what is stored.
//
// SMTPPassword is the one write-only field, and it is a pointer because three
// answers are possible: absent keeps the stored credential, an empty string
// clears it, and a value replaces it.
//
// The bounds match the ones the console renders. The backend is the enforcement
// point, and the console form is a convenience for the operator.
type SettingsBody struct {
	Transport string `json:"transport" validate:"required,oneof=smtp log"`

	SMTPHost     string  `json:"smtpHost" validate:"required_if=Transport smtp,omitempty,max=255"`
	SMTPPort     int     `json:"smtpPort" validate:"required,min=1,max=65535"`
	SMTPUsername string  `json:"smtpUsername" validate:"omitempty,max=255"`
	SMTPPassword *string `json:"smtpPassword" validate:"omitnil,max=255"`

	FromAddress string `json:"fromAddress" validate:"required_if=Transport smtp,omitempty,email,max=320"`
	FromName    string `json:"fromName" validate:"omitempty,max=255"`

	TLSMode            string `json:"tlsMode" validate:"required,oneof=starttls tls none"`
	SendTimeoutSeconds int    `json:"sendTimeoutSeconds" validate:"required,min=1,max=300"`
}

// SettingsView is how this tenant sends mail, as the console reads it.
//
// PasswordSet reports that a credential is stored. The value is never carried:
// the console renders a badge and a change button from this one flag.
//
// Configured reports that the transport can be used as it stands. The log
// transport always can, because it delivers to the log and needs nothing.
type SettingsView struct {
	Transport          string `json:"transport"`
	SMTPHost           string `json:"smtpHost"`
	SMTPPort           int    `json:"smtpPort"`
	SMTPUsername       string `json:"smtpUsername"`
	PasswordSet        bool   `json:"passwordSet"`
	FromAddress        string `json:"fromAddress"`
	FromName           string `json:"fromName"`
	TLSMode            string `json:"tlsMode"`
	SendTimeoutSeconds int    `json:"sendTimeoutSeconds"`
	Configured         bool   `json:"configured"`
}

// TestBody is the body of one diagnostic send. Template names one of the keys
// the gateway renders, and the service refuses any other.
type TestBody struct {
	To       string `json:"to" validate:"required,email,max=320"`
	Template string `json:"template" validate:"required,max=64"`
}

// defaultSettings is the delivery of a tenant that stored no row.
func defaultSettings(tenantID string) Settings {
	return Settings{
		TenantID:      tenantID,
		Transport:     TransportLog,
		SMTPPort:      DefaultSMTPPort,
		TLSMode:       DefaultTLSMode,
		SendTimeoutMS: DefaultSendTimeoutSeconds * 1000,
	}
}

// apply writes one body onto the stored row and answers the row to store. The
// password follows the write-only rule, so an absent field keeps what is there.
func (b SettingsBody) apply(stored Settings) Settings {
	stored.Transport = b.Transport
	stored.SMTPHost = b.SMTPHost
	stored.SMTPPort = b.SMTPPort
	stored.SMTPUsername = b.SMTPUsername
	stored.FromAddress = b.FromAddress
	stored.FromName = b.FromName
	stored.TLSMode = b.TLSMode
	stored.SendTimeoutMS = b.SendTimeoutSeconds * 1000

	if b.SMTPPassword != nil {
		stored.Password = *b.SMTPPassword
	}
	return stored
}

// view answers the delivery settings the console renders. The password is
// reported as a flag and never as a value.
func (s Settings) view() SettingsView {
	return SettingsView{
		Transport:          s.Transport,
		SMTPHost:           s.SMTPHost,
		SMTPPort:           s.SMTPPort,
		SMTPUsername:       s.SMTPUsername,
		PasswordSet:        s.Password != "",
		FromAddress:        s.FromAddress,
		FromName:           s.FromName,
		TLSMode:            s.TLSMode,
		SendTimeoutSeconds: s.SendTimeoutMS / 1000,
		Configured:         s.usable(),
	}
}

// usable reports that the transport can send as it stands. SMTP needs a host to
// dial and an address to send from. The log transport needs nothing.
func (s Settings) usable() bool {
	if s.Transport != TransportSMTP {
		return true
	}
	return s.SMTPHost != "" && s.FromAddress != ""
}
