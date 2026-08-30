package notification

import (
	"errors"
	"fmt"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
	"time"
)

// The message keys the gateway renders. A key outside this set is refused: a row
// stored under any other name would never be read, and the console would show an
// override that changes nothing.
const (
	KeyPasswordReset     = "password_reset"
	KeyEmailVerification = "email_verification"
	KeyMemberInvitation  = "member_invitation"
	KeyPasskeyRegistered = "passkey_registered"
)

// Keys is every message key, in the order the console lists them.
var Keys = []string{
	KeyPasswordReset, KeyEmailVerification, KeyMemberInvitation, KeyPasskeyRegistered,
}

// The three levels one message can come from, most specific first.
const (
	SourceOrg      = "org"
	SourceTenant   = "tenant"
	SourceEmbedded = "embedded"
)

// ErrUnknownTemplate reports a key the gateway never sends.
var ErrUnknownTemplate = errors.New("unknown notification template")

// ErrTemplateSyntax reports a message that does not parse. It is refused on the
// write, because a stored template that fails to parse breaks every send of that
// key and the operator learns it from a password reset that never arrives.
var ErrTemplateSyntax = errors.New("the message does not parse")

// Content is the three parts of one message.
type Content struct {
	Subject  string
	BodyText string
	BodyHTML string
}

// embedded is the message every tenant falls back to. The gateway ships them, so
// a tenant that overrode nothing still sends something a person can act on.
var embedded = map[string]Content{
	KeyPasswordReset: {
		Subject:  "Reset your password",
		BodyText: "Hello {{.DisplayName}},\n\nOpen this link to choose a new password:\n{{.Link}}\n\nIf you did not ask for this, ignore this message.\n",
		BodyHTML: "<p>Hello {{.DisplayName}},</p>\n<p>Open this link to choose a new password:</p>\n<p><a href=\"{{.Link}}\">Reset your password</a></p>\n<p>If you did not ask for this, ignore this message.</p>\n",
	},
	KeyEmailVerification: {
		Subject:  "Verify your email address",
		BodyText: "Hello {{.DisplayName}},\n\nOpen this link to verify your email address:\n{{.Link}}\n\nYour code is {{.Code}}.\n",
		BodyHTML: "<p>Hello {{.DisplayName}},</p>\n<p>Open this link to verify your email address:</p>\n<p><a href=\"{{.Link}}\">Verify your email address</a></p>\n<p>Your code is <strong>{{.Code}}</strong>.</p>\n",
	},
	KeyPasskeyRegistered: {
		Subject:  "A passkey was added to your account",
		BodyText: "Hello {{.DisplayName}},\n\nA passkey was added to your account. You can now sign in with the device that holds it.\n\nIf you did not add it, open your security settings, remove the passkey, and change your password.\n",
		BodyHTML: "<p>Hello {{.DisplayName}},</p>\n<p>A passkey was added to your account. You can now sign in with the device that holds it.</p>\n<p>If you did not add it, open your security settings, remove the passkey, and change your password.</p>\n",
	},
	KeyMemberInvitation: {
		Subject:  "You are invited",
		BodyText: "Hello {{.DisplayName}},\n\nYou were invited to join. Open this link to accept:\n{{.Link}}\n",
		BodyHTML: "<p>Hello {{.DisplayName}},</p>\n<p>You were invited to join. Open this link to accept:</p>\n<p><a href=\"{{.Link}}\">Accept the invitation</a></p>\n",
	},
}

// Vars is what a message can name. The same three values render every key, so
// one preview and one send read the same shape.
type Vars struct {
	DisplayName string
	Link        string
	Code        string
}

// sample is the data a preview and a test send render with. It names nobody
// real, and the link points at a host that cannot be registered.
var sample = Vars{
	DisplayName: "Ada Lovelace",
	Link:        "https://example.com/verify?token=sample",
	Code:        "123456",
}

// TemplateBody is the body of one override write.
//
// The bounds match the columns: the subject is a VARCHAR(512) and both bodies
// are MEDIUMTEXT, so the limit here is what a person writes and not what MySQL
// holds.
type TemplateBody struct {
	Subject  string `json:"subject" validate:"required,max=512"`
	BodyText string `json:"bodyText" validate:"required,max=65535"`
	BodyHTML string `json:"bodyHtml" validate:"required,max=65535"`
}

// TemplateInfo is one row of the template list.
//
// IsOverride reports that the level that was read holds a row of its own, so the
// console knows whether a revert has anything to remove. Source names the level
// the message actually comes from, which is not the same question: an
// organization that stores nothing reads a tenant message.
type TemplateInfo struct {
	Key        string     `json:"key"`
	IsOverride bool       `json:"isOverride"`
	Source     string     `json:"source"`
	UpdatedAt  *time.Time `json:"updatedAt"`
}

// TemplateView is one message as the console edits it: the content that resolves
// at the level that was read, and where it came from.
type TemplateView struct {
	Key        string `json:"key"`
	IsOverride bool   `json:"isOverride"`
	Source     string `json:"source"`

	Subject  string `json:"subject"`
	BodyText string `json:"bodyText"`
	BodyHTML string `json:"bodyHtml"`
}

// RenderedView is one message rendered with the sample data.
type RenderedView struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// content answers the parts of one override row.
func (t Template) content() Content {
	return Content{Subject: t.Subject, BodyText: t.BodyText, BodyHTML: t.BodyHTML}
}

// row turns one write into the override row of a level.
func (b TemplateBody) row(tenantID, orgID, key string) Template {
	return Template{
		TenantID: tenantID,
		OrgID:    orgID,
		Key:      key,
		Subject:  b.Subject,
		BodyText: b.BodyText,
		BodyHTML: b.BodyHTML,
	}
}

// known reports that the gateway renders the key.
func known(key string) bool {
	_, ok := embedded[key]
	return ok
}

// parse checks that all three parts render. The subject and the text body are
// text templates, and the HTML body is an HTML template, so the escaping of a
// value matches where it lands.
func (c Content) parse() error {
	for name, source := range map[string]string{"subject": c.Subject, "bodyText": c.BodyText} {
		if _, err := texttemplate.New(name).Parse(source); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrTemplateSyntax, name, err)
		}
	}
	if _, err := htmltemplate.New("bodyHtml").Parse(c.BodyHTML); err != nil {
		return fmt.Errorf("%w: bodyHtml: %v", ErrTemplateSyntax, err)
	}
	return nil
}

// render fills one message with the values it names.
func (c Content) render(vars Vars) (RenderedView, error) {
	subject, err := renderText("subject", c.Subject, vars)
	if err != nil {
		return RenderedView{}, err
	}
	text, err := renderText("bodyText", c.BodyText, vars)
	if err != nil {
		return RenderedView{}, err
	}

	parsed, err := htmltemplate.New("bodyHtml").Parse(c.BodyHTML)
	if err != nil {
		return RenderedView{}, fmt.Errorf("%w: bodyHtml: %v", ErrTemplateSyntax, err)
	}
	var out strings.Builder
	if err := parsed.Execute(&out, vars); err != nil {
		return RenderedView{}, fmt.Errorf("%w: bodyHtml: %v", ErrTemplateSyntax, err)
	}

	return RenderedView{Subject: subject, Text: text, HTML: out.String()}, nil
}

// renderText fills one text part of a message.
func renderText(name, source string, vars Vars) (string, error) {
	parsed, err := texttemplate.New(name).Parse(source)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrTemplateSyntax, name, err)
	}
	var out strings.Builder
	if err := parsed.Execute(&out, vars); err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrTemplateSyntax, name, err)
	}
	return out.String(), nil
}
