package notification

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/utils"
)

// NewSender answers the transport a tenant's settings name.
//
// The log transport writes one line and delivers nothing. It is what a tenant
// that configured no relay uses, so a development deployment sends no mail by
// accident.
//
// The SMTP password is read from the settings and handed to the relay. It
// reaches no log line here, at any level: the failure lines name the host and
// the error, never the credential.
func NewSender(log logger.Logger) Sender {
	return func(ctx context.Context, settings Settings, msg Message) error {
		if settings.Transport != TransportSMTP {
			log.Info("the log transport delivered a message",
				logger.String("tenant_id", settings.TenantID),
				logger.String("subject", msg.Subject))
			return nil
		}
		return sendSMTP(ctx, settings, msg, log)
	}
}

// sendSMTP hands one message to the relay the settings name.
func sendSMTP(ctx context.Context, settings Settings, msg Message, log logger.Logger) error {
	address := net.JoinHostPort(settings.SMTPHost, strconv.Itoa(settings.SMTPPort))
	timeout := time.Duration(settings.SendTimeoutMS) * time.Millisecond

	client, err := dial(ctx, settings, address, timeout)
	if err != nil {
		return err
	}
	defer client.Close()

	if settings.TLSMode == "starttls" {
		if err := client.StartTLS(&tls.Config{ServerName: settings.SMTPHost}); err != nil {
			return fmt.Errorf("start TLS with %s: %w", address, err)
		}
	}

	if settings.SMTPUsername != "" {
		auth := smtp.PlainAuth("", settings.SMTPUsername, settings.Password, settings.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticate to %s: %w", address, err)
		}
	}

	if err := client.Mail(settings.FromAddress); err != nil {
		return fmt.Errorf("open an envelope on %s: %w", address, err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("name a recipient on %s: %w", address, err)
	}

	body, err := compose(settings, msg)
	if err != nil {
		return err
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("open the body on %s: %w", address, err)
	}
	if _, err := writer.Write(body); err != nil {
		return fmt.Errorf("write the body to %s: %w", address, err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close the body on %s: %w", address, err)
	}

	log.Debug("the relay accepted a message",
		logger.String("tenant_id", settings.TenantID), logger.String("smtp_host", settings.SMTPHost))
	return client.Quit()
}

// dial opens the connection the TLS mode asks for. Implicit TLS wraps the socket
// from the first byte, and the other two modes open it in the clear: starttls
// then upgrades it, and none leaves it open.
func dial(ctx context.Context, settings Settings, address string, timeout time.Duration) (*smtp.Client, error) {
	dialer := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	var err error
	if settings.TLSMode == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: settings.SMTPHost})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	client, err := smtp.NewClient(conn, settings.SMTPHost)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open an SMTP session on %s: %w", address, err)
	}
	return client, nil
}

// compose writes one message as the RFC 5322 bytes the relay reads. The two
// bodies go in a multipart/alternative, plain text first, so a reader that
// renders no HTML still reads the message.
func compose(settings Settings, msg Message) ([]byte, error) {
	var out strings.Builder
	body := multipart.NewWriter(&out)

	from := settings.FromAddress
	if settings.FromName != "" {
		from = fmt.Sprintf("%s <%s>", settings.FromName, settings.FromAddress)
	}

	fmt.Fprintf(&out, "From: %s\r\n", from)
	fmt.Fprintf(&out, "To: %s\r\n", msg.To)
	fmt.Fprintf(&out, "Subject: %s\r\n", msg.Subject)
	fmt.Fprintf(&out, "Message-ID: <%s@%s>\r\n", utils.NewUUIDv7(), settings.SMTPHost)
	fmt.Fprintf(&out, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&out, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&out, "Content-Type: multipart/alternative; boundary=%s\r\n\r\n", body.Boundary())

	for _, part := range []struct{ mediaType, content string }{
		{"text/plain; charset=utf-8", msg.Text},
		{"text/html; charset=utf-8", msg.HTML},
	} {
		writer, err := body.CreatePart(textproto.MIMEHeader{"Content-Type": {part.mediaType}})
		if err != nil {
			return nil, fmt.Errorf("compose the %s part: %w", part.mediaType, err)
		}
		if _, err := writer.Write([]byte(part.content)); err != nil {
			return nil, fmt.Errorf("write the %s part: %w", part.mediaType, err)
		}
	}
	if err := body.Close(); err != nil {
		return nil, fmt.Errorf("close the message: %w", err)
	}
	return []byte(out.String()), nil
}
