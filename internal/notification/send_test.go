package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// TestSendTestHandsTheResolvedMessageToTheTransport covers the diagnostic send.
// It renders what this tenant actually sends, so a passing test proves the
// template and the relay together.
func TestSendTestHandsTheResolvedMessageToTheTransport(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyPasswordReset,
		templateBody("Reset your password")); err != nil {
		t.Fatalf("write the tenant override: %v", err)
	}

	err := svc.SendTest(context.Background(), noteOperator, TestBody{
		To: "operator@example.com", Template: KeyPasswordReset,
	})
	if err != nil {
		t.Fatalf("send the test message: %v", err)
	}
	if len(sentMessages) != 1 {
		t.Fatalf("the send handed over %d messages, want one", len(sentMessages))
	}

	msg := sentMessages[0]
	if msg.To != "operator@example.com" || msg.Subject != "Reset your password" {
		t.Errorf("the message reads %+v, want the resolved template", msg)
	}
	if !strings.Contains(msg.Text, sample.DisplayName) {
		t.Errorf("the message reads text %q, want the sample data rendered", msg.Text)
	}

	if len(noteEvents) != 2 || noteEvents[1].Action != string(audit.ActionNotificationTestSent) {
		t.Fatalf("the send recorded %+v, want one test event", noteEvents)
	}
	if strings.Contains(noteEvents[1].Metadata, "operator@example.com") {
		t.Errorf("the event metadata reads %q, want no recipient address", noteEvents[1].Metadata)
	}
}

// TestSendTestAnswersSendFailedWhenTheTransportRefuses covers the answer the
// console has a sentence for. The operator reads it as a configuration problem,
// because that is what it almost always is.
func TestSendTestAnswersSendFailedWhenTheTransportRefuses(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)
	sendFails = true

	err := svc.SendTest(context.Background(), noteOperator, TestBody{
		To: "operator@example.com", Template: KeyPasswordReset,
	})
	if !errors.Is(err, ErrSendFailed) {
		t.Errorf("a refused send reads %v, want ErrSendFailed", err)
	}
	if len(noteEvents) != 0 {
		t.Errorf("the refused send recorded %+v, want nothing", noteEvents)
	}
}

// TestSendTestMasksTheRecipientInTheLog covers the address of a person. It is
// not a credential, and it is still not written out in full.
func TestSendTestMasksTheRecipientInTheLog(t *testing.T) {
	log, logs := logger.NewObserved()
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)
	svc.log, svc.deps.Log = log, log

	if err := svc.SendTest(context.Background(), noteOperator, TestBody{
		To: "operator@example.com", Template: KeyPasswordReset,
	}); err != nil {
		t.Fatalf("send the test message: %v", err)
	}
	for _, entry := range logs.All() {
		line := fmt.Sprintf("%s %v", entry.Message, entry.ContextMap())
		if strings.Contains(line, "operator@example.com") {
			t.Errorf("the log line %q carries the recipient in full", line)
		}
	}
}

// TestSendTestRefusesAKeyTheGatewayNeverSends covers a typed key.
func TestSendTestRefusesAKeyTheGatewayNeverSends(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	err := svc.SendTest(context.Background(), noteOperator, TestBody{
		To: "operator@example.com", Template: "not_a_template",
	})
	if !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("an unknown key sends %v, want ErrUnknownTemplate", err)
	}
	if len(sentMessages) != 0 {
		t.Errorf("the refused send handed over %+v, want nothing", sentMessages)
	}
}

// TestSendTestRefusesAPersonWhoDoesNotManageTheTenant covers the gate. The test
// send uses the tenant relay, so it is gated the way the relay is.
func TestSendTestRefusesAPersonWhoDoesNotManageTheTenant(t *testing.T) {
	svc := testService(t, nil, orgOwner(noteOrgID))

	err := svc.SendTest(context.Background(), noteOperator, TestBody{
		To: "operator@example.com", Template: KeyPasswordReset,
	})
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner sends %v, want ErrForbidden", err)
	}
	if len(sentMessages) != 0 {
		t.Errorf("the refused send handed over %+v, want nothing", sentMessages)
	}
}
