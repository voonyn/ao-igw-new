package di

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"alphaomega/identitygateway/internal/platform/config"
)

// newTestClient points a Client at srv with a fixed credential.
func newTestClient(srv *httptest.Server) *Client {
	return New(config.DIConfig{
		BaseURL:           srv.URL,
		ClientID:          "spass_iam",
		ClientSecret:      "s3cr3t",
		InputDescriptorID: "custom-descriptor",
		Timeout:           time.Second,
	}, nil)
}

func TestClient_InitializeVPTransaction(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantErr  bool
		expected Transaction
	}{
		{
			name:   "carries both identifiers and the qr_code object verbatim",
			status: http.StatusOK,
			body: `{"data":{"presentation_id":"1f2e3d4c5b6a7988990a1b2c3d4e5f60",
			         "qr_code":{"session_id":"aabbccddeeff00112233445566778899",
			                    "url":"openid4vp://authorize?x=1",
			                    "fallback_url":"https://di.example/get-the-app",
			                    "callback":"xxx"}}}`,
			expected: Transaction{
				PresentationID: "1f2e3d4c5b6a7988990a1b2c3d4e5f60",
				SessionID:      "aabbccddeeff00112233445566778899",
			},
		},
		{
			name:    "a response missing presentation_id is an error, not an empty transaction",
			status:  http.StatusOK,
			body:    `{"data":{"qr_code":{"session_id":"aabb"}}}`,
			wantErr: true,
		},
		{
			name:    "a response missing session_id is an error",
			status:  http.StatusOK,
			body:    `{"data":{"presentation_id":"1f2e","qr_code":{}}}`,
			wantErr: true,
		},
		{
			name:    "a non-2xx status is an error",
			status:  http.StatusBadGateway,
			body:    `{"error":"upstream"}`,
			wantErr: true,
		},
		{
			name:    "an unparsable body is an error",
			status:  http.StatusOK,
			body:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAuth, gotPath, gotNonce string
			var in struct {
				Nonce                  string          `json:"nonce"`
				ClientID               string          `json:"clientId"`
				ClientSecret           string          `json:"clientSecret"`
				Aud                    string          `json:"aud"`
				PresentationDefinition json.RawMessage `json:"presentationDefinition"`
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&in)
				gotNonce = in.Nonce
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			txn, err := newTestClient(srv).InitializeVPTransaction(context.Background(), "the-nonce")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("InitializeVPTransaction: want error, got %+v", txn)
				}
				return
			}
			if err != nil {
				t.Fatalf("InitializeVPTransaction: %v", err)
			}

			// The Scan Verifier authenticates the caller in the BODY and refuses any
			// Authorization header, so sending one is a regression.
			if gotAuth != "" {
				t.Errorf("Authorization = %q, want no header at all", gotAuth)
			}
			if in.ClientID != "spass_iam" || in.ClientSecret != "s3cr3t" {
				t.Errorf("body credentials = %q/%q, want spass_iam/s3cr3t", in.ClientID, in.ClientSecret)
			}
			// The Scan Verifier refuses a request with no definition, and refuses a
			// definition whose inner keys are camel case. Pin the snake_case seam.
			var pd struct {
				ID               string `json:"id"`
				InputDescriptors []struct {
					ID     string `json:"id"`
					Format struct {
						SDJWT struct {
							Algs []string `json:"sd-jwt_alg_values"`
						} `json:"vc+sd-jwt"`
					} `json:"format"`
					Constraints struct {
						LimitDisclosure string `json:"limit_disclosure"`
						Fields          []struct {
							Path   []string `json:"path"`
							Filter *struct {
								Type  string `json:"type"`
								Const string `json:"const"`
							} `json:"filter"`
						} `json:"fields"`
					} `json:"constraints"`
				} `json:"input_descriptors"`
			}
			if err := json.Unmarshal(in.PresentationDefinition, &pd); err != nil {
				t.Fatalf("presentationDefinition: %v", err)
			}
			if len(pd.InputDescriptors) != 1 || pd.InputDescriptors[0].Constraints.LimitDisclosure != "required" {
				t.Errorf("presentationDefinition = %s, want one snake_case descriptor with limit_disclosure", in.PresentationDefinition)
			}
			// The Scan Verifier matches the credential by this id, so the configured
			// value must reach the wire unchanged.
			if pd.InputDescriptors[0].ID != "custom-descriptor" {
				t.Errorf("input_descriptors[0].id = %q, want custom-descriptor", pd.InputDescriptors[0].ID)
			}
			// The definition id is a fresh uuid per transaction, not a fixed string.
			if _, err := uuid.Parse(pd.ID); err != nil {
				t.Errorf("presentationDefinition.id = %q, want a uuid", pd.ID)
			}
			if got := pd.InputDescriptors[0].Format.SDJWT.Algs; len(got) != 1 || got[0] != "ES256" {
				t.Errorf("sd-jwt_alg_values = %v, want [ES256]", got)
			}
			// Two fields: the vct type filter DI matches the credential on, and the
			// username claim QR login resolves against users.username.
			fields := pd.InputDescriptors[0].Constraints.Fields
			if len(fields) != 2 {
				t.Fatalf("constraints.fields = %v, want 2", fields)
			}
			if len(fields[0].Path) != 1 || fields[0].Path[0] != "$.vct" ||
				fields[0].Filter == nil || fields[0].Filter.Const != "custom-descriptor" {
				t.Errorf("fields[0] = %+v, want $.vct filtered to custom-descriptor", fields[0])
			}
			if len(fields[1].Path) != 1 || fields[1].Path[0] != "$.username.value" {
				t.Errorf("fields[1].path = %v, want [$.username.value]", fields[1].Path)
			}
			// The Scan Verifier binds the presentation to this audience.
			if in.Aud != "user" {
				t.Errorf("aud = %q, want user", in.Aud)
			}
			if gotPath != initializePath {
				t.Errorf("path = %q, want %q", gotPath, initializePath)
			}
			// The nonce MUST reach the Scan Verifier. It is the replay binding.
			if gotNonce != "the-nonce" {
				t.Errorf("nonce sent = %q, want the-nonce", gotNonce)
			}
			if txn.PresentationID != tt.expected.PresentationID {
				t.Errorf("PresentationID = %q, want %q", txn.PresentationID, tt.expected.PresentationID)
			}
			if txn.SessionID != tt.expected.SessionID {
				t.Errorf("SessionID = %q, want %q", txn.SessionID, tt.expected.SessionID)
			}
			// qr_code goes to the browser unchanged, the fallback_url included. The
			// sign-in page renders it as "no app?". A re-encode drops every field
			// the Scan Verifier adds later.
			var qr map[string]any
			if err := json.Unmarshal(txn.QRCode, &qr); err != nil {
				t.Fatalf("QRCode is not a JSON object: %v", err)
			}
			if qr["fallback_url"] != "https://di.example/get-the-app" {
				t.Errorf("QRCode dropped fallback_url: %v", qr)
			}
			if qr["url"] != "openid4vp://authorize?x=1" {
				t.Errorf("QRCode dropped url: %v", qr)
			}
		})
	}
}

func TestClient_EnrolUser(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		in       EnrolUser
		wantErr  bool
		wantUUID string
	}{
		{
			name:     "returns the userUuid on a zero stateWord",
			status:   http.StatusOK,
			body:     `{"msg":"SUCCESS!","stateWord":0,"data":{"userUuid":"8223dcabff6243e58ffe88b1ad09b18b"}}`,
			in:       EnrolUser{FullName: "Test User", IDNumber: "950218130004"},
			wantUUID: "8223dcabff6243e58ffe88b1ad09b18b",
		},
		{
			// The one that matters: a refusal inside a success status.
			name:    "a non-zero stateWord is a refusal, not a success",
			status:  http.StatusOK,
			body:    `{"msg":"DUPLICATE","stateWord":1,"data":{}}`,
			in:      EnrolUser{IDNumber: "950218130004"},
			wantErr: true,
		},
		{
			name:    "a missing userUuid is an error",
			status:  http.StatusOK,
			body:    `{"msg":"SUCCESS!","stateWord":0,"data":{}}`,
			in:      EnrolUser{IDNumber: "950218130004"},
			wantErr: true,
		},
		{
			name:    "an empty id number never leaves this deployment",
			in:      EnrolUser{FullName: "Test User"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != enrolUserPath {
					t.Errorf("path = %q, want %q", r.URL.Path, enrolUserPath)
				}
				_ = json.NewDecoder(r.Body).Decode(&got)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			uuid, err := newTestClient(srv).EnrolUser(context.Background(), tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if uuid != tt.wantUUID {
				t.Errorf("uuid = %q, want %q", uuid, tt.wantUUID)
			}
		})
	}
}

// TestClient_EnrolUserBody pins the request shape: the account is keyed by
// identityDocumentInfo.idNumber, and an unverified email must not carry an
// attestation we do not hold.
func TestClient_EnrolUserBody(t *testing.T) {
	tests := []struct {
		name string
		in   EnrolUser
		want func(t *testing.T, body map[string]any)
	}{
		{
			name: "id number and full name",
			in:   EnrolUser{FullName: "Test User", IDNumber: "950218130004"},
			want: func(t *testing.T, body map[string]any) {
				if got := body["userInfo"].(map[string]any)["fullName"]; got != "Test User" {
					t.Errorf("fullName = %v", got)
				}
				doc := body["identityDocumentInfo"].(map[string]any)
				if doc["idNumber"] != "950218130004" || doc["idType"] != enrolIDType || doc["countryId"] != enrolCountryID {
					t.Errorf("identityDocumentInfo = %v", doc)
				}
				if _, ok := body["emailInfo"]; ok {
					t.Error("emailInfo sent for a user with no email")
				}
			},
		},
		{
			name: "an empty full name falls back to the id number",
			in:   EnrolUser{IDNumber: "950218130004"},
			want: func(t *testing.T, body map[string]any) {
				if got := body["userInfo"].(map[string]any)["fullName"]; got != "950218130004" {
					t.Errorf("fullName = %v", got)
				}
			},
		},
		{
			name: "an unverified email carries no verifiedBy or verifiedAt",
			in:   EnrolUser{IDNumber: "950218130004", Email: "a@example.com"},
			want: func(t *testing.T, body map[string]any) {
				e := body["emailInfo"].([]any)[0].(map[string]any)
				if e["emailAddress"] != "a@example.com" || e["isVerified"] != float64(0) {
					t.Errorf("emailInfo = %v", e)
				}
				if _, ok := e["verifiedBy"]; ok {
					t.Error("verifiedBy asserted for an unverified email")
				}
				if _, ok := e["verifiedAt"]; ok {
					t.Error("verifiedAt asserted for an unverified email")
				}
			},
		},
		{
			name: "a verified email carries the attestation in the expected format",
			in: EnrolUser{
				IDNumber: "950218130004", Email: "a@example.com", EmailVerified: true,
				VerifiedAt: time.Date(2025, 5, 26, 10, 0, 0, 0, time.UTC),
			},
			want: func(t *testing.T, body map[string]any) {
				e := body["emailInfo"].([]any)[0].(map[string]any)
				if e["isVerified"] != float64(1) || e["verifiedBy"] != enrolVerifiedBy {
					t.Errorf("emailInfo = %v", e)
				}
				if e["verifiedAt"] != "2025-05-26 10:00:00" {
					t.Errorf("verifiedAt = %v", e["verifiedAt"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&got)
				_, _ = w.Write([]byte(`{"stateWord":0,"data":{"userUuid":"u1"}}`))
			}))
			defer srv.Close()

			if _, err := newTestClient(srv).EnrolUser(context.Background(), tt.in); err != nil {
				t.Fatalf("EnrolUser: %v", err)
			}
			tt.want(t, got)
		})
	}
}
