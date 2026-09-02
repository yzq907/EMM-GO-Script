package pam

import (
	"strings"
	"testing"
)

func TestRedactRemovesCredentialMaterial(t *testing.T) {
	in := `password=secret Cookie: sid=abc X-Auth-Token=token Authorization: Bearer xyz /sessions/550e8400-e29b-41d4-a716-446655440000/ssh`
	out := Redact(in)
	for _, forbidden := range []string{"secret", "abc", "token", "xyz", "550e8400-e29b-41d4-a716-446655440000"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("redaction retained %q: %s", forbidden, out)
		}
	}
}

func TestRedactRemovesLicenseRedirectQueryToken(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef%3Asgppam%3Aoperator%3A123456"
	in := `{"licenseRedirectUrl":"http://127.0.0.1:7070/login?token=` + secret + `\u0026redirectURL=%2Findex"}`
	out := Redact(in)
	if strings.Contains(out, secret) || strings.Contains(out, "operator") || !strings.Contains(out, "token=[REDACTED]") {
		t.Fatalf("license redirect token was not redacted: %s", out)
	}
}

func TestRedactRemovesLicenseRedirectQueryTokenFormats(t *testing.T) {
	for name, secret := range map[string]string{
		"jwt":              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.signature",
		"base64":           "c2dwLXBh bS1vcGVyYXRvcg==",
		"hex64":            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"unencoded-colons": "0123456789abcdef:sgppam:operator:123456",
	} {
		t.Run(name, func(t *testing.T) {
			in := `redirect=http://127.0.0.1/login?token=` + secret + `\u0026redirectURL=%2Findex`
			out := Redact(in)
			if strings.Contains(out, secret) || strings.Contains(out, "operator") || !strings.Contains(out, "token=[REDACTED]") || !strings.Contains(out, `\u0026redirectURL=`) {
				t.Fatalf("query token format was not safely redacted: %s", out)
			}
		})
	}
}

func TestRedactOnlyTreatsTokenAtQueryParameterBoundaryAsSecret(t *testing.T) {
	in := `label=token=public&token=private&next=ok`
	out := Redact(in)
	if !strings.Contains(out, "label=token=public") || strings.Contains(out, "private") || !strings.Contains(out, "&next=ok") {
		t.Fatalf("query parameter boundaries were not preserved: %s", out)
	}
}
