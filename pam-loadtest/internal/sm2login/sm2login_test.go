package sm2login

import "testing"

func TestEncryptPasswordKnownVector(t *testing.T) {
	// Public key observed from a real SGP-PAM /login/crypto-key response.
	const pub = "047AE4D5CEDF92B910CF22CF1E976B8C3F8C081B7CADEAB1839C895D1706969A0BA8351096B26D43C6DDEF56302001C0BFD7B30ED9B25168FB755AE26047FE0CA7"
	out, err := EncryptPassword("emmEMM2023@leagsoft", pub, "C1C3C2")
	if err != nil {
		t.Fatal(err)
	}
	// C1 (64 bytes) + C3 (32 bytes) + C2 (len(password) bytes) in hex.
	if len(out) != 2*(64+32+len("emmEMM2023@leagsoft")) {
		t.Fatalf("ciphertext length %d, want %d", len(out), 2*(64+32+len("emmEMM2023@leagsoft")))
	}
	t.Logf("cipher=%s", out)
}
