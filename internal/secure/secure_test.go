package secure

import "testing"

func TestPKCEChallengeMatchesRFC7636(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := PKCEChallenge(verifier); got != want {
		t.Fatalf("challenge = %s, want %s", got, want)
	}
}

func TestRandomTokensAreUniqueAndUnpadded(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		token, err := RandomToken(32)
		if err != nil {
			t.Fatal(err)
		}
		if len(token) != 43 || seen[token] {
			t.Fatalf("bad or repeated token %q", token)
		}
		seen[token] = true
	}
}

func TestSHA256Hex(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256Hex("abc"); got != want {
		t.Fatalf("hash = %s", got)
	}
}

func TestEqual(t *testing.T) {
	if !Equal("test-password-1", "test-password-1") || Equal("test-password-1", "test-password-2") || Equal("", "x") || !Equal("", "") {
		t.Fatal("Equal is wrong")
	}
}

func TestIsUUID(t *testing.T) {
	if !IsUUID("3f0c1c9e-6f0d-4c37-8d4e-0d7a9e2b1a11") {
		t.Fatal("a valid uuid was rejected")
	}
	for _, bad := range []string{"", "' OR 1=1 --", "3f0c1c9e6f0d4c378d4e0d7a9e2b1a11", "3f0c1c9e-6f0d-4c37-8d4e-0d7a9e2b1a1", "zzzzzzzz-6f0d-4c37-8d4e-0d7a9e2b1a11"} {
		if IsUUID(bad) {
			t.Errorf("%q was accepted", bad)
		}
	}
}
