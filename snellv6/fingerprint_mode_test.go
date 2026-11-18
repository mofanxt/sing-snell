package snellv6

import "testing"

func TestFingerprintModeCompatibility(t *testing.T) {
	key := []byte("test-mode-compatibility")
	for _, mode := range []Mode{ModeDefault, ModeUnshaped, ModeUnsafeRaw} {
		for _, enabled := range []bool{false, true} {
			wantErr := enabled && mode == ModeUnsafeRaw
			_, clientErr := NewClient(ClientOptions{PSK: key, Mode: mode, Fingerprint: enabled})
			_, serverErr := NewMultiService[int](ServerOptions{PSK: key, Mode: mode, Fingerprint: enabled})
			if (clientErr != nil) != wantErr || (serverErr != nil) != wantErr {
				t.Fatalf("mode %s enabled %v: client %v server %v", mode, enabled, clientErr, serverErr)
			}
		}
	}
}
