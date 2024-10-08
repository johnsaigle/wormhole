package transferverifier

import (
	"testing"
)

// none of the values are necessary for fuzzing
var tv = TransferVerifier{}

func FuzzParseLogMessagePublishedPayload(f *testing.F) {
	// data := make([]byte, 0, MIN_TRANSFER_PAYLOAD_SIZE)

	f.Fuzz(func(t *testing.T, payload []byte) {
		// No point fuzzing when the input is too small
		if len(payload) < MIN_TRANSFER_PAYLOAD_SIZE {
			t.Skip("input too small")
		}
		// NOTE: Very simple test, just makes sure it doesn't panic.
		tv.parseLogMessagePublishedPayload(payload)
		// if err != nil {
		// 	t.Errorf("Error: %q. Payload: %v\n", err, payload)
		// }
		// Check for panics
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("The code panicked: %v", r)
			}
		}()
	})
}
