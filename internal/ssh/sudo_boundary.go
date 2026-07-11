package ssh

import (
	"strings"

	"github.com/LanodonF/coordinate-foister/internal/utils"
)

// newSudoInputBoundary returns a line that does not occur in any framed input.
// Sudo -S may consume the password line, or may leave it untouched when a
// cached ticket/NOPASSWD rule applies. A root-side shell discards complete
// lines through this boundary before it starts the requested payload.
func newSudoInputBoundary(framed ...string) string {
	for {
		marker := "COORDINATE_STDIN_" + utils.GenerateRandomFileName(32)
		collision := false
		for _, value := range framed {
			for _, line := range strings.Split(value, "\n") {
				if line == marker {
					collision = true
					break
				}
			}
			if collision {
				break
			}
		}
		if !collision {
			return marker
		}
	}
}

func discardThroughBoundary(marker string) string {
	return "marker=" + shQuote(marker) + "; found=; " +
		"while IFS= read -r line; do if [ \"$line\" = \"$marker\" ]; then found=1; break; fi; done; " +
		"[ \"$found\" = 1 ] || exit 126; unset line marker found; "
}

func sudoBoundaryCommand(payload, marker string) string {
	return "sudo -S -p '' " + shWrap(discardThroughBoundary(marker)+payload)
}

func sudoBoundaryInput(password, marker, payloadInput string) string {
	return password + "\n" + marker + "\n" + payloadInput
}
