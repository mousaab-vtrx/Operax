//go:build !linux

package seccomp

import "fmt"

func Apply(string) error {
	return fmt.Errorf("seccomp backend is only implemented on linux")
}
