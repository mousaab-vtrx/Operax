//go:build !linux

package kernelrun

func Dispatch([]string) (bool, error) {
	return false, nil
}

func Executable() (string, error) {
	return "", nil
}
