package provision

import "os"

func interactiveCommand(command []string) []string {
	if len(command) == 1 && command[0] == "/bin/sh" {
		return []string{"/bin/sh", "-i"}
	}
	return command
}

func interactiveEnv() []string {
	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	return []string{
		"HOME=/root",
		"PWD=/",
		"PS1=operax# ",
		"TERM=" + term,
	}
}
