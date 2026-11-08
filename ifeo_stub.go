//go:build !windows

package main

import "fmt"

func RunIFEOInterceptor(targetArgs []string) int {
	fmt.Println("[!] IFEO live process debugger mode is only supported on Windows.")
	return 1
}

func InstallIFEO(alsoHookControlPanel bool) error {
	return fmt.Errorf("IFEO registry installation is only supported on Windows")
}

func UninstallIFEO() error {
	return fmt.Errorf("IFEO registry uninstallation is only supported on Windows")
}
