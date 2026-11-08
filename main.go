package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func printUsage() {
	fmt.Println(`================================================================================
  ChronoTrident (时序三叉戟) - Runtime Subsystem Resurrector for Win11 & Hybrid Silicon
================================================================================
Usage:
  1. Install IFEO Debugger Hook (Survives all Windows Updates automatically):
     chronotrident.exe --install-ifeo [--with-cpl]

  2. Uninstall IFEO Debugger Hook:
     chronotrident.exe --uninstall-ifeo

  3. IFEO Debugger Trigger (Invoked automatically by Windows Kernel):
     chronotrident.exe --ifeo <TargetExePath> [Args...]

  4. Scan PE Binary (ieframe.dll / inetcpl.cpl) for SBE & Homepage Patch Points:
     chronotrident.exe --scan <file1.dll> [file2.cpl ...]

  5. Offline Disk Patch PE Binary (Updates PE CheckSum automatically):
     chronotrident.exe --patch-file <src.dll> [dst.dll]
================================================================================`)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		return
	}

	switch args[0] {
	case "--ifeo":
		os.Exit(RunIFEOInterceptor(args[1:]))

	case "--install-ifeo":
		withCPL := false
		for _, a := range args[1:] {
			if a == "--with-cpl" || a == "-c" {
				withCPL = true
			}
		}
		if err := InstallIFEO(withCPL); err != nil {
			fmt.Fprintf(os.Stderr, "[-] InstallIFEO error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] ChronoTrident IFEO Hook installed! Internet Explorer & Homepage settings are now update-proof.")

	case "--uninstall-ifeo":
		if err := UninstallIFEO(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] UninstallIFEO error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] ChronoTrident IFEO Hook uninstalled.")

	case "--scan":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "[-] Please specify at least one PE file to scan.")
			os.Exit(1)
		}
		exitCode := 0
		for _, p := range args[1:] {
			fmt.Printf("\n[*] Scanning: %s\n", p)
			targets, err := LocateTargets(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  [-] Error: %v\n", err)
				exitCode = 1
			}
			for _, t := range targets {
				fmt.Printf("  [+] %-47s | VA: 0x%09X | RVA: 0x%06X | RawOff: 0x%06X | Orig: %-12s -> Patch: %s\n",
					t.Name, t.VA, t.RVA, t.FileOffset,
					strings.ToUpper(hex.EncodeToString(t.OrigBytes)),
					strings.ToUpper(hex.EncodeToString(t.PatchBytes)),
				)
			}
		}
		os.Exit(exitCode)

	case "--patch-file":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "[-] Usage: --patch-file <src> [dst]")
			os.Exit(1)
		}
		src := args[1]
		dst := src + ".patched"
		if len(args) >= 3 {
			dst = args[2]
		} else {
			ext := filepath.Ext(src)
			base := strings.TrimSuffix(src, ext)
			dst = base + "_patched" + ext
		}
		targets, err := PatchPEFile(src, dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] PatchPEFile failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Successfully patched %s -> %s\n", src, dst)
		for _, t := range targets {
			fmt.Printf("  [*] Patched %-47s @ VA 0x%09X (FileOff 0x%06X): %s -> %s\n",
				t.Name, t.VA, t.FileOffset,
				strings.ToUpper(hex.EncodeToString(t.OrigBytes)),
				strings.ToUpper(hex.EncodeToString(t.PatchBytes)),
			)
		}

	default:
		printUsage()
	}
}
