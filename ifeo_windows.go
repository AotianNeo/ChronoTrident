//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	DEBUG_PROCESS                    = 0x00000001
	DEBUG_ONLY_THIS_PROCESS          = 0x00000002
	CREATE_UNICODE_ENVIRONMENT       = 0x00000400
	DBG_CONTINUE                     = 0x00010002
	DBG_EXCEPTION_NOT_HANDLED        = 0x80010001
	EXCEPTION_DEBUG_EVENT            = 1
	CREATE_THREAD_DEBUG_EVENT        = 2
	CREATE_PROCESS_DEBUG_EVENT       = 3
	EXIT_THREAD_DEBUG_EVENT          = 4
	EXIT_PROCESS_DEBUG_EVENT         = 5
	LOAD_DLL_DEBUG_EVENT             = 6
	UNLOAD_DLL_DEBUG_EVENT           = 7
	OUTPUT_DEBUG_STRING_EVENT        = 8
	RIP_EVENT                        = 9
	PROCESS_VM_WRITE                 = 0x0020
	PROCESS_VM_OPERATION             = 0x0008
	PROCESS_VM_READ                  = 0x0010
	PROCESS_QUERY_INFORMATION        = 0x0400
)

type DEBUG_EVENT struct {
	DebugEventCode uint32
	ProcessId      uint32
	ThreadId       uint32
	_              uint32 // padding to align Union on 64-bit
	Union          [160]byte
}

type LOAD_DLL_DEBUG_INFO struct {
	File                windows.Handle
	BaseOfDll           uintptr
	DebugInfoFileOffset uint32
	DebugInfoSize       uint32
	ImageName           uintptr
	Unicode             uint16
}

type CREATE_PROCESS_DEBUG_INFO struct {
	File                windows.Handle
	Process             windows.Handle
	Thread              windows.Handle
	BaseOfImage         uintptr
	DebugInfoFileOffset uint32
	DebugInfoSize       uint32
	ThreadLocalBase     uintptr
	StartAddress        uintptr
	ImageName           uintptr
	Unicode             uint16
}

type EXCEPTION_RECORD64 struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      uint64
	ExceptionAddress     uint64
	NumberParameters     uint32
	_                    uint32
	ExceptionInformation [15]uint64
}

type EXCEPTION_DEBUG_INFO64 struct {
	ExceptionRecord EXCEPTION_RECORD64
	FirstChance     uint32
}

var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procWaitForDebugEvent    = modkernel32.NewProc("WaitForDebugEvent")
	procContinueDebugEvent   = modkernel32.NewProc("ContinueDebugEvent")
	procDebugActiveProcessStop = modkernel32.NewProc("DebugActiveProcessStop")
	procDebugSetProcessKillOnExit = modkernel32.NewProc("DebugSetProcessKillOnExit")
	procWriteProcessMemory   = modkernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory    = modkernel32.NewProc("ReadProcessMemory")
	procWow64GetThreadContext = modkernel32.NewProc("Wow64GetThreadContext")
	procGetThreadContext     = modkernel32.NewProc("GetThreadContext")
	procOpenThread           = modkernel32.NewProc("OpenThread")
	procFlushInstructionCache = modkernel32.NewProc("FlushInstructionCache")
	procGetFinalPathNameByHandleW = modkernel32.NewProc("GetFinalPathNameByHandleW")
	procAttachConsole        = modkernel32.NewProc("AttachConsole")
)

func attachParentConsole() {
	r, _, _ := procAttachConsole.Call(uintptr(0xFFFFFFFF))
	if r != 0 {
		hOut, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		if err == nil && hOut != 0 && hOut != windows.InvalidHandle {
			os.Stdout = os.NewFile(uintptr(hOut), "/dev/stdout")
		}
		hErr, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
		if err == nil && hErr != 0 && hErr != windows.InvalidHandle {
			os.Stderr = os.NewFile(uintptr(hErr), "/dev/stderr")
		}
	}
}

func getFilePathFromHandle(hFile windows.Handle) string {
	if hFile == 0 || hFile == windows.InvalidHandle {
		return ""
	}
	buf := make([]uint16, 1024)
	r, _, _ := procGetFinalPathNameByHandleW.Call(
		uintptr(hFile),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if r == 0 || r >= uintptr(len(buf)) {
		return ""
	}
	s := syscall.UTF16ToString(buf[:r])
	return strings.TrimPrefix(s, `\\?\`)
}

func appendLog(format string, args ...any) {
	logDir := `C:\ProgramData\ChronoTrident`
	_ = os.MkdirAll(logDir, 0755)
	f, err := os.OpenFile(filepath.Join(logDir, `ifeo.log`), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\r\n", args...)
}

func patchLoadedModuleInMemory(hProcess windows.Handle, baseAddr uintptr, dllPath string) {
	targets, err := LocateTargets(dllPath)
	if err != nil {
		appendLog("[!] LocateTargets(%s) error: %v", dllPath, err)
		return
	}
	for _, t := range targets {
		destAddr := baseAddr + uintptr(t.RVA)
		var oldProt uint32
		err := windows.VirtualProtectEx(hProcess, destAddr, uintptr(len(t.PatchBytes)), windows.PAGE_EXECUTE_READWRITE, &oldProt)
		if err != nil {
			appendLog("[!] VirtualProtectEx(0x%x) error: %v", destAddr, err)
			continue
		}
		var written uintptr
		r1, _, e1 := procWriteProcessMemory.Call(
			uintptr(hProcess),
			destAddr,
			uintptr(unsafe.Pointer(&t.PatchBytes[0])),
			uintptr(len(t.PatchBytes)),
			uintptr(unsafe.Pointer(&written)),
		)
		procFlushInstructionCache.Call(uintptr(hProcess), destAddr, uintptr(len(t.PatchBytes)))
		var dummy uint32
		_ = windows.VirtualProtectEx(hProcess, destAddr, uintptr(len(t.PatchBytes)), oldProt, &dummy)
		appendLog("[+] Patched %s @ 0x%x (r1=%d, written=%d, err=%v)", t.Name, destAddr, r1, written, e1)
	}
}

// RunIFEOInterceptor launches the target process under a debug loop (bypassing IFEO recursion via DEBUG_ONLY_THIS_PROCESS),
// intercepts LOAD_DLL_DEBUG_EVENT for ieframe.dll and inetcpl.cpl, patches the 3 SBE/Homepage functions in memory,
// and detaches cleanly once the modules are patched.
func RunIFEOInterceptor(targetArgs []string) int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(targetArgs) == 0 {
		return 1
	}
	exePath := targetArgs[0]
	if !strings.ContainsAny(exePath, `\/`) {
		if resolved, err := exec.LookPath(exePath); err == nil {
			exePath = resolved
		} else if sysDir, err := windows.GetSystemDirectory(); err == nil {
			exePath = filepath.Join(sysDir, exePath)
		}
	}
	appendLog("=== RunIFEOInterceptor exePath=%s args: %v ===", exePath, targetArgs)

	// Reconstruct full command line
	var cmdParts []string
	for _, arg := range targetArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
	}
	cmdLine, err := syscall.UTF16PtrFromString(strings.Join(cmdParts, " "))
	if err != nil {
		return 1
	}
	exePtr, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return 1
	}

	isTabCmd := false
	for _, a := range targetArgs[1:] {
		up := strings.ToUpper(a)
		if strings.Contains(up, "SCODEF:") || strings.Contains(up, "CREDAT:") {
			isTabCmd = true
			break
		}
	}

	// On Windows on ARM (WoA), 64-bit Program Files\Internet Explorer\iexplore.exe has no DesktopFrameProcess
	// and thunks to 32-bit Program Files (x86)\Internet Explorer\IEXPLORE.EXE. And in 32-bit IEXPLORE.EXE,
	// GetNativeSystemInfo under x86 WOW64 on ARM64 returns PROCESSOR_ARCHITECTURE_AMD64 (9) instead of ARM64 (12),
	// causing 32-bit IEXPLORE.EXE to thunk back to 64-bit iexplore.exe in an infinite ping-pong loop!
	// Therefore, on ARM64 Windows, if a normal Frame launch of 64-bit iexplore.exe is requested, we directly
	// redirect it to 32-bit Program Files (x86)\Internet Explorer\IEXPLORE.EXE and patch its WOW64 check!
	if runtime.GOARCH == "arm64" && strings.HasSuffix(strings.ToLower(exePath), `\program files\internet explorer\iexplore.exe`) {
		if !isTabCmd {
			x86IE := `C:\Program Files (x86)\Internet Explorer\IEXPLORE.EXE`
			if _, err := os.Stat(x86IE); err == nil {
				exePath = x86IE
				targetArgs[0] = x86IE
				cmdParts[0] = syscall.EscapeArg(x86IE)
				cmdLine, _ = syscall.UTF16PtrFromString(strings.Join(cmdParts, " "))
				exePtr, _ = syscall.UTF16PtrFromString(exePath)
				appendLog("[*] WoA Frame launch redirected directly to 32-bit %s", x86IE)
			}
		}
	}

	// If iexplore.exe does not exist at target path (e.g., removed by Win11 update),
	// synthesize a minimal launcher or load ieframe.dll!DesktopFrameProcess directly!
	if _, statErr := os.Stat(exePath); os.IsNotExist(statErr) && strings.HasSuffix(strings.ToLower(exePath), "iexplore.exe") {
		return runDirectIEHost(targetArgs[1:])
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// Use DEBUG_ONLY_THIS_PROCESS (0x2) so child processes are handled cleanly by their own IFEO Debugger instance
	err = windows.CreateProcess(
		exePtr,
		cmdLine,
		nil,
		nil,
		false,
		DEBUG_ONLY_THIS_PROCESS|CREATE_UNICODE_ENVIRONMENT,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		appendLog("[!] CreateProcess failed: %v", err)
		return 1
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// Ensure child process keeps running when we detach
	procDebugSetProcessKillOnExit.Call(0)

	isInetcplHost := strings.HasSuffix(strings.ToLower(exePath), "rundll32.exe") || strings.HasSuffix(strings.ToLower(exePath), "control.exe")


	procHandles := map[uint32]windows.Handle{
		pi.ProcessId: pi.Process,
	}

	var ev DEBUG_EVENT
	for {
		ret, _, eWait := procWaitForDebugEvent.Call(uintptr(unsafe.Pointer(&ev)), 0xFFFFFFFF)
		if ret == 0 {
			appendLog("  [!] WaitForDebugEvent returned 0 (err=%v)", eWait)
			break
		}

		continueStatus := uint32(DBG_CONTINUE)

		switch ev.DebugEventCode {
		case CREATE_PROCESS_DEBUG_EVENT:
			info := (*CREATE_PROCESS_DEBUG_INFO)(unsafe.Pointer(&ev.Union[0]))
			if info.Process != 0 && ev.ProcessId != pi.ProcessId {
				procHandles[ev.ProcessId] = info.Process
			}
			exeImgPath := getFilePathFromHandle(info.File)
			if info.File != 0 {
				windows.CloseHandle(info.File)
			}
			if strings.HasSuffix(strings.ToLower(exeImgPath), `\iexplore.exe`) && !isTabCmd {
				hProc := procHandles[ev.ProcessId]
				if hProc == 0 {
					hProc = pi.Process
				}
				patchLoadedModuleInMemory(hProc, info.BaseOfImage, exeImgPath)
			}

		case LOAD_DLL_DEBUG_EVENT:
			info := (*LOAD_DLL_DEBUG_INFO)(unsafe.Pointer(&ev.Union[0]))
			dllPath := getFilePathFromHandle(info.File)
			if info.File != 0 {
				windows.CloseHandle(info.File)
			}
			lowPath := strings.ToLower(dllPath)
			if strings.HasSuffix(lowPath, `\ieframe.dll`) || strings.HasSuffix(lowPath, `\inetcpl.cpl`) {
				hProc := procHandles[ev.ProcessId]
				if hProc == 0 {
					hProc = pi.Process
				}
				patchLoadedModuleInMemory(hProc, info.BaseOfDll, dllPath)
				// Continue the debug loop without detaching so we maintain full control and observe all events
				procContinueDebugEvent.Call(uintptr(ev.ProcessId), uintptr(ev.ThreadId), uintptr(DBG_CONTINUE))
				continue
			} else if !isInetcplHost {
				appendLog("  [DLL] %s @ 0x%x", dllPath, info.BaseOfDll)
			}

		case EXCEPTION_DEBUG_EVENT:
			ex := (*EXCEPTION_DEBUG_INFO64)(unsafe.Pointer(&ev.Union[0]))
			// 0x80000003 is STATUS_BREAKPOINT, 0x4000001F is STATUS_WX86_BREAKPOINT (initial loader breakpoints)
			if ex.ExceptionRecord.ExceptionCode != 0x80000003 && ex.ExceptionRecord.ExceptionCode != 0x4000001F {
				appendLog("  [!] Exception PID=%d TID=%d Code=0x%08x Addr=0x%x FirstChance=%d", ev.ProcessId, ev.ThreadId, ex.ExceptionRecord.ExceptionCode, ex.ExceptionRecord.ExceptionAddress, ex.FirstChance)
				continueStatus = uint32(DBG_EXCEPTION_NOT_HANDLED)
			}

		case EXIT_PROCESS_DEBUG_EVENT:
			exitCode := *(*uint32)(unsafe.Pointer(&ev.Union[0]))
			appendLog("  [*] EXIT_PROCESS PID=%d ExitCode=0x%x (%d)", ev.ProcessId, exitCode, exitCode)
			if h, ok := procHandles[ev.ProcessId]; ok && ev.ProcessId != pi.ProcessId && h != 0 {
				windows.CloseHandle(h)
			}
			delete(procHandles, ev.ProcessId)
			procContinueDebugEvent.Call(uintptr(ev.ProcessId), uintptr(ev.ThreadId), uintptr(DBG_CONTINUE))
			if len(procHandles) == 0 {
				appendLog("  [*] Process PID %d exited normally before detach.", pi.ProcessId)
				return 0
			}
			continue
		}

		procContinueDebugEvent.Call(uintptr(ev.ProcessId), uintptr(ev.ThreadId), uintptr(continueStatus))
	}
	return 0
}

// runDirectIEHost loads System32\ieframe.dll in-process, patches it in memory, and calls DesktopFrameProcess directly
// in case C:\Program Files\Internet Explorer\iexplore.exe was deleted by a Windows 11 update.
func runDirectIEHost(args []string) int {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		sysDir = `C:\Windows\System32`
	}
	ieframePath := filepath.Join(sysDir, "ieframe.dll")
	dll, err := windows.LoadLibrary(ieframePath)
	if err != nil {
		return 1
	}
	curProc, _ := windows.GetCurrentProcess()
	patchLoadedModuleInMemory(curProc, uintptr(dll), ieframePath)

	proc, err := windows.GetProcAddress(dll, "DesktopFrameProcess")
	if err != nil {
		return 1
	}
	ret, _, _ := syscall.SyscallN(proc)
	return int(ret)
}

// InstallIFEO copies the current executable to C:\ProgramData\ChronoTrident\chronotrident.exe
// and registers IFEO Debugger keys + Win10 FCK keys + IconsVisible.
func InstallIFEO(alsoHookControlPanel bool) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}
	installDir := `C:\ProgramData\ChronoTrident`
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", installDir, err)
	}
	dstExe := filepath.Join(installDir, "chronotrident.exe")
	if !strings.EqualFold(selfPath, dstExe) {
		raw, err := os.ReadFile(selfPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dstExe, raw, 0755); err != nil {
			return fmt.Errorf("copy to %s: %w", dstExe, err)
		}
	}

	debuggerVal := fmt.Sprintf(`"%s" --ifeo`, dstExe)

	// 1. Register IFEO for iexplore.exe (survives all Windows Cumulative Updates!)
	targets := []string{"iexplore.exe"}
	if alsoHookControlPanel {
		targets = append(targets, "rundll32.exe", "control.exe")
	}

	for _, t := range targets {
		keyPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` + t
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("create IFEO key %s: %w", keyPath, err)
		}
		if err := k.SetStringValue("Debugger", debuggerVal); err != nil {
			k.Close()
			return err
		}
		k.Close()
		fmt.Printf("[+] Registered IFEO Debugger for %-14s -> %s\n", t, debuggerVal)
	}

	// 2. Set FEATURE_BYPASS_SBE_FDD5E421 for Win10 SAC native bypass (64-bit & 32-bit WOW64)
	fckPaths := []string{
		`SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BYPASS_SBE_FDD5E421`,
		`SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BYPASS_SBE_FDD5E421`,
	}
	for _, fp := range fckPaths {
		if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, fp, registry.SET_VALUE); err == nil {
			_ = k.SetDWordValue("*", 1)
			_ = k.SetDWordValue("iexplore.exe", 1)
			_ = k.SetDWordValue("rundll32.exe", 1)
			_ = k.SetDWordValue("control.exe", 1)
			k.Close()
		}
	}
	fmt.Println("[+] Enabled HKLM FEATURE_BYPASS_SBE_FDD5E421 wildcard (* = 1)")

	// 3. Ensure IconsVisible = 1 and ShowIconsCommand is present in both 64-bit and WOW6432Node
	// so IsIEVisible() (0x1015e1d9 / 0x1015e320) returns TRUE in both Frame/Tab and inetcpl.cpl!
	for _, infoKey := range []string{
		`SOFTWARE\Clients\StartMenuInternet\IEXPLORE.EXE\InstallInfo`,
		`SOFTWARE\WOW6432Node\Clients\StartMenuInternet\IEXPLORE.EXE\InstallInfo`,
	} {
		if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, infoKey, registry.SET_VALUE); err == nil {
			_ = k.SetDWordValue("IconsVisible", 1)
			_ = k.SetStringValue("ShowIconsCommand", `"C:\Program Files\Internet Explorer\iexplore.exe"`)
			k.Close()
		}
	}

	// 4. Clear DisableInternetExplorerLaunchViaCOM in case Win11 24H2 policy was set,
	// and disable Edge's ie_to_edge_bho ({1FD49718-1D00-4B19-AF5F-070AF6D5D54C}) so Tab processes stay alive!
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Internet Explorer\Main`, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue("DisableInternetExplorerApp")
		_ = k.DeleteValue("DisableInternetExplorerLaunchViaCOM")
		_ = k.SetDWordValue("DisableFirstRunCustomize", 1)
		k.Close()
	}
	// Disable Edge site redirection & prevent Edge BHO reinstall
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue("RedirectSitesFromInternetExplorerRedirectMode", 0)
		_ = k.SetDWordValue("RedirectSitesFromInternetExplorerPreventBHOInstall", 1)
		k.Close()
	}
	for _, bhoKey := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}`,
	} {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, bhoKey)
	}
	for _, mainKey := range []string{
		`SOFTWARE\Microsoft\Internet Explorer\Main`,
		`SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main`,
	} {
		if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, mainKey, registry.SET_VALUE); err == nil {
			_ = k.SetDWordValue("NoBrowserBars", 1)
			_ = k.SetDWordValue("DisableFirstRunCustomize", 1)
			k.Close()
		}
	}

	// 5. Expose "Enable 64-bit processes for Enhanced Protected Mode*" (inetcpl.cpl,-4755) in Advanced Options
	adv64Path := `SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CRYPTO\PROTECTEDMODE64`
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, adv64Path, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue("Text", "Enable 64-bit processes for Enhanced Protected Mode*")
		_ = k.SetStringValue("PlugUIText", "@C:\\Windows\\System32\\inetcpl.cpl,-4755")
		_ = k.SetStringValue("RegPath", "SOFTWARE\\Microsoft\\Internet Explorer\\Main")
		_ = k.SetStringValue("RegPoliciesPath", "SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main")
		_ = k.SetStringValue("ValueName", "Isolation64Bit")
		_ = k.SetStringValue("Type", "checkbox")
		_ = k.SetDWordValue("CheckedValue", 1)
		_ = k.SetDWordValue("UncheckedValue", 0)
		_ = k.SetDWordValue("DefaultValue", 0)
		_ = k.SetDWordValue("HKeyRoot", 0x80000001) // HKEY_CURRENT_USER
		_ = k.SetDWordValue("IEOnly", 1)
		k.Close()
	}

	// 6. Create Desktop shortcut on Public Desktop so it appears on all users' desktops
	pubDesktop := os.Getenv("PUBLIC")
	if pubDesktop == "" {
		pubDesktop = `C:\Users\Public`
	}
	lnkPath := filepath.Join(pubDesktop, "Desktop", "Internet Explorer.lnk")
	psCmd := fmt.Sprintf(`$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s'); $s.TargetPath='C:\Program Files\Internet Explorer\iexplore.exe'; $s.IconLocation='C:\Program Files\Internet Explorer\iexplore.exe,0'; $s.Description='Internet Explorer'; $s.Save()`, lnkPath)
	_ = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd).Run()

	return nil
}

// UninstallIFEO removes the IFEO Debugger registry entries.
func UninstallIFEO() error {
	for _, t := range []string{"iexplore.exe", "rundll32.exe", "control.exe"} {
		keyPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` + t
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE); err == nil {
			_ = k.DeleteValue("Debugger")
			k.Close()
			fmt.Printf("[-] Removed IFEO Debugger from %s\n", t)
		}
	}
	return nil
}
