<p align="center">
  <img src="https://img.shields.io/badge/Architecture-AMD64%20%7C%20ARM64X%20%7C%20CHPE32-blue?style=for-the-badge&logo=windows" alt="Arch">
  <img src="https://img.shields.io/badge/Target-Windows%2011%20(21H2--24H2%2B)-0078D4?style=for-the-badge&logo=windows11" alt="Windows 11">
  <img src="https://img.shields.io/badge/Security-Zero--Disk--Tamper%20(SFC%20Immune)-success?style=for-the-badge" alt="Zero-Tamper">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Language-Go%201.22%2B-00ADD8?style=for-the-badge&logo=go" alt="Language">
</p>

<h1 align="center">⚡ ChronoTrident (时序三叉戟)</h1>

<h3 align="center">The Architecture-Agnostic, Zero-Tamper Runtime Subsystem Resurrector for Windows 11 & Hybrid Silicon</h3>

<p align="center">
  <b>English</b> | <a href="README_zh.md">简体中文</a>
</p>

---

## 🌌 Manifesto & Overview

**ChronoTrident** is an avant-garde, update-proof runtime resurrection engine designed to liberate and re-animate the **Microsoft Trident (MSHTML)** engine and **Internet Explorer 11** on modern Windows operating systems (**Windows 10 SAC / Windows 11 21H2 ~ 24H2+, Canary, Dev, and Beta channels**).

Rather than resorting to fragile, destructive legacy methods—such as overwriting system PE binaries, patching files on disk, or replacing dynamic link libraries (which inevitably trip Windows Resource Protection (WRP), trigger `sfc /scannow` rollback, or collapse during monthly Patch Tuesday cumulative updates)—**ChronoTrident operates entirely at the dynamic execution boundary**.

By leveraging kernel-level **Image File Execution Options (IFEO)** and native low-level debugging telemetry (`DEBUG_ONLY_THIS_PROCESS`), ChronoTrident intercepts `iexplore.exe`, `inetcpl.cpl`, and `rundll32.exe` at the exact millisecond of process creation, seamlessly sublimating the in-memory execution state across **AMD64, ARM64/ARM64EC (ARM64X), and x86/CHPE32** architectures.

```
                    ┌────────────────────────────────────────┐
                    │       User / System Invocation         │
                    │   iexplore.exe / inetcpl.cpl / COM     │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼ (Kernel IFEO Trap)
             ┌─────────────────────────────────────────────────────┐
             │            ⚡ ChronoTrident Hyper-Engine            │
             │           (Non-Destructive Interceptor)             │
             └──────────┬───────────────────────────────┬──────────┘
                        │ Spawns Target in Debug Loop   │
                        ▼                               ▼
       ┌──────────────────────────────────┐   ┌──────────────────────────────────┐
       │   Code Path Neutralization       │   │   Data Path State Overrides      │
       │  • BypassThunkTo64BitFrame (WoA) │   │  • g_InitOnceIsStandaloneIE = 2  │
       │  • OpenInEdge Heuristics NOP     │   │  • g_fIsStandaloneIEDisabled = 0 │
       │  • GeneralPageDialogProc Unhide  │   │  • g_fIsSBEEnabled = 0           │
       └──────────────────────────────────┘   └──────────────────────────────────┘
                        │                               │
                        └───────────────┬───────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       Native Trident Engine Unleashed (100% OK)     │
             │   No Edge BHO • No Redirect Loop • SFC Untouched    │
             └─────────────────────────────────────────────────────┘
```

---

## ⚡ Core Breakthroughs & Capabilities

### 1. Zero-Disk-Modification (SFC & WRP Compliant)
- Never modifies a single byte on the physical disk for system binaries (`ieframe.dll`, `inetcpl.cpl`, `iexplore.exe`).
- Fully immune to **Windows Resource Protection (WRP)**, **System File Checker (SFC)**, and **TrustedInstaller** permission locks.
- Survives all **Windows Cumulative Updates (LCU)** seamlessly without re-patching.

### 2. Universal Hybrid Architecture Support
- **AMD64 (x86_64 Native)**: Intel / AMD 64-bit systems.
- **ARM64 / ARM64EC (Hybrid ARM64X)**: Native execution on Qualcomm Snapdragon X Elite, Microsoft SQ series, and Apple Silicon under Parallels Desktop / VMware Fusion.
- **CHPE32 / x86 WOW64**: Compiled Hybrid Portable Executables on Windows on ARM (WoA).

### 3. Resolution of the WoA "Infinite Thunk Loop"
- In Windows on ARM (WoA), 32-bit `iexplore.exe` invokes `GetNativeSystemInfo` under the x86 WOW64 emulation layer. Due to an internal kernel quirk, the API returns `PROCESSOR_ARCHITECTURE_AMD64` (9) instead of `PROCESSOR_ARCHITECTURE_ARM64` (12).
- This triggers a misrouted 64-bit frame redirection (`ThunkTo64BitFrame`), resulting in a recursive process spawn storm.
- ChronoTrident dynamically locates and mutates the conditional branch `cmp word ptr [esp+0x9c], 0x0c` into `nop; jmp`, terminating the recursive loop.

### 4. Code & Data Dual-Interlock (Bypassing XTA JIT Cache)
- Modern Windows on ARM translates x86 instructions via the **XTA (x86-to-ARM64) JIT Execution Engine** (`xtajitse.dll`), which caches translated blocks.
- ChronoTrident applies a dual-interlock technique: it patches both code entry points and un-JITted runtime synchronization variables in the `.data` section:
  - `g_InitOnceIsStandaloneIEDisabled = 2` (InitOnce Completed)
  - `g_fIsStandaloneIEDisabled = 0` (IE Is Enabled)
  - `g_InitOnceIsSBEEnabled = 2` (SBE Init Completed)
  - `g_fIsSBEEnabled = 0` (Small Browser Experience Disabled)
  - `g_IconsVisible = 1` & `g_ShowIconsCommand = 1`

### 5. Triple-Tier Edge BHO Neutralization
- Disarms the Edge redirector Browser Helper Object (`ie_to_edge_bho.dll`, CLSID `{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}`).
- Enforces enterprise Group Policy lockdowns:
  - `RedirectSitesFromInternetExplorerRedirectMode = 0` (Never redirect)
  - `RedirectSitesFromInternetExplorerPreventBHOInstall = 1` (Suppress re-installation)
- Silences initial setup and telemetry dialogs (`DisableFirstRunCustomize = 1`, `NoBrowserBars = 1`).

### 6. Control Panel Homepage UI Revivification
- Restores the hidden Homepage address inputs and button groups inside `inetcpl.cpl` (`GeneralPageDialogProc`) by overriding the runtime visibility state flags.

---

## 🛠️ Installation & Quick Start

ChronoTrident is packaged as a single, zero-dependency native executable compiled in Go.

### 🚀 One-Click Install (Admin Privileges Required)

Open an elevated Command Prompt or PowerShell (`Run as Administrator`):

```cmd
:: Install IFEO hook for Internet Explorer & Internet Properties (inetcpl.cpl)
chronotrident.exe --install-ifeo --with-cpl
```

*That's it!* ChronoTrident will:
1. Copy itself to `C:\ProgramData\ChronoTrident\chronotrident.exe`.
2. Register the IFEO Debugger keys for `iexplore.exe`, `rundll32.exe`, and `control.exe`.
3. Configure Edge anti-redirection policies.
4. Neutralize the Edge BHO keys.
5. Generate an official Internet Explorer shortcut on the desktop.

### 🧹 Non-Destructive Uninstall

To completely revert the system to its initial state without leaving any residue:

```cmd
chronotrident.exe --uninstall-ifeo
```

---

## 🔍 Advanced Diagnostics & Tooling

### Heuristic Binary Inspection Mode (`--scan`)

Inspect any system binary for live patch targets, Relative Virtual Addresses (RVAs), and architecture signatures without modifying anything:

```cmd
chronotrident.exe --scan C:\Windows\System32\ieframe.dll C:\Windows\System32\inetcpl.cpl
```

Example Output:
```text
[*] Scanning: C:\Windows\System32\ieframe.dll
  [+] StandaloneIE_InitOnceDirect        | VA: 0x1802E8A10 | RVA: 0x02E8A10 | Orig: 488D0D123456 | Patch: C705...
  [+] SBE_InitOnceDirect                 | VA: 0x1802E9B30 | RVA: 0x02E9B30 | Orig: 488D0D654321 | Patch: C705...
  [+] OpenInEdge_ConditionalBranch       | VA: 0x1801C2050 | RVA: 0x01C2050 | Orig: 0F85A0000000 | Patch: 90E9A0000000
```

### Standalone Offline Disk Patcher (`--patch-file`)

For research, PE analysis, or embedded systems where an offline modified binary is specifically required (automatically re-computes `PE CheckSum` via imagehlp):

```cmd
chronotrident.exe --patch-file C:\Test\ieframe.dll C:\Test\ieframe_patched.dll
```

---

## 🔬 First-Principles Deep Dive

<details>
<summary><b>1. Why does <code>iexplore.exe -Embedding</code> work natively?</b></summary>

When `iexplore.exe` is launched without arguments, its startup sequence in `wWinMain` calls `SHOpenFolderWindow` and evaluates user session states to determine whether to execute `ShouldOpenInEdge`.

If modern Edge redirection policies are detected, it invokes `ShellExecuteExW` targeting `msedge.exe` with command line arguments containing the original URL, followed immediately by `ExitProcess(0)`.

However, when passed the `-Embedding` flag (or when instantiated via COM CLSID `{0002DF01-0000-0000-C000-000000000046}`):
1. `wWinMain` identifies the process as an **ActiveX / OLE In-Place Automation Server**.
2. It completely bypasses the interactive browser window creation logic and the `ShouldOpenInEdge` redirector branch.
3. It hands off execution directly to `CIEFrameServer::Register()` and initializes the message loop.
ChronoTrident guarantees that both normal user shell clicks and automated COM requests execute cleanly without invoking Edge.
</details>

<details>
<summary><b>2. The WoA WOW64 Architecture Discrepancy</b></summary>

On Windows on ARM (WoA), 32-bit `iexplore.exe` contains the following architecture validation routine:
```asm
call    ds:__imp__GetNativeSystemInfo
cmp     word ptr [esp+9Ch], 0Ch    ; 0x0C == PROCESSOR_ARCHITECTURE_ARM64
je      short loc_Continue32Bit
call    ThunkTo64BitFrame          ; Delegates to 64-bit iexplore.exe
```
Under x86 WOW64 on Windows 11 WoA, `GetNativeSystemInfo` populates the architecture word with `0x0009` (`PROCESSOR_ARCHITECTURE_AMD64`) due to the unified 64-bit translation harness. The comparison fails, invoking `ThunkTo64BitFrame`. The 64-bit instance inspects its launch arguments and attempts to delegate back down, resulting in an infinite recursion storm.

ChronoTrident replaces the branch instruction `0F 84` (`je`) with `90 E9` (`nop; jmp`), permanently locking execution in the valid frame.
</details>

<details>
<summary><b>3. Why Pattern Matching Survives Windows Updates</b></summary>

Rather than using fragile fixed offsets, ChronoTrident uses **Domain Invariant Signatures**:
1. **Instruction Semantics over Hardcoded Addresses**: Memory patterns match the opcode layout (`48 8D 0D` - `lea rcx, [rip+offset]`) and immediate constants rather than absolute pointers.
2. **Anchor & Back-Walk Engine**: We locate unambiguous strings and GUID literals (e.g. `CLSID_InternetExplorer`, `"Standalone"`), then walk back through the function prologue to resolve the target dispatch table.
3. **PE Section Boundary Verification**: All computed pointers are mathematically verified against `.text` and `.data` Virtual Address ranges extracted dynamically from the PE Header.
</details>

---

## 🏗️ Architecture Matrix

| Platform / Architecture | Code Target | In-Memory Patch Strategy | Verification Status |
| :--- | :--- | :--- | :---: |
| **x86_64 / AMD64** | `ieframe.dll`, `inetcpl.cpl` | IFEO Interception + RIP Relative Opcode Override | ✅ **Verified (Win11 24H2)** |
| **ARM64 / ARM64EC** | `ieframe.dll` (ARM64X) | PC-Relative ADRP/LDR Literal Pool Mutation | ✅ **Verified (Win11 24H2 WoA)** |
| **CHPE32 / x86** | `iexplore.exe` | Thunk Bypass (`90 E9`) + `.data` State Interlock | ✅ **Verified (Win11 24H2 WoA)** |

---

## 💻 Building from Source

ChronoTrident has zero CGo dependencies and compiles natively from macOS, Linux, or Windows using the standard Go compiler:

```bash
# Clone the repository
git clone https://github.com/your-username/ChronoTrident.git
cd ChronoTrident

# Compile for Windows x64 (AMD64)
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/chronotrident_amd64.exe .

# Compile for Windows on ARM (ARM64)
GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o bin/chronotrident_arm64.exe .
```

---

## ⚖️ License & Ethical Declaration

This project is licensed under the [MIT License](LICENSE).

**Disclaimer**: ChronoTrident is intended for backwards compatibility research, digital preservation, industrial SCADA/ERP legacy maintenance, and reverse engineering research. All product names, logos, and brands are property of their respective owners. Microsoft, Windows, and Internet Explorer are trademarks of the Microsoft group of companies.
