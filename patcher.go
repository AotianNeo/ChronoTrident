package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"unicode/utf16"
)

// PatchTarget represents a located function in the PE binary to be patched.
type PatchTarget struct {
	Name       string
	Arch       string
	VA         uint64
	RVA        uint32
	FileOffset uint32
	OrigBytes  []byte
	PatchBytes []byte
}

var (
	// x86-64: mov eax, 1; ret
	PatchX64MovEax1Ret = []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}
	// x86-64: test r8, r8; jz +6; and dword ptr [r8], 0; mov eax, 1; ret
	PatchX64CheckBrowseInProc = []byte{0x4D, 0x85, 0xC0, 0x74, 0x06, 0x41, 0x83, 0x20, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}
	// x86-64 / x86-32: xor eax, eax; ret
	PatchX86XorEaxRet = []byte{0x33, 0xC0, 0xC3}
	// x86-32 (__stdcall 3 args = 12 bytes): mov eax, 1; ret 0xC
	PatchX86MovEax1Ret0C = []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00}
	// x86-32 (__fastcall 2 reg args + 1 stack arg = ret 4): mov eax, [esp+4]; test eax, eax; jz +3; and dword ptr [eax], 0; xor eax, eax; inc eax; ret 4
	PatchX86CheckBrowseInProc = []byte{0x8B, 0x44, 0x24, 0x04, 0x85, 0xC0, 0x74, 0x03, 0x83, 0x20, 0x00, 0x33, 0xC0, 0x40, 0xC2, 0x04, 0x00}
	// AArch64 (ARM64 / ARM64EC): mov w0, #1; ret (52800020 D65F03C0)
	PatchARM64MovW0_1Ret = []byte{0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}
	// AArch64 (ARM64 / ARM64EC): cbz x2, #8; str wzr, [x2]; mov w0, #1; ret
	PatchARM64CheckBrowseInProc = []byte{0x42, 0x00, 0x00, 0xB4, 0x5F, 0x00, 0x00, 0xB9, 0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}
	// AArch64 (ARM64 / ARM64EC): mov w0, #0; ret (52800000 D65F03C0)
	PatchARM64MovW0_0Ret = []byte{0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}
)

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// LocateTargets scans an ieframe.dll or inetcpl.cpl PE binary across:
//   - AMD64 (0x8664): Win10 SAC / Win11 x64
//   - ARM64 / ARM64X (0xAA64): Windows on ARM (locating BOTH ARM64EC and native ARM64 copies in Hybrid PEs)
//   - I386 (0x014C): 32-bit x86 / SysWOW64 / CHPE32
func LocateTargets(filePath string) ([]PatchTarget, error) {
	rawFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", filePath, err)
	}

	peFile, err := pe.NewFile(bytes.NewReader(rawFile))
	if err != nil {
		return nil, fmt.Errorf("parse PE %s: %w", filePath, err)
	}
	defer peFile.Close()

	var imageBase uint64
	switch hdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase = hdr.ImageBase
	case *pe.OptionalHeader32:
		imageBase = uint64(hdr.ImageBase)
	default:
		return nil, fmt.Errorf("unsupported PE optional header")
	}

	var textSec *pe.Section
	for _, s := range peFile.Sections {
		if s.Name == ".text" {
			textSec = s
			break
		}
	}
	if textSec == nil {
		for _, s := range peFile.Sections {
			if (s.Characteristics & pe.IMAGE_SCN_CNT_CODE) != 0 {
				textSec = s
				break
			}
		}
	}
	if textSec == nil {
		return nil, fmt.Errorf("no .text code section found")
	}

	textData, err := textSec.Data()
	if err != nil {
		return nil, fmt.Errorf("read .text section: %w", err)
	}
	textVA := imageBase + uint64(textSec.VirtualAddress)

	// Find VA of UTF-16LE string "DisableFirstRunCustomize" in any section
	disableFRCStr := encodeUTF16LE("DisableFirstRunCustomize")
	var disableFRCVA uint64
	for _, s := range peFile.Sections {
		sData, err := s.Data()
		if err != nil {
			continue
		}
		if idx := bytes.Index(sData, disableFRCStr); idx != -1 {
			disableFRCVA = imageBase + uint64(s.VirtualAddress) + uint64(idx)
			break
		}
	}

	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return locateTargetsAMD64(filePath, textSec, textData, textVA, disableFRCVA)
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return locateTargetsARM64(filePath, textSec, textData, textVA, disableFRCVA)
	case pe.IMAGE_FILE_MACHINE_I386:
		return locateTargetsI386(filePath, textSec, textData, textVA, disableFRCVA)
	default:
		return nil, fmt.Errorf("unsupported PE machine architecture 0x%04x", peFile.Machine)
	}
}

func locateTargetsAMD64(filePath string, textSec *pe.Section, textData []byte, textVA, disableFRCVA uint64) ([]PatchTarget, error) {
	// Collect all LEA RDX, [RIP + disp32] (48 8D 15 xx xx xx xx) targets inside .text
	leaTargetSet := make(map[int]struct{})
	for i := 0; i <= len(textData)-7; i++ {
		if textData[i] == 0x48 && textData[i+1] == 0x8D && textData[i+2] == 0x15 {
			disp := int32(binary.LittleEndian.Uint32(textData[i+3 : i+7]))
			destOff := i + 7 + int(disp)
			if destOff >= 0 && destOff < len(textData) {
				leaTargetSet[destOff] = struct{}{}
			}
		}
	}
	leaTargets := make([]int, 0, len(leaTargetSet))
	for off := range leaTargetSet {
		leaTargets = append(leaTargets, off)
	}
	sort.Ints(leaTargets)

	var results []PatchTarget

	// 1. SBEUtil::InitOnceIsSBEEnabled
	if disableFRCVA != 0 {
		for i := 0; i <= len(textData)-7; i++ {
			if textData[i] == 0x4C && textData[i+1] == 0x8D && textData[i+2] == 0x05 {
				disp := int32(binary.LittleEndian.Uint32(textData[i+3 : i+7]))
				targetVA := uint64(int64(textVA) + int64(i) + 7 + int64(disp))
				if targetVA == disableFRCVA {
					idx := sort.SearchInts(leaTargets, i+1) - 1
					if idx >= 0 {
						cbOff := leaTargets[idx]
						if i-cbOff < 0x100 {
							results = append(results, PatchTarget{
								Name:       "SBEUtil::InitOnceIsSBEEnabled",
								Arch:       "AMD64",
								VA:         textVA + uint64(cbOff),
								RVA:        textSec.VirtualAddress + uint32(cbOff),
								FileOffset: textSec.Offset + uint32(cbOff),
								OrigBytes:  append([]byte(nil), textData[cbOff:cbOff+len(PatchX64MovEax1Ret)]...),
								PatchBytes: PatchX64MovEax1Ret,
							})
							break
						}
					}
				}
			}
		}
	}

	// 2. LaunchEdgeUtil::InitOnceIsStandaloneIEDisabled
	patConfig0C := []byte{0xB9, 0x0C, 0x00, 0x00, 0x10}
	for _, cbOff := range leaTargets {
		endOff := cbOff + 0x70
		if endOff > len(textData) {
			endOff = len(textData)
		}
		if bytes.Contains(textData[cbOff:endOff], patConfig0C) {
			results = append(results, PatchTarget{
				Name:       "LaunchEdgeUtil::InitOnceIsStandaloneIEDisabled",
				Arch:       "AMD64",
				VA:         textVA + uint64(cbOff),
				RVA:        textSec.VirtualAddress + uint32(cbOff),
				FileOffset: textSec.Offset + uint32(cbOff),
				OrigBytes:  append([]byte(nil), textData[cbOff:cbOff+len(PatchX64MovEax1Ret)]...),
				PatchBytes: PatchX64MovEax1Ret,
			})
			break
		}
	}

	// 3. HideIEOnlySettings
	prologue := []byte{0x40, 0x53, 0x48, 0x83, 0xEC, 0x20}
	tailSig := []byte{0x85, 0xC0, 0x0F, 0x94, 0xC3}
	for _, headSig := range [][]byte{
		{0x85, 0xC0, 0x75, 0x0A, 0xE8},
		{0x85, 0xC9, 0x75, 0x0A, 0xE8},
	} {
		searchPos := 0
		foundHide := false
		for {
			idx := bytes.Index(textData[searchPos:], headSig)
			if idx == -1 {
				break
			}
			absIdx := searchPos + idx
			if absIdx+14 <= len(textData) && bytes.Equal(textData[absIdx+9:absIdx+14], tailSig) {
				startWindow := absIdx - 0x60
				if startWindow < 0 {
					startWindow = 0
				}
				if p := bytes.LastIndex(textData[startWindow:absIdx], prologue); p != -1 {
					fnOff := startWindow + p
					results = append(results, PatchTarget{
						Name:       "HideIEOnlySettings",
						Arch:       "AMD64",
						VA:         textVA + uint64(fnOff),
						RVA:        textSec.VirtualAddress + uint32(fnOff),
						FileOffset: textSec.Offset + uint32(fnOff),
						OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86XorEaxRet)]...),
						PatchBytes: PatchX86XorEaxRet,
					})
					foundHide = true
					break
				}
			}
			searchPos = absIdx + 1
		}
		if foundHide {
			break
		}
	}

	// 4. ShouldOpenInEdge(ushort const *) -> bool (xor eax, eax; ret)
	// Prevents ResolveInitialBrowserLocation from redirecting default homepage / empty command-line launches to Edge.
	for _, pat := range []struct {
		head []byte
		tail []byte
	}{
		{[]byte{0xBF, 0x56, 0x00, 0x00, 0x10}, []byte{0x8D, 0x4F, 0xB6}},
		{[]byte{0xB9, 0x0C, 0x00, 0x00, 0x10}, []byte{0xB9, 0x56, 0x00, 0x00, 0x10}},
	} {
		foundShould := false
		for pos := 0; ; {
			idx := bytes.Index(textData[pos:], pat.head)
			if idx == -1 {
				break
			}
			absIdx := pos + idx
			endWin := absIdx + 0x30
			if endWin > len(textData) {
				endWin = len(textData)
			}
			if bytes.Contains(textData[absIdx:endWin], pat.tail) {
				for back := absIdx; back > 0 && absIdx-back <= 0x80; back-- {
					if textData[back-1] == 0xCC && textData[back] != 0xCC {
						results = append(results, PatchTarget{
							Name:       "ShouldOpenInEdge",
							Arch:       "AMD64",
							VA:         textVA + uint64(back),
							RVA:        textSec.VirtualAddress + uint32(back),
							FileOffset: textSec.Offset + uint32(back),
							OrigBytes:  append([]byte(nil), textData[back:back+len(PatchX86XorEaxRet)]...),
							PatchBytes: PatchX86XorEaxRet,
						})
						foundShould = true
						break
					}
				}
			}
			if foundShould {
				break
			}
			pos = absIdx + 1
		}
		if foundShould {
			break
		}
	}

	// 5. TryIEShellDelegation(pidl, flags) -> int (xor eax, eax; ret)
	// Prevents SHOpenFolderWindow from delegating URL PIDLs (via CheckBrowseInProcess -> urlmon!ord_495 -> ShellExecuteExW) to Edge.
	patTryStack := []byte{0xB8, 0xF0, 0x10, 0x00, 0x00}
	patTryCfg := []byte{0xB9, 0x03, 0x00, 0x00, 0x20}
	patTryPrologue := []byte{0x48, 0x89, 0x5C, 0x24, 0x18}
	for pos := 0; ; {
		idx := bytes.Index(textData[pos:], patTryStack)
		if idx == -1 {
			break
		}
		absIdx := pos + idx
		endWin := absIdx + 0x50
		if endWin > len(textData) {
			endWin = len(textData)
		}
		if bytes.Contains(textData[absIdx:endWin], patTryCfg) {
			startWin := absIdx - 0x30
			if startWin < 0 {
				startWin = 0
			}
			if p := bytes.LastIndex(textData[startWin:absIdx], patTryPrologue); p != -1 {
				fnOff := startWin + p
				results = append(results, PatchTarget{
					Name:       "TryIEShellDelegation",
					Arch:       "AMD64",
					VA:         textVA + uint64(fnOff),
					RVA:        textSec.VirtualAddress + uint32(fnOff),
					FileOffset: textSec.Offset + uint32(fnOff),
					OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86XorEaxRet)]...),
					PatchBytes: PatchX86XorEaxRet,
				})
				break
			}
		}
		pos = absIdx + 1
	}

	// 6. CheckBrowseInProcess(pidl, flags, outFlags) -> int (1)
	// Prevents AddTabInternal / OpenPrimaryHomePage / TryIEShellDelegation from calling urlmon!ord_495
	// (which invokes Windows.System.Launcher.dll / ShellExecuteExW to redirect http/https/about:blank to Edge).
	patChkBrowseX64 := []byte{0x44, 0x8D, 0x77, 0x03, 0x44, 0x0F, 0x45, 0xF2, 0x41, 0xF6, 0xC6, 0x01}
	patChkPrologueX64 := []byte{0x48, 0x89, 0x5C, 0x24, 0x10}
	if idx := bytes.Index(textData, patChkBrowseX64); idx != -1 {
		startWin := idx - 0x50
		if startWin < 0 {
			startWin = 0
		}
		if p := bytes.LastIndex(textData[startWin:idx], patChkPrologueX64); p != -1 {
			fnOff := startWin + p
			results = append(results, PatchTarget{
				Name:       "CheckBrowseInProcess",
				Arch:       "AMD64",
				VA:         textVA + uint64(fnOff),
				RVA:        textSec.VirtualAddress + uint32(fnOff),
				FileOffset: textSec.Offset + uint32(fnOff),
				OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX64CheckBrowseInProc)]...),
				PatchBytes: PatchX64CheckBrowseInProc,
			})
		}
	}

	if len(results) < 1 {
		return results, fmt.Errorf("expected at least 1 AMD64 patch target in %s, but found %d", filePath, len(results))
	}
	return results, nil
}

// locateTargetsARM64 locates all targets in an ARM64 or ARM64X (Hybrid ARM64EC + native ARM64) PE binary.
// In ARM64X binaries (such as Windows 11 WoA System32\ieframe.dll and inetcpl.cpl), both the ARM64EC
// and native ARM64 copies of every function are compiled into AArch64 machine code inside .text.
func locateTargetsARM64(filePath string, textSec *pe.Section, textData []byte, textVA, disableFRCVA uint64) ([]PatchTarget, error) {
	// Collect all AArch64 `ADRP Rd, page; ADD X1, Rd, #imm12` callback addresses in .text
	x1Targets := make(map[int]struct{})
	for off := 0; off <= len(textData)-8; off += 4 {
		ins1 := binary.LittleEndian.Uint32(textData[off : off+4])
		if (ins1 & 0x9F000000) == 0x90000000 {
			rd := ins1 & 0x1F
			immlo := int64((ins1 >> 29) & 0x3)
			immhi := int64((ins1 >> 5) & 0x7FFFF)
			imm := (immhi << 2) | immlo
			if (imm & (1 << 20)) != 0 {
				imm -= (1 << 21)
			}
			page := (int64(textVA+uint64(off)) & ^int64(0xFFF)) + (imm << 12)
			for _, step := range []int{4, 8} {
				if off+step+4 > len(textData) {
					break
				}
				ins2 := binary.LittleEndian.Uint32(textData[off+step : off+step+4])
				// ADD X1, Rd, #imm12 (sh=0)
				if (ins2 & 0xFFC003FF) == (0x91000001 | (rd << 5)) {
					imm12 := int64((ins2 >> 10) & 0xFFF)
					targetVA := uint64(page + imm12)
					if targetVA >= textVA && targetVA < textVA+uint64(len(textData)) && (targetVA&0xF) == 0 {
						x1Targets[int(targetVA-textVA)] = struct{}{}
					}
				}
			}
		}
	}

	var results []PatchTarget
	tagArch := func(idx int) string {
		if idx == 0 {
			return "ARM64EC"
		}
		return "ARM64"
	}

	// 1. Locate SBEUtil::InitOnceIsSBEEnabled (both ARM64EC and native ARM64 copies)
	// Identified by `ADRP Rd, page; ADD X2, Rd, #imm12` pointing to L"DisableFirstRunCustomize"
	if disableFRCVA != 0 {
		sbeCount := 0
		for off := 0; off <= len(textData)-8; off += 4 {
			ins1 := binary.LittleEndian.Uint32(textData[off : off+4])
			if (ins1 & 0x9F000000) == 0x90000000 {
				rd := ins1 & 0x1F
				immlo := int64((ins1 >> 29) & 0x3)
				immhi := int64((ins1 >> 5) & 0x7FFFF)
				imm := (immhi << 2) | immlo
				if (imm & (1 << 20)) != 0 {
					imm -= (1 << 21)
				}
				page := (int64(textVA+uint64(off)) & ^int64(0xFFF)) + (imm << 12)
				ins2 := binary.LittleEndian.Uint32(textData[off+4 : off+8])
				// ADD X2, Rd, #imm12 (sh=0)
				if (ins2 & 0xFFC003FF) == (0x91000002 | (rd << 5)) {
					imm12 := int64((ins2 >> 10) & 0xFFF)
					if uint64(page+imm12) == disableFRCVA {
						// Walk backwards up to 0x80 bytes to find `pacibsp` (0xD503237F) entry point in x1Targets
						for back := off; back >= 0 && off-back <= 0x80; back -= 4 {
							if binary.LittleEndian.Uint32(textData[back:back+4]) == 0xD503237F {
								if _, ok := x1Targets[back]; ok {
									archTag := tagArch(sbeCount)
									results = append(results, PatchTarget{
										Name:       fmt.Sprintf("SBEUtil::InitOnceIsSBEEnabled [%s]", archTag),
										Arch:       archTag,
										VA:         textVA + uint64(back),
										RVA:        textSec.VirtualAddress + uint32(back),
										FileOffset: textSec.Offset + uint32(back),
										OrigBytes:  append([]byte(nil), textData[back:back+len(PatchARM64MovW0_1Ret)]...),
										PatchBytes: PatchARM64MovW0_1Ret,
									})
									sbeCount++
								}
								break
							}
						}
					}
				}
			}
		}
	}

	// 2. Locate LaunchEdgeUtil::InitOnceIsStandaloneIEDisabled (both ARM64EC and native ARM64 copies)
	// Identified by adjacent literal pool `0C 00 00 10 26 00 00 10` immediately following the function epilogue
	litPoolSig := []byte{0x0C, 0x00, 0x00, 0x10, 0x26, 0x00, 0x00, 0x10}
	standaloneCount := 0
	searchPos := 0
	for {
		idx := bytes.Index(textData[searchPos:], litPoolSig)
		if idx == -1 {
			break
		}
		absIdx := (searchPos + idx) & ^3
		for back := absIdx; back >= 0 && absIdx-back <= 0x100; back -= 4 {
			if binary.LittleEndian.Uint32(textData[back:back+4]) == 0xD503237F {
				if _, ok := x1Targets[back]; ok {
					archTag := tagArch(standaloneCount)
					results = append(results, PatchTarget{
						Name:       fmt.Sprintf("LaunchEdgeUtil::InitOnceIsStandaloneIEDisabled [%s]", archTag),
						Arch:       archTag,
						VA:         textVA + uint64(back),
						RVA:        textSec.VirtualAddress + uint32(back),
						FileOffset: textSec.Offset + uint32(back),
						OrigBytes:  append([]byte(nil), textData[back:back+len(PatchARM64MovW0_1Ret)]...),
						PatchBytes: PatchARM64MovW0_1Ret,
					})
					standaloneCount++
				}
				break
			}
		}
		searchPos = absIdx + 4
	}

	// 3. Locate HideIEOnlySettings (both ARM64EC and native ARM64 copies)
	// Identified by `cmp w0, #0; cset w19, eq` (`1F 00 00 71 F3 17 9F 1A`) followed within 0x60 bytes by `cset w19, ne` (`F3 07 9F 1A`)
	hideMidSig := []byte{0x1F, 0x00, 0x00, 0x71, 0xF3, 0x17, 0x9F, 0x1A}
	hideTailSig := []byte{0xF3, 0x07, 0x9F, 0x1A}
	hideCount := 0
	searchPos = 0
	for {
		idx := bytes.Index(textData[searchPos:], hideMidSig)
		if idx == -1 {
			break
		}
		absIdx := (searchPos + idx) & ^3
		endWin := absIdx + 0x60
		if endWin > len(textData) {
			endWin = len(textData)
		}
		if bytes.Contains(textData[absIdx:endWin], hideTailSig) {
			for back := absIdx; back >= 0 && absIdx-back <= 0x60; back -= 4 {
				if binary.LittleEndian.Uint32(textData[back:back+4]) == 0xD503237F {
					archTag := tagArch(hideCount)
					results = append(results, PatchTarget{
						Name:       fmt.Sprintf("HideIEOnlySettings [%s]", archTag),
						Arch:       archTag,
						VA:         textVA + uint64(back),
						RVA:        textSec.VirtualAddress + uint32(back),
						FileOffset: textSec.Offset + uint32(back),
						OrigBytes:  append([]byte(nil), textData[back:back+len(PatchARM64MovW0_0Ret)]...),
						PatchBytes: PatchARM64MovW0_0Ret,
					})
					hideCount++
					break
				}
			}
		}
		searchPos = absIdx + 4
	}

	// 4. Locate ShouldOpenInEdge (both ARM64EC and native ARM64 copies)
	// Identified by adjacent literal pool `0C 00 00 10 56 00 00 10` immediately following the function epilogue
	shouldEdgePoolSig := []byte{0x0C, 0x00, 0x00, 0x10, 0x56, 0x00, 0x00, 0x10}
	shouldEdgeCount := 0
	searchPos = 0
	for {
		idx := bytes.Index(textData[searchPos:], shouldEdgePoolSig)
		if idx == -1 {
			break
		}
		absIdx := (searchPos + idx) & ^3
		for back := absIdx; back >= 0 && absIdx-back <= 0x200; back -= 4 {
			if binary.LittleEndian.Uint32(textData[back:back+4]) == 0xD503237F {
				archTag := tagArch(shouldEdgeCount)
				results = append(results, PatchTarget{
					Name:       fmt.Sprintf("ShouldOpenInEdge [%s]", archTag),
					Arch:       archTag,
					VA:         textVA + uint64(back),
					RVA:        textSec.VirtualAddress + uint32(back),
					FileOffset: textSec.Offset + uint32(back),
					OrigBytes:  append([]byte(nil), textData[back:back+len(PatchARM64MovW0_0Ret)]...),
					PatchBytes: PatchARM64MovW0_0Ret,
				})
				shouldEdgeCount++
				break
			}
		}
		searchPos = absIdx + 4
	}

	// 5. Locate TryIEShellDelegation (both ARM64EC and native ARM64 copies)
	// Identified by adjacent literal pool `03 00 00 20 04 00 00 20` and `mov x15, #0x10a` (`4F 21 80 D2`) in prologue
	tryDelPoolSig := []byte{0x03, 0x00, 0x00, 0x20, 0x04, 0x00, 0x00, 0x20}
	tryDelStackSig := []byte{0x4F, 0x21, 0x80, 0xD2}
	tryDelCount := 0
	searchPos = 0
	for {
		idx := bytes.Index(textData[searchPos:], tryDelPoolSig)
		if idx == -1 {
			break
		}
		absIdx := (searchPos + idx) & ^3
		for back := absIdx; back >= 0 && absIdx-back <= 0x200; back -= 4 {
			if binary.LittleEndian.Uint32(textData[back:back+4]) == 0xD503237F {
				if bytes.Contains(textData[back:absIdx], tryDelStackSig) {
					archTag := tagArch(tryDelCount)
					results = append(results, PatchTarget{
						Name:       fmt.Sprintf("TryIEShellDelegation [%s]", archTag),
						Arch:       archTag,
						VA:         textVA + uint64(back),
						RVA:        textSec.VirtualAddress + uint32(back),
						FileOffset: textSec.Offset + uint32(back),
						OrigBytes:  append([]byte(nil), textData[back:back+len(PatchARM64MovW0_0Ret)]...),
						PatchBytes: PatchARM64MovW0_0Ret,
					})
					tryDelCount++
				}
				break
			}
		}
		searchPos = absIdx + 4
	}

	// 6. Locate CheckBrowseInProcess (both ARM64EC and native ARM64 copies)
	// Identified by `sub sp, sp, x15, lsl #4; cmp w1, #0; mov w8, #3` (`FF 73 2F CB 3F 00 00 71 68 00 80 52`)
	chkBrowseARM64Sig := []byte{0xFF, 0x73, 0x2F, 0xCB, 0x3F, 0x00, 0x00, 0x71, 0x68, 0x00, 0x80, 0x52}
	chkBrowseCount := 0
	searchPos = 0
	for {
		idx := bytes.Index(textData[searchPos:], chkBrowseARM64Sig)
		if idx == -1 {
			break
		}
		absIdx := (searchPos + idx) & ^3
		for back := absIdx; back >= 0 && absIdx-back <= 0x60; back -= 4 {
			if binary.LittleEndian.Uint32(textData[back:back+4]) == 0xD503237F {
				archTag := tagArch(chkBrowseCount)
				results = append(results, PatchTarget{
					Name:       fmt.Sprintf("CheckBrowseInProcess [%s]", archTag),
					Arch:       archTag,
					VA:         textVA + uint64(back),
					RVA:        textSec.VirtualAddress + uint32(back),
					FileOffset: textSec.Offset + uint32(back),
					OrigBytes:  append([]byte(nil), textData[back:back+len(PatchARM64CheckBrowseInProc)]...),
					PatchBytes: PatchARM64CheckBrowseInProc,
				})
				chkBrowseCount++
				break
			}
		}
		searchPos = absIdx + 4
	}

	if len(results) < 2 {
		return results, fmt.Errorf("expected at least 2 ARM64/ARM64EC patch targets in %s, but found %d", filePath, len(results))
	}
	return results, nil
}

// locateTargetsI386 locates the 3 patch targets in 32-bit x86 (SysWOW64 / CHPE32) ieframe.dll and inetcpl.cpl.
func locateTargetsI386(filePath string, textSec *pe.Section, textData []byte, textVA, disableFRCVA uint64) ([]PatchTarget, error) {
	var results []PatchTarget
	prologueStd := []byte{0x8B, 0xFF, 0x55, 0x8B, 0xEC} // mov edi, edi; push ebp; mov ebp, esp

	// 1. SBEUtil::InitOnceIsSBEEnabled (__stdcall 3 args -> ret 0xC)
	if disableFRCVA != 0 {
		pushDFRC := make([]byte, 5)
		pushDFRC[0] = 0x68
		binary.LittleEndian.PutUint32(pushDFRC[1:5], uint32(disableFRCVA))
		if idx := bytes.Index(textData, pushDFRC); idx != -1 {
			startWin := idx - 0x50
			if startWin < 0 {
				startWin = 0
			}
			if p := bytes.LastIndex(textData[startWin:idx], prologueStd); p != -1 {
				fnOff := startWin + p
				results = append(results, PatchTarget{
					Name:       "SBEUtil::InitOnceIsSBEEnabled [x86]",
					Arch:       "I386",
					VA:         textVA + uint64(fnOff),
					RVA:        textSec.VirtualAddress + uint32(fnOff),
					FileOffset: textSec.Offset + uint32(fnOff),
					OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86MovEax1Ret0C)]...),
					PatchBytes: PatchX86MovEax1Ret0C,
				})
				// Also locate the InitOnce structure & cached bool in SBEUtil::IsSBEEnabled (`68 <fnVA> 68 <initOnceVA> FF 15 <imp> A0 <boolVA>`)
				pushCb := make([]byte, 5)
				pushCb[0] = 0x68
				binary.LittleEndian.PutUint32(pushCb[1:5], uint32(textVA+uint64(fnOff)))
				if wIdx := bytes.Index(textData[fnOff:minInt(len(textData), fnOff+0x100)], pushCb); wIdx != -1 {
					absW := fnOff + wIdx
					if absW+17 <= len(textData) && textData[absW+5] == 0x68 && textData[absW+16] == 0xA0 {
						initOnceVA := binary.LittleEndian.Uint32(textData[absW+6 : absW+10])
						boolVA := binary.LittleEndian.Uint32(textData[absW+17 : absW+21])
						imgBase32 := uint32(textVA) - textSec.VirtualAddress
						results = append(results,
							PatchTarget{
								Name:       "SBEUtil::g_InitOnceIsSBEEnabled [data]",
								Arch:       "I386",
								VA:         uint64(initOnceVA),
								RVA:        initOnceVA - imgBase32,
								FileOffset: 0,
								OrigBytes:  []byte{0, 0, 0, 0},
								PatchBytes: []byte{2, 0, 0, 0}, // RTL_RUN_ONCE_CHECK_ONLY = 2 (completed)
							},
							PatchTarget{
								Name:       "SBEUtil::g_fIsSBEEnabled [data]",
								Arch:       "I386",
								VA:         uint64(boolVA),
								RVA:        boolVA - imgBase32,
								FileOffset: 0,
								OrigBytes:  []byte{0},
								PatchBytes: []byte{0},
							},
						)
					}
				}
			}
		}
	}

	// 2. LaunchEdgeUtil::InitOnceIsStandaloneIEDisabled (__stdcall 3 args -> ret 0xC)
	patPush0C := []byte{0x68, 0x0C, 0x00, 0x00, 0x10}
	patPush26 := []byte{0x68, 0x26, 0x00, 0x00, 0x10}
	patRet0C := []byte{0xC2, 0x0C, 0x00}
	searchPos := 0
	for {
		idx := bytes.Index(textData[searchPos:], patPush0C)
		if idx == -1 {
			break
		}
		absIdx := searchPos + idx
		endWin := absIdx + 0x50
		if endWin > len(textData) {
			endWin = len(textData)
		}
		if bytes.Contains(textData[absIdx:endWin], patPush26) && bytes.Contains(textData[absIdx:endWin], patRet0C) {
			startWin := absIdx - 0x40
			if startWin < 0 {
				startWin = 0
			}
			if p := bytes.LastIndex(textData[startWin:absIdx], prologueStd); p != -1 {
				fnOff := startWin + p
				results = append(results, PatchTarget{
					Name:       "LaunchEdgeUtil::InitOnceIsStandaloneIEDisabled [x86]",
					Arch:       "I386",
					VA:         textVA + uint64(fnOff),
					RVA:        textSec.VirtualAddress + uint32(fnOff),
					FileOffset: textSec.Offset + uint32(fnOff),
					OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86MovEax1Ret0C)]...),
					PatchBytes: PatchX86MovEax1Ret0C,
				})
				// Also locate the InitOnce structure & cached bool in LaunchEdgeUtil::IsStandaloneIEDisabled (`68 <fnVA> 68 <initOnceVA> FF 15 <imp> A0 <boolVA>`)
				pushCb := make([]byte, 5)
				pushCb[0] = 0x68
				binary.LittleEndian.PutUint32(pushCb[1:5], uint32(textVA+uint64(fnOff)))
				if wIdx := bytes.Index(textData[fnOff:minInt(len(textData), fnOff+0x120)], pushCb); wIdx != -1 {
					absW := fnOff + wIdx
					if absW+21 <= len(textData) && textData[absW+5] == 0x68 && textData[absW+16] == 0xA0 {
						initOnceVA := binary.LittleEndian.Uint32(textData[absW+6 : absW+10])
						boolVA := binary.LittleEndian.Uint32(textData[absW+17 : absW+21])
						imgBase32 := uint32(textVA) - textSec.VirtualAddress
						results = append(results,
							PatchTarget{
								Name:       "LaunchEdgeUtil::g_InitOnceIsStandaloneIEDisabled [data]",
								Arch:       "I386",
								VA:         uint64(initOnceVA),
								RVA:        initOnceVA - imgBase32,
								FileOffset: 0,
								OrigBytes:  []byte{0, 0, 0, 0},
								PatchBytes: []byte{2, 0, 0, 0}, // RTL_RUN_ONCE_CHECK_ONLY = 2 (completed)
							},
							PatchTarget{
								Name:       "LaunchEdgeUtil::g_fIsStandaloneIEDisabled [data]",
								Arch:       "I386",
								VA:         uint64(boolVA),
								RVA:        boolVA - imgBase32,
								FileOffset: 0,
								OrigBytes:  []byte{0},
								PatchBytes: []byte{0},
							},
						)
					}
				}
				break
			}
		}
		searchPos = absIdx + 1
	}

	// 3. _HideIEOnlySettings@0 (__stdcall 0 args -> ret)
	patHideX86 := []byte{0xF7, 0xD8, 0x1B, 0xDB, 0x43, 0xFF, 0x15} // neg eax; sbb ebx, ebx; inc ebx; call dword ptr [...]
	prologueEbx := []byte{0x8B, 0xFF, 0x53}                         // mov edi, edi; push ebx
	if idx := bytes.Index(textData, patHideX86); idx != -1 {
		startWin := idx - 0x30
		if startWin < 0 {
			startWin = 0
		}
		if p := bytes.LastIndex(textData[startWin:idx], prologueEbx); p != -1 {
			fnOff := startWin + p
			results = append(results, PatchTarget{
				Name:       "_HideIEOnlySettings@0 [x86]",
				Arch:       "I386",
				VA:         textVA + uint64(fnOff),
				RVA:        textSec.VirtualAddress + uint32(fnOff),
				FileOffset: textSec.Offset + uint32(fnOff),
				OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86XorEaxRet)]...),
				PatchBytes: PatchX86XorEaxRet,
			})
		}
	}

	// 4. For 32-bit iexplore.exe on Windows on ARM:
	// GetNativeSystemInfo under x86 WOW64 on ARM64 returns PROCESSOR_ARCHITECTURE_AMD64 (9) instead of ARM64 (12),
	// causing `cmp word ptr [esp+0x9c], 0x0c; je DesktopFrameProcess` (`66 83 BC 24 9C 00 00 00 0C 0F 84`)
	// to fall through into ThunkTo64BitFrame -> infinite 32<->64 ping-pong loop!
	// Patch the `0F 84` (JE rel32) to `90 E9` (NOP; JMP rel32) so 32-bit IEXPLORE.EXE always runs DesktopFrameProcess.
	patWoAThunk := []byte{0x66, 0x83, 0xBC, 0x24, 0x9C, 0x00, 0x00, 0x00, 0x0C, 0x0F, 0x84}
	if idx := bytes.Index(textData, patWoAThunk); idx != -1 {
		jeOff := idx + 9
		results = append(results, PatchTarget{
			Name:       "wWinMain::BypassThunkTo64BitFrame [x86]",
			Arch:       "I386",
			VA:         textVA + uint64(jeOff),
			RVA:        textSec.VirtualAddress + uint32(jeOff),
			FileOffset: textSec.Offset + uint32(jeOff),
			OrigBytes:  append([]byte(nil), textData[jeOff:jeOff+2]...),
			PatchBytes: []byte{0x90, 0xE9},
		})
		return results, nil
	}

	// 5. ShouldOpenInEdge (__fastcall 1 arg in ECX -> ret)
	patPush56 := []byte{0x68, 0x56, 0x00, 0x00, 0x10}
	searchPos = 0
	for {
		idx := bytes.Index(textData[searchPos:], patPush0C)
		if idx == -1 {
			break
		}
		absIdx := searchPos + idx
		endWin := absIdx + 0x20
		if endWin > len(textData) {
			endWin = len(textData)
		}
		if bytes.Contains(textData[absIdx:endWin], patPush56) {
			startWin := absIdx - 0x60
			if startWin < 0 {
				startWin = 0
			}
			if p := bytes.LastIndex(textData[startWin:absIdx], prologueStd); p != -1 {
				fnOff := startWin + p
				results = append(results, PatchTarget{
					Name:       "ShouldOpenInEdge [x86]",
					Arch:       "I386",
					VA:         textVA + uint64(fnOff),
					RVA:        textSec.VirtualAddress + uint32(fnOff),
					FileOffset: textSec.Offset + uint32(fnOff),
					OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86XorEaxRet)]...),
					PatchBytes: PatchX86XorEaxRet,
				})
				break
			}
		}
		searchPos = absIdx + 1
	}

	// 6. _TryIEShellDelegation@8 (__fastcall 2 args in ECX, EDX -> ret)
	patTryCfgX86 := []byte{0x68, 0x03, 0x00, 0x00, 0x20}
	patTryStackX86 := []byte{0xB8, 0xA4, 0x10, 0x00, 0x00}
	searchPos = 0
	for {
		idx := bytes.Index(textData[searchPos:], patTryCfgX86)
		if idx == -1 {
			break
		}
		absIdx := searchPos + idx
		startWin := absIdx - 0x50
		if startWin < 0 {
			startWin = 0
		}
		if bytes.Contains(textData[startWin:absIdx], patTryStackX86) {
			if p := bytes.LastIndex(textData[startWin:absIdx], prologueStd); p != -1 {
				fnOff := startWin + p
				results = append(results, PatchTarget{
					Name:       "_TryIEShellDelegation@8 [x86]",
					Arch:       "I386",
					VA:         textVA + uint64(fnOff),
					RVA:        textSec.VirtualAddress + uint32(fnOff),
					FileOffset: textSec.Offset + uint32(fnOff),
					OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86XorEaxRet)]...),
					PatchBytes: PatchX86XorEaxRet,
				})
				break
			}
		}
		searchPos = absIdx + 1
	}

	// 7. _CheckBrowseInProcess@12 (__fastcall 2 args in ECX, EDX + 1 stack arg -> ret 4)
	patChkBrowseX86 := []byte{0x6A, 0x03, 0x85, 0xD2, 0x58, 0x0F, 0x45, 0xC2}
	if idx := bytes.Index(textData, patChkBrowseX86); idx != -1 {
		startWin := idx - 0x40
		if startWin < 0 {
			startWin = 0
		}
		if p := bytes.LastIndex(textData[startWin:idx], prologueStd); p != -1 {
			fnOff := startWin + p
			results = append(results, PatchTarget{
				Name:       "_CheckBrowseInProcess@12 [x86]",
				Arch:       "I386",
				VA:         textVA + uint64(fnOff),
				RVA:        textSec.VirtualAddress + uint32(fnOff),
				FileOffset: textSec.Offset + uint32(fnOff),
				OrigBytes:  append([]byte(nil), textData[fnOff:fnOff+len(PatchX86CheckBrowseInProc)]...),
				PatchBytes: PatchX86CheckBrowseInProc,
			})
		}
	}

	// 8. Locate IsIEVisible globals g_IconsVisible (0xA3 <va>) and g_ShowIconsCommand (0x89 0D <va>)
	// In 32-bit ieframe.dll / inetcpl.cpl, IsIEVisible() checks g_IconsVisible == 1 (1 = visible, 2 = hidden).
	// Pre-setting both to 1 in .data guarantees IsIEVisible() == TRUE and IsIEHidden() == FALSE without calling EdgeLaunchHelper!
	patIconsVis := []byte{0x39, 0x45, 0xF8, 0x0F, 0x94, 0xC0, 0x40, 0xA3}
	if idx := bytes.Index(textData, patIconsVis); idx != -1 && idx+12 <= len(textData) {
		iconsVisVA := binary.LittleEndian.Uint32(textData[idx+8 : idx+12])
		imgBase32 := uint32(textVA) - textSec.VirtualAddress
		results = append(results,
			PatchTarget{
				Name:       "g_IconsVisible [data]",
				Arch:       "I386",
				VA:         uint64(iconsVisVA),
				RVA:        iconsVisVA - imgBase32,
				FileOffset: 0,
				OrigBytes:  []byte{0, 0, 0, 0},
				PatchBytes: []byte{1, 0, 0, 0},
			},
			PatchTarget{
				Name:       "g_ShowIconsCommand [data]",
				Arch:       "I386",
				VA:         uint64(iconsVisVA + 4),
				RVA:        iconsVisVA + 4 - imgBase32,
				FileOffset: 0,
				OrigBytes:  []byte{0, 0, 0, 0},
				PatchBytes: []byte{1, 0, 0, 0},
			},
		)
	}

	if len(results) < 1 {
		return results, fmt.Errorf("expected at least 1 I386 patch target in %s, but found %d", filePath, len(results))
	}
	return results, nil
}

// ComputePEChecksum calculates the standard Windows PE OptionalHeader.CheckSum.
func ComputePEChecksum(data []byte, checksumOffset int) uint32 {
	var sum uint64
	length := len(data)
	for i := 0; i < length; i += 2 {
		if i == checksumOffset || i == checksumOffset+2 {
			continue
		}
		var word uint16
		if i+1 < length {
			word = binary.LittleEndian.Uint16(data[i : i+2])
		} else {
			word = uint16(data[i])
		}
		sum += uint64(word)
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	sum = (sum & 0xFFFF) + (sum >> 16)
	sum += uint64(length)
	return uint32(sum)
}

// PatchPEFile reads srcPath, applies all located patches, updates the PE CheckSum, and writes to dstPath.
func PatchPEFile(srcPath, dstPath string) ([]PatchTarget, error) {
	targets, err := LocateTargets(srcPath)
	if err != nil {
		return targets, err
	}

	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return nil, err
	}

	for _, t := range targets {
		if t.FileOffset == 0 {
			continue
		}
		copy(raw[t.FileOffset:int(t.FileOffset)+len(t.PatchBytes)], t.PatchBytes)
	}

	// Update PE header CheckSum
	if len(raw) >= 0x40 {
		peHdrOff := int(binary.LittleEndian.Uint32(raw[0x3C:0x40]))
		// OptionalHeader starts at peHdrOff + 24; CheckSum is at OptionalHeader + 64
		csumOff := peHdrOff + 24 + 64
		if csumOff+4 <= len(raw) {
			newSum := ComputePEChecksum(raw, csumOff)
			binary.LittleEndian.PutUint32(raw[csumOff:csumOff+4], newSum)
		}
	}

	if err := os.WriteFile(dstPath, raw, 0755); err != nil {
		return nil, err
	}
	return targets, nil
}
