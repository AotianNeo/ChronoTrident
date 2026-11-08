<p align="center">
  <img src="https://img.shields.io/badge/架构支持-AMD64%20%7C%20ARM64X%20%7C%20CHPE32-blue?style=for-the-badge&logo=windows" alt="Arch">
  <img src="https://img.shields.io/badge/目标系统-Windows%2011%20(21H2--24H2%2B)-0078D4?style=for-the-badge&logo=windows11" alt="Windows 11">
  <img src="https://img.shields.io/badge/安全体系-零磁盘篡改%20(SFC%20免疫)-success?style=for-the-badge" alt="Zero-Tamper">
  <img src="https://img.shields.io/badge/开源协议-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/开发语言-Go%201.22%2B-00ADD8?style=for-the-badge&logo=go" alt="Language">
</p>

<h1 align="center">⚡ ChronoTrident (时序三叉戟)</h1>

<h3 align="center">跨架构·零磁盘篡改·Windows 11 原生 Trident 运行时超空间唤醒引擎</h3>

<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

---

## 🌌 项目宣言与设计理念 (Manifesto)

**ChronoTrident (时序三叉戟)** 是一项前卫且具备高抗更新能力的系统级运行时复苏引擎，专注于在现代操作系统（**Windows 10 SAC / Windows 11 21H2 ~ 24H2+，涵盖 Canary、Dev、Beta 及正式渠道**）上完整唤醒并释放被微软人为屏蔽的 **Microsoft Trident (MSHTML)** 渲染核心与 **Internet Explorer 11** 原生环境。

传统的 IE 恢复手段大多采用粗暴的磁盘篡改逻辑——例如暴力替换系统文件、覆盖 `ieframe.dll`、强改物理二进制字节。这类方案存在致命缺陷：会破坏系统的数字签名、触发 Windows 资源保护机制（WRP）、被 `sfc /scannow` 自动检测并回滚，并在微软每月的累积更新（Patch Tuesday LCU）中彻底失效。

**ChronoTrident 摒弃一切破坏性修改，从第一性原理出发，完全在动态内存边界与内核拦截层构建闭环**：
- 利用 Windows 内核原生的 **映像劫持机制 (Image File Execution Options, IFEO)**；
- 通过底层调试事件流环路 (`DEBUG_ONLY_THIS_PROCESS`) 在进程初始化的微秒级时钟内截获目标；
- 无缝覆盖 **AMD64、ARM64 / ARM64EC (ARM64X 混合架构) 以及 x86 / CHPE32**；
- 在不修改物理磁盘任何一字节的前提下，实现代码语义与数据流状态的动态升华。

```
                    ┌────────────────────────────────────────┐
                    │          用户 / 自动化业务拉起           │
                    │   iexplore.exe / inetcpl.cpl / COM     │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼ (内核级 IFEO 捕获)
             ┌─────────────────────────────────────────────────────┐
             │            ⚡ ChronoTrident 超空间引导引擎          │
             │           (Non-Destructive Interceptor)             │
             └──────────┬───────────────────────────────┬──────────┘
                        │ 以挂起/调试模式创建目标进程   │
                        ▼                               ▼
       ┌──────────────────────────────────┐   ┌──────────────────────────────────┐
       │         代码指令流动态消除        │   │         数据段运行时状态重定     │
       │  • BypassThunkTo64BitFrame (WoA) │   │  • g_InitOnceIsStandaloneIE = 2  │
       │  • OpenInEdge 启发式重定向空化   │   │  • g_fIsStandaloneIEDisabled = 0 │
       │  • GeneralPageDialogProc UI 显化 │   │  • g_fIsSBEEnabled = 0           │
       └──────────────────────────────────┘   └──────────────────────────────────┘
                        │                               │
                        └───────────────┬───────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       原生 Trident 引擎完美激活 (100% 畅通)         │
             │   零 Edge BHO 干扰 • 零循环重定向 • SFC/WRP 绝不报警 │
             └─────────────────────────────────────────────────────┘
```

---

## ⚡ 核心突破与技术特性

### 1. 零磁盘篡改 (Zero-Disk-Tamper)
- 对操作系统物理磁盘上的所有系统文件（`ieframe.dll`、`inetcpl.cpl`、`iexplore.exe` 等）**不作任何落盘修改**。
- 完美规避 **Windows 资源保护机制 (WRP)**、**系统文件检查器 (SFC)** 以及 **TrustedInstaller** 严格的权限防护体系。
- 具备天生抗更新属性，跨越任何版本补丁（LCU）与内部预览版大版本升级。

### 2. 全架构超融合支持 (Universal Hybrid Silicon)
- **AMD64 (x86_64 原生)**：主流 Intel 与 AMD 桌面 / 服务器 64 位平台。
- **ARM64 / ARM64EC (ARM64X 异构 PE)**：针对高通 Snapdragon X Elite、微软 SQ 系列芯片以及 Apple Silicon（在 Parallels Desktop / VMware Fusion 虚拟机下）原生支持。
- **CHPE32 / x86 WOW64**：针对 Windows on ARM (WoA) 特殊编译的 Compiled Hybrid Portable Executable 指令集。

### 3. 根治 Windows on ARM "无限 Thunk 乒乓循环" 漏洞
- 在 Windows on ARM 环境中，32 位 `iexplore.exe` 在 x86 WOW64 模拟层下调用 `GetNativeSystemInfo` 时，由于微软内核兼容性返回映射异常，返回了 `PROCESSOR_ARCHITECTURE_AMD64` (9) 而非预期的 `ARM64` (12)。
- 这一低级逻辑断裂导致程序错误跳转至 64 位委托框架 `ThunkTo64BitFrame`，进而不断递归衍生子进程造成内存雪崩与闪退。
- ChronoTrident 动态捕获此处的关键分支指令，将 `cmp word ptr [esp+0x9c], 0x0c; je ...` 现场改造为 `nop; jmp`，彻底终结递归死循环。

### 4. 代码与数据“双重互锁”机制 (击穿 XTA JIT 缓存壁垒)
- Windows on ARM 通过 **XTA (x86-to-ARM64) JIT 执行引擎** (`xtajitse.dll`) 缓存翻译后的代码块，单纯修改代码段可能因命中陈旧缓存而失效。
- ChronoTrident 引入创新性的“代码与数据双重互锁”策略：不仅修补代码入口，更直接向未参与 JIT 编译的 `.data` 数据段写入就绪态运行变量：
  - `g_InitOnceIsStandaloneIEDisabled = 2` (一次性初始化已完成)
  - `g_fIsStandaloneIEDisabled = 0` (独立运行禁止标志置假)
  - `g_InitOnceIsSBEEnabled = 2` (SBE 初始化完成)
  - `g_fIsSBEEnabled = 0` (精简浏览器模式置假)
  - `g_IconsVisible = 1` 与 `g_ShowIconsCommand = 1` (桌面图标呈现)

### 5. 三阶收敛式 Edge BHO 深度中和
- 精确清理并拦截 Edge 重定向浏览器辅助对象 (`ie_to_edge_bho.dll`，CLSID `{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}`)。
- 全局固化 Edge 企业策略阻断重定向：
  - `RedirectSitesFromInternetExplorerRedirectMode = 0` (永不重定向)
  - `RedirectSitesFromInternetExplorerPreventBHOInstall = 1` (彻底阻断静默装载)
- 静默旁路首次运行配置向导与侵入式遥测弹窗 (`DisableFirstRunCustomize = 1`、`NoBrowserBars = 1`)。

### 6. 控制面板“主页输入框”完整显化复原
- 逆向解除 `inetcpl.cpl`（Internet 属性）中 `GeneralPageDialogProc` 的控件折叠逻辑，让现代 Windows 11 中被隐藏的主页配置区与按钮群重见天日。

---

## 🛠️ 安装与使用指南

ChronoTrident 采用 Go 语言编译为单一绿色无依赖的原生二进制可执行程序。

### 🚀 一键极速部署 (需管理员权限)

以管理员身份打开 CMD 或 PowerShell，运行：

```cmd
:: 为 Internet Explorer 及控制面板属性安装持久化 IFEO 拦截引擎
chronotrident.exe --install-ifeo --with-cpl
```

执行后程序会自动完成：
1. 复制自身至受保护的系统级目录 `C:\ProgramData\ChronoTrident\chronotrident.exe`。
2. 注册 `iexplore.exe`、`rundll32.exe` 和 `control.exe` 的 IFEO 映像劫持调试器。
3. 注入 Edge 反重定向组策略。
4. 深度清除残留 BHO 劫持键值。
5. 在当前用户桌面自动生成可正常使用的 Internet Explorer 快捷方式。

### 🧹 零残留平滑卸载

若需将系统环境完全恢复至出厂初始状态，只需执行：

```cmd
chronotrident.exe --uninstall-ifeo
```

系统内所有的 IFEO 劫持注册表项、策略控制键均会被无损抹除，绝不损坏任何系统文件。

---

## 🔍 高级诊断与逆向工程模式

### 启发式动态内存扫描 (`--scan`)

在不改动任何字节的前提下，针对当前系统的任意 PE 二进制文件进行目标点启发式扫描与地址解析：

```cmd
chronotrident.exe --scan C:\Windows\System32\ieframe.dll C:\Windows\System32\inetcpl.cpl
```

典型输出：
```text
[*] Scanning: C:\Windows\System32\ieframe.dll
  [+] StandaloneIE_InitOnceDirect        | VA: 0x1802E8A10 | RVA: 0x02E8A10 | Orig: 488D0D123456 | Patch: C705...
  [+] SBE_InitOnceDirect                 | VA: 0x1802E9B30 | RVA: 0x02E9B30 | Orig: 488D0D654321 | Patch: C705...
  [+] OpenInEdge_ConditionalBranch       | VA: 0x1801C2050 | RVA: 0x01C2050 | Orig: 0F85A0000000 | Patch: 90E9A0000000
```

### 独立离线文件打补丁模式 (`--patch-file`)

专为离线固件封装、嵌入式工控镜像定制研发，可对提取出的目标二进制执行落盘修改，并通过 `imagehlp` 规范重算修正 `PE CheckSum` 校验和：

```cmd
chronotrident.exe --patch-file C:\Test\ieframe.dll C:\Test\ieframe_patched.dll
```

---

## 🔬 第一性原理逆向解密

<details>
<summary><b>1. 为什么 <code>iexplore.exe -Embedding</code> 能在现代系统上原生运行？</b></summary>

当我们在现代 Windows 上直接双击 `iexplore.exe` 时，其入口点 `wWinMain` 会走主交互路径，调用 `SHOpenFolderWindow` 并评估当前会话是否需要执行 `ShouldOpenInEdge`。一旦检测到 Edge 劫持策略激活，它便会构造 `ShellExecuteExW` 将当前 URL 转交 `msedge.exe`，自身随即调用 `ExitProcess(0)` 退出。

但若追加了 `-Embedding` 命令行参数（或者通过 COM 接口 CLSID `{0002DF01-0000-0000-C000-000000000046}` 实例化）：
1. `wWinMain` 解析参数后确认自身属于 **ActiveX / OLE 进程内就地自动化服务 (In-Place Automation Server)**。
2. 此状态下系统强制旁路普通浏览器窗口的外壳导航生命周期，直接跳过 `ShouldOpenInEdge`。
3. 控制权直抵 `CIEFrameServer::Register()` 并步入标准消息循环。
ChronoTrident 通过动态状态伪装，让所有常规交互启动也能获得甚至超越 `-Embedding` 的稳定纯净度。
</details>

<details>
<summary><b>2. 揭秘 Windows on ARM (WoA) 的 WOW64 架构判定异常</b></summary>

在 Windows on ARM 系统中，32 位的 `iexplore.exe` 内嵌了如下架构探测汇编片段：
```asm
call    ds:__imp__GetNativeSystemInfo
cmp     word ptr [esp+9Ch], 0Ch    ; 0x0C 代表 PROCESSOR_ARCHITECTURE_ARM64
je      short loc_Continue32Bit
call    ThunkTo64BitFrame          ; 委托给 64 位 iexplore.exe
```
但在 Win11 WoA 的 x86 WOW64 模拟子系统中，微软统一的 64 位翻译框架导致 `GetNativeSystemInfo` 写入了 `0x0009` (`PROCESSOR_ARCHITECTURE_AMD64`)。对比失败后程序跳转进 `ThunkTo64BitFrame`；而 64 位实例在重新校验后又认为自身应由 32 位处理，从而陷入了无休止的相互拉起循环。

ChronoTrident 将跳转条件字 `0F 84` (`je`) 动态篡改为 `90 E9` (`nop; jmp`)，从根本上锁死执行流，确保进程顺利呈现。
</details>

<details>
<summary><b>3. 为什么 ChronoTrident 的特征码在跨越多个版本后仍然坚如磐石？</b></summary>

与容易因微小偏移失效的传统硬编码基址不同，ChronoTrident 依赖的是 **领域不变量 (Domain Invariants)**：
1. **语义级操作码匹配**：仅锚定指令骨架（如 `48 8D 0D` 即 `lea rcx, [rip+offset]`）及操作数语义，完全脱离绝对虚拟地址。
2. **锚点溯源反向遍历**：先定位高熵不变常量（如特征 GUID、关键字符串标签），再向上回溯函数序言（Prologue），以确定关键调度表地址。
3. **PE 节区逻辑自校验**：扫描器解构 PE Header 中的节区表（Section Table），对所有计算出的相对虚拟偏移进行 `.text` 与 `.data` 边界合法性数学校验，杜绝非法解引用。
</details>

---

## 🏗️ 跨平台支持矩阵

| 芯片与操作系统架构 | 目标二进制 | 核心补丁实现策略 | 实机验证状态 |
| :--- | :--- | :--- | :---: |
| **x86_64 / AMD64** | `ieframe.dll`, `inetcpl.cpl` | IFEO 拦截 + RIP 相对偏移指令实时重写 | ✅ **通过实测 (Win11 24H2)** |
| **ARM64 / ARM64EC** | `ieframe.dll` (ARM64X) | PC-Relative ADRP/LDR 常量池指针动态篡改 | ✅ **通过实测 (Win11 24H2 WoA)** |
| **CHPE32 / x86** | `iexplore.exe` | Thunk 旁路 (`90 E9`) + `.data` 状态段强行互锁 | ✅ **通过实测 (Win11 24H2 WoA)** |

---

## 💻 源码编译构建指南

ChronoTrident 拥有纯净的工程设计，零 CGo 依赖，支持在 macOS、Linux 或 Windows 本机交叉编译：

```bash
# 克隆仓库
git clone https://github.com/your-username/ChronoTrident.git
cd ChronoTrident

# 为 Windows x64 (AMD64) 编译
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/chronotrident_amd64.exe .

# 为 Windows on ARM (ARM64) 编译
GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o bin/chronotrident_arm64.exe .
```

---

## ⚖️ 开源协议与合规声明

本项目依据 [MIT License](LICENSE) 规范开放源代码。

**合规性声明**：ChronoTrident 研发之核心目的旨在为关键工业自动化系统 (SCADA)、传统企业内部 ERP/OA 门户兼容、金融级 USB-Key 证书交互及计算机软硬件发展史提供非侵入式的兼容性运行环境。文中提及之 Microsoft、Windows 及 Internet Explorer 等均为微软公司旗下注册商标，本项目与微软公司不存在任何官方商业关联。
